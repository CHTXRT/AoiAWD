#!/usr/bin/env python3
"""
AWD 中心化防护平台 - 管理端
运行在本地,接收远程 Agent 转发的流量,进行集中防护和管理
"""

import json
import time
import logging
import re
from datetime import datetime
from flask import Flask, request, Response, jsonify, render_template_string
from collections import defaultdict, deque
from threading import Lock
import requests

app = Flask(__name__)

# ==================== 全局配置 ====================
CONFIG = {
    'SECRET_KEY': 'change_this_secret_key_in_production',  # Agent 认证密钥
    'LOG_DIR': './logs',
    'MAX_AGENTS': 50,
}

# 存储所有 Agent 的配置
agents_config = {}  # {agent_id: {backend_url, real_flag, fake_flag, ...}}
agents_status = {}  # {agent_id: {last_seen, requests_count, attacks_count}}
agents_lock = Lock()

# 统计数据
request_history = defaultdict(lambda: deque(maxlen=1000))
attack_logs = defaultdict(list)
stats_lock = Lock()

# 攻击检测规则
ATTACK_PATTERNS = [
    (r'union\s+select', 'SQL注入'),
    (r"'\s*or\s*'1'\s*=\s*'1", 'SQL注入'),
    (r'<script[^>]*>', 'XSS'),
    (r'javascript:', 'XSS'),
    (r'\.\./\.\./', '路径穿越'),
    (r'__import__', 'Python代码注入'),
    (r'eval\s*\(', '代码执行'),
    (r'exec\s*\(', '代码执行'),
    (r'os\.system', '命令执行'),
    (r'subprocess', '命令执行'),
    (r'{{.*}}', 'SSTI'),
    (r'{%.*%}', 'SSTI'),
    (r'file://', '文件协议'),
    (r'data://', '数据协议'),
]

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('awd_platform.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ==================== 工具函数 ====================
def verify_agent(agent_id, secret):
    """验证 Agent 身份"""
    if secret != CONFIG['SECRET_KEY']:
        return False
    return True


def register_agent(agent_id, config):
    """注册新的 Agent"""
    with agents_lock:
        agents_config[agent_id] = {
            'backend_url': config.get('backend_url'),
            'real_flag': config.get('real_flag'),
            'fake_flag': config.get('fake_flag'),
            'team_name': config.get('team_name', 'Unknown'),
            'registered_at': datetime.now().isoformat(),
        }
        agents_status[agent_id] = {
            'last_seen': time.time(),
            'requests_count': 0,
            'attacks_count': 0,
            'status': 'online'
        }
    logger.info(f"Agent 注册成功: {agent_id} ({config.get('team_name')})")


def update_agent_status(agent_id):
    """更新 Agent 状态"""
    with agents_lock:
        if agent_id in agents_status:
            agents_status[agent_id]['last_seen'] = time.time()
            agents_status[agent_id]['status'] = 'online'


def detect_attack(data):
    """检测攻击特征"""
    if not data:
        return False, []

    data_str = str(data).lower()
    matched = []

    for pattern, attack_type in ATTACK_PATTERNS:
        if re.search(pattern, data_str, re.IGNORECASE):
            matched.append(attack_type)

    return len(matched) > 0, list(set(matched))


def replace_flag(text, real_flag, fake_flag):
    """替换 Flag"""
    if not isinstance(text, str) or not real_flag:
        return text

    if real_flag in text:
        logger.warning(f"检测到 Flag 泄露,已替换: {real_flag[:20]}...")
        return text.replace(real_flag, fake_flag)

    return text


def process_response(response_data, content_type, agent_config):
    """处理响应,替换 Flag"""
    real_flag = agent_config.get('real_flag', '')
    fake_flag = agent_config.get('fake_flag', 'flag{not_real}')

    try:
        if 'json' in content_type:
            data = json.loads(response_data)
            data_str = json.dumps(data)
            if real_flag and real_flag in data_str:
                data_str = data_str.replace(real_flag, fake_flag)
                return data_str.encode()

        elif 'html' in content_type or 'text' in content_type:
            text = response_data.decode('utf-8', errors='ignore')
            text = replace_flag(text, real_flag, fake_flag)
            return text.encode('utf-8')

    except Exception as e:
        logger.error(f"Flag 替换失败: {e}")

    return response_data


def log_attack(agent_id, client_ip, method, path, attack_types):
    """记录攻击日志"""
    with stats_lock:
        attack_logs[agent_id].append({
            'timestamp': datetime.now().isoformat(),
            'client_ip': client_ip,
            'method': method,
            'path': path,
            'attack_types': attack_types
        })

        # 只保留最近 1000 条
        if len(attack_logs[agent_id]) > 1000:
            attack_logs[agent_id] = attack_logs[agent_id][-1000:]

        # 更新统计
        if agent_id in agents_status:
            agents_status[agent_id]['attacks_count'] += 1


# ==================== Agent API ====================
@app.route('/api/agent/register', methods=['POST'])
def agent_register():
    """Agent 注册接口"""
    data = request.get_json()

    agent_id = data.get('agent_id')
    secret = data.get('secret')
    config = data.get('config', {})

    if not agent_id or not verify_agent(agent_id, secret):
        return jsonify({'error': 'Invalid credentials'}), 403

    register_agent(agent_id, config)

    return jsonify({
        'status': 'ok',
        'message': 'Agent registered successfully',
        'agent_id': agent_id
    })


@app.route('/api/agent/heartbeat', methods=['POST'])
def agent_heartbeat():
    """Agent 心跳接口"""
    data = request.get_json()
    agent_id = data.get('agent_id')
    secret = data.get('secret')

    if not verify_agent(agent_id, secret):
        return jsonify({'error': 'Invalid credentials'}), 403

    update_agent_status(agent_id)

    # 返回最新配置
    config = agents_config.get(agent_id, {})

    return jsonify({
        'status': 'ok',
        'config': {
            'real_flag': config.get('real_flag'),
            'fake_flag': config.get('fake_flag'),
        }
    })


@app.route('/api/agent/proxy', methods=['POST'])
def agent_proxy():
    """Agent 流量代理接口 - 核心功能"""
    # 获取 Agent 信息
    agent_id = request.headers.get('X-Agent-ID')
    secret = request.headers.get('X-Agent-Secret')

    if not verify_agent(agent_id, secret):
        return jsonify({'error': 'Invalid credentials'}), 403

    # 获取 Agent 配置
    agent_config = agents_config.get(agent_id, {})
    if not agent_config:
        return jsonify({'error': 'Agent not registered'}), 404

    # 更新状态
    update_agent_status(agent_id)
    with agents_lock:
        agents_status[agent_id]['requests_count'] += 1

    # 解析转发的请求
    proxy_data = request.get_json()
    method = proxy_data.get('method')
    path = proxy_data.get('path')
    headers = proxy_data.get('headers', {})
    body = proxy_data.get('body', '')
    client_ip = proxy_data.get('client_ip', 'unknown')

    # 攻击检测
    request_data = {
        'path': path,
        'headers': headers,
        'body': body,
    }

    is_attack, attack_types = detect_attack(request_data)

    if is_attack:
        log_attack(agent_id, client_ip, method, path, attack_types)
        logger.warning(f"[{agent_id}] 检测到攻击: {client_ip} {method} {path} - {attack_types}")

    # 转发到后端服务
    backend_url = agent_config.get('backend_url', '')
    if not backend_url:
        return jsonify({'error': 'Backend URL not configured'}), 500

    try:
        target_url = f"{backend_url}{path}"

        # 发送请求到后端
        resp = requests.request(
            method=method,
            url=target_url,
            headers=headers,
            data=body.encode() if isinstance(body, str) else body,
            timeout=30,
            allow_redirects=False
        )

        # 处理响应
        content_type = resp.headers.get('Content-Type', '')
        response_data = resp.content

        # Flag 替换
        response_data = process_response(response_data, content_type, agent_config)

        # 返回给 Agent
        return jsonify({
            'status_code': resp.status_code,
            'headers': dict(resp.headers),
            'body': response_data.decode('utf-8', errors='ignore'),
            'is_attack': is_attack,
            'attack_types': attack_types
        })

    except Exception as e:
        logger.error(f"代理请求失败: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== 管理界面 ====================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>AWD 中心化防护平台</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                  color: white; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 28px; }
        .container { max-width: 1400px; margin: 20px auto; padding: 0 20px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                 gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; 
                     box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .stat-card h3 { color: #666; font-size: 14px; margin-bottom: 10px; }
        .stat-card .value { font-size: 32px; font-weight: bold; color: #667eea; }
        .agents-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); 
                       gap: 20px; }
        .agent-card { background: white; border-radius: 10px; padding: 20px; 
                      box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .agent-header { display: flex; justify-content: space-between; align-items: center; 
                        margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #f0f0f0; }
        .agent-id { font-weight: bold; font-size: 18px; color: #333; }
        .status { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; }
        .status.online { background: #d4edda; color: #155724; }
        .status.offline { background: #f8d7da; color: #721c24; }
        .agent-info { margin: 10px 0; }
        .agent-info div { padding: 8px 0; display: flex; justify-content: space-between; 
                          border-bottom: 1px solid #f5f5f5; }
        .agent-info label { color: #666; font-size: 14px; }
        .agent-info span { color: #333; font-weight: 500; }
        .attacks { background: #fff3cd; padding: 10px; border-radius: 5px; margin-top: 10px; }
        .attacks-title { font-weight: bold; color: #856404; margin-bottom: 5px; }
        .attack-item { font-size: 12px; color: #856404; padding: 3px 0; }
        .btn { padding: 8px 16px; border: none; border-radius: 5px; cursor: pointer; 
               font-size: 14px; transition: all 0.3s; }
        .btn-primary { background: #667eea; color: white; }
        .btn-primary:hover { background: #5568d3; }
        .btn-danger { background: #dc3545; color: white; }
        .refresh-btn { position: fixed; bottom: 30px; right: 30px; padding: 15px 30px;
                       font-size: 16px; box-shadow: 0 4px 10px rgba(0,0,0,0.2); }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AWD 中心化防护平台</h1>
    </div>

    <div class="container">
        <div class="stats">
            <div class="stat-card">
                <h3>在线 Agent</h3>
                <div class="value">{{ stats.online_agents }}</div>
            </div>
            <div class="stat-card">
                <h3>总请求数</h3>
                <div class="value">{{ stats.total_requests }}</div>
            </div>
            <div class="stat-card">
                <h3>检测到攻击</h3>
                <div class="value">{{ stats.total_attacks }}</div>
            </div>
            <div class="stat-card">
                <h3>系统状态</h3>
                <div class="value" style="font-size: 24px; color: #28a745;">运行中</div>
            </div>
        </div>

        <h2 style="margin-bottom: 20px;">Agent 列表</h2>

        <div class="agents-grid">
            {% for agent_id, config in agents.items() %}
            <div class="agent-card">
                <div class="agent-header">
                    <div class="agent-id">{{ agent_id }}</div>
                    <div class="status {{ status[agent_id].status }}">
                        {{ status[agent_id].status }}
                    </div>
                </div>

                <div class="agent-info">
                    <div>
                        <label>团队名称:</label>
                        <span>{{ config.team_name }}</span>
                    </div>
                    <div>
                        <label>后端地址:</label>
                        <span style="font-size: 12px;">{{ config.backend_url }}</span>
                    </div>
                    <div>
                        <label>请求数:</label>
                        <span>{{ status[agent_id].requests_count }}</span>
                    </div>
                    <div>
                        <label>攻击数:</label>
                        <span style="color: #dc3545;">{{ status[agent_id].attacks_count }}</span>
                    </div>
                    <div>
                        <label>最后心跳:</label>
                        <span>{{ status[agent_id].last_seen_str }}</span>
                    </div>
                </div>

                {% if attacks.get(agent_id) %}
                <div class="attacks">
                    <div class="attacks-title">最近攻击 (最多5条)</div>
                    {% for attack in attacks[agent_id][-5:] %}
                    <div class="attack-item">
                        {{ attack.client_ip }} - {{ attack.method }} {{ attack.path }}
                        <br>类型: {{ ', '.join(attack.attack_types) }}
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>

        {% if not agents %}
        <div style="text-align: center; padding: 60px; color: #999;">
            <h2>暂无 Agent 连接</h2>
            <p style="margin-top: 10px;">请在靶机上部署 Agent 脚本</p>
        </div>
        {% endif %}
    </div>

    <button class="btn btn-primary refresh-btn" onclick="location.reload()">
        🔄 刷新
    </button>
</body>
</html>
"""


@app.route('/')
def dashboard():
    """管理界面"""
    # 计算统计数据
    online_count = sum(1 for s in agents_status.values()
                       if time.time() - s['last_seen'] < 60)
    total_requests = sum(s['requests_count'] for s in agents_status.values())
    total_attacks = sum(s['attacks_count'] for s in agents_status.values())

    # 更新状态
    for agent_id, status in agents_status.items():
        if time.time() - status['last_seen'] > 60:
            status['status'] = 'offline'
        status['last_seen_str'] = datetime.fromtimestamp(status['last_seen']).strftime('%H:%M:%S')

    return render_template_string(
        DASHBOARD_HTML,
        agents=agents_config,
        status=agents_status,
        attacks=attack_logs,
        stats={
            'online_agents': online_count,
            'total_requests': total_requests,
            'total_attacks': total_attacks,
        }
    )


# ==================== 管理 API ====================
@app.route('/api/admin/agents', methods=['GET'])
def get_agents():
    """获取所有 Agent 信息"""
    return jsonify({
        'agents': agents_config,
        'status': agents_status,
        'attacks': {k: v[-100:] for k, v in attack_logs.items()}
    })


@app.route('/api/admin/agent/<agent_id>/config', methods=['POST'])
def update_agent_config(agent_id):
    """更新 Agent 配置"""
    if agent_id not in agents_config:
        return jsonify({'error': 'Agent not found'}), 404

    data = request.get_json()

    with agents_lock:
        if 'real_flag' in data:
            agents_config[agent_id]['real_flag'] = data['real_flag']
        if 'fake_flag' in data:
            agents_config[agent_id]['fake_flag'] = data['fake_flag']

    logger.info(f"Agent 配置已更新: {agent_id}")
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("AWD 中心化防护平台启动中...")
    logger.info("=" * 60)
    logger.info(f"管理界面: http://0.0.0.0:9000")
    logger.info(f"Agent API: http://0.0.0.0:9000/api/agent/*")
    logger.info(f"密钥: {CONFIG['SECRET_KEY']}")
    logger.info("=" * 60)

    app.run(host='0.0.0.0', port=9000, debug=False, threaded=True)