import os
import paramiko
import threading
from flask import Flask, request, jsonify, render_template_string
from werkzeug.utils import secure_filename

app = Flask(__name__)

# 配置路径
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['KEYS_FOLDER'] = os.path.join(BASE_DIR, 'keys')

# 确保目录存在
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
if not os.path.exists(app.config['KEYS_FOLDER']):
    os.makedirs(app.config['KEYS_FOLDER'])

class SSHController:
    def __init__(self):
        self.sessions = {}  # ip -> client
        self.targets = []   # List of dicts
        self.lock = threading.Lock()

    def add_target(self, ip, port=22, user='root', password=None, key_path=None):
        with self.lock:
            # 避免重复添加
            for t in self.targets:
                if t['ip'] == ip:
                    return
            self.targets.append({
                'ip': ip,
                'port': int(port),
                'user': user,
                'password': password,
                'key_path': key_path,
                'status': 'disconnected'
            })

    def get_available_keys(self):
        """获取所有可用密钥"""
        keys = []
        if os.path.exists(app.config['KEYS_FOLDER']):
            for f in os.listdir(app.config['KEYS_FOLDER']):
                path = os.path.join(app.config['KEYS_FOLDER'], f)
                if os.path.isfile(path):
                    keys.append(path)
        return keys

    def connect(self, ip):
        """连接靶机，自动匹配密钥"""
        target = next((t for t in self.targets if t['ip'] == ip), None)
        if not target:
            return False, "Target not found"

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            # 1. 尝试指定密钥
            if target['key_path'] and os.path.exists(target['key_path']):
                client.connect(ip, port=target['port'], username=target['user'], key_filename=target['key_path'], timeout=5)
                self.sessions[ip] = client
                target['status'] = 'connected'
                return True, "Connected with specified key"

            # 2. 尝试密码
            if target['password']:
                client.connect(ip, port=target['port'], username=target['user'], password=target['password'], timeout=5)
                self.sessions[ip] = client
                target['status'] = 'connected'
                return True, "Connected with password"

            # 3. 尝试匹配目录下的所有密钥
            keys = self.get_available_keys()
            # 优化：优先尝试文件名包含IP的密钥
            keys.sort(key=lambda k: 0 if ip in k else 1)
            
            for key in keys:
                try:
                    client.connect(ip, port=target['port'], username=target['user'], key_filename=key, timeout=5)
                    self.sessions[ip] = client
                    target['status'] = 'connected'
                    target['key_path'] = key # 记录成功的密钥
                    return True, f"Connected with key {os.path.basename(key)}"
                except paramiko.AuthenticationException:
                    continue
                except Exception:
                    continue

            return False, "Authentication failed (No matching key/password)"

        except Exception as e:
            target['status'] = 'error'
            return False, str(e)

    def execute(self, ip, cmd):
        """执行命令"""
        if ip not in self.sessions:
            return "Not connected"
        try:
            # 检查会话是否活跃或认证是否失效
            transport = self.sessions[ip].get_transport()
            if not transport or not transport.is_active() or not self.sessions[ip].get_transport().is_authenticated():
                self.connect(ip) # 尝试重连
            
            stdin, stdout, stderr = self.sessions[ip].exec_command(cmd, timeout=10)
            return stdout.read().decode() + stderr.read().decode()
        except Exception as e:
            return f"Error: {str(e)}"

    def upload(self, ip, local_path, remote_path):
        """上传文件 (FTP/SFTP)"""
        if ip not in self.sessions:
            return False, "Not connected"
        try:
            sftp = self.sessions[ip].open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            return True, "Success"
        except Exception as e:
            return False, str(e)

controller = SSHController()

# HTML 模板
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>AWD 靶机控制台</title>
    <meta charset="utf-8">
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 20px; background: #f0f2f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1, h3 { color: #333; }
        .status-connected { color: #28a745; font-weight: bold; }
        .status-disconnected { color: #dc3545; }
        .status-error { color: #ffc107; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background-color: #f8f9fa; }
        textarea { width: 100%; height: 200px; font-family: monospace; padding: 10px; border: 1px solid #ddd; border-radius: 4px; background: #1e1e1e; color: #00ff00; }
        input[type="text"], input[type="password"] { padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .btn { padding: 8px 16px; cursor: pointer; background: #007bff; color: white; border: none; border-radius: 4px; transition: background 0.2s; }
        .btn:hover { background: #0056b3; }
        .btn-sm { padding: 4px 8px; font-size: 12px; }
        .flex-row { display: flex; gap: 10px; align-items: center; }
    </style>
</head>
<body>
<div class="container">
    <h1>🎮 AWD 靶机控制台</h1>
    
    <!-- 添加靶机 -->
    <div class="card">
        <h3>添加靶机</h3>
        <form action="/add_target" method="post" class="flex-row">
            <input type="text" name="ip" placeholder="IP 地址" required>
            <input type="text" name="port" placeholder="端口" value="22" size="5">
            <input type="text" name="user" placeholder="用户名" value="root" size="10">
            <input type="password" name="password" placeholder="密码 (可选)">
            <button type="submit" class="btn">添加</button>
        </form>
    </div>

    <!-- 靶机列表 -->
    <div class="card">
        <h3>靶机列表 (在线: {{ connected_count }}/{{ total_count }})</h3>
        <table>
            <thead>
                <tr>
                    <th>IP</th>
                    <th>用户</th>
                    <th>状态</th>
                    <th>操作</th>
                </tr>
            </thead>
            <tbody>
                {% for t in targets %}
                <tr>
                    <td>{{ t.ip }}</td>
                    <td>{{ t.user }}</td>
                    <td class="status-{{ t.status }}">{{ t.status }}</td>
                    <td>
                        <button class="btn btn-sm" onclick="connect('{{ t.ip }}')">连接</button>
                        <button class="btn btn-sm" onclick="selectTarget('{{ t.ip }}')">控制</button>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <!-- 控制面板 -->
    <div class="card" id="console-panel">
        <h3>控制台 & FTP - 当前目标: <span id="current-target" style="color: #007bff;">未选择</span></h3>
        
        <h4>执行命令</h4>
        <div class="flex-row" style="margin-bottom: 10px;">
            <input type="text" id="cmd-input" style="flex-grow: 1;" placeholder="输入命令 (例如: ls -la /flag)">
            <button class="btn" onclick="runCommand()">执行</button>
        </div>
        <textarea id="cmd-output" readonly></textarea>

        <h4 style="margin-top: 20px;">文件上传</h4>
        <form id="upload-form" class="flex-row">
            <input type="file" id="file-input" name="file">
            <input type="text" id="remote-path" placeholder="远程路径 (例如: /tmp/shell.php)" style="flex-grow: 1;">
            <button type="button" class="btn" onclick="uploadFile()">上传</button>
        </form>
    </div>
</div>

<script>
    let currentIp = null;

    function selectTarget(ip) {
        currentIp = ip;
        document.getElementById('current-target').innerText = ip;
        document.getElementById('cmd-output').value = "已选择目标: " + ip + "\\n准备就绪...";
    }

    async function connect(ip) {
        const btn = event.target;
        btn.innerText = "连接中...";
        try {
            const res = await fetch('/api/connect', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ip: ip})
            });
            const data = await res.json();
            alert(data.message);
            location.reload();
        } catch (e) {
            alert("连接请求失败");
        } finally {
            btn.innerText = "连接";
        }
    }

    async function runCommand() {
        if (!currentIp) return alert("请先选择一个目标");
        const cmd = document.getElementById('cmd-input').value;
        if (!cmd) return;
        
        document.getElementById('cmd-output').value += "\\n> " + cmd + "\\n执行中...";
        
        const res = await fetch('/api/execute', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip: currentIp, cmd: cmd})
        });
        const data = await res.json();
        document.getElementById('cmd-output').value = data.output;
    }

    async function uploadFile() {
        if (!currentIp) return alert("请先选择一个目标");
        const fileInput = document.getElementById('file-input');
        const remotePath = document.getElementById('remote-path').value;
        
        if (!fileInput.files[0]) return alert("请选择文件");
        if (!remotePath) return alert("请输入远程路径");

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('ip', currentIp);
        formData.append('remote_path', remotePath);

        const btn = event.target;
        btn.innerText = "上传中...";

        try {
            const res = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();
            alert(data.message);
        } catch (e) {
            alert("上传失败");
        } finally {
            btn.innerText = "上传";
        }
    }
</script>
</body>
</html>
"""

@app.route('/')
def index():
    connected = sum(1 for t in controller.targets if t['status'] == 'connected')
    return render_template_string(HTML_TEMPLATE, 
                                targets=controller.targets,
                                connected_count=connected,
                                total_count=len(controller.targets))

@app.route('/add_target', methods=['POST'])
def add_target():
    controller.add_target(
        request.form['ip'],
        request.form.get('port', 22),
        request.form.get('user', 'root'),
        request.form.get('password'),
        None
    )
    return index()

@app.route('/api/connect', methods=['POST'])
def api_connect():
    data = request.json
    success, msg = controller.connect(data['ip'])
    return jsonify({'success': success, 'message': msg})

@app.route('/api/execute', methods=['POST'])
def api_execute():
    data = request.json
    output = controller.execute(data['ip'], data['cmd'])
    return jsonify({'output': output})

@app.route('/api/upload', methods=['POST'])
def api_upload():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'})
    
    file = request.files['file']
    ip = request.form['ip']
    remote_path = request.form['remote_path']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'})
        
    filename = secure_filename(file.filename)
    local_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(local_path)
    
    success, msg = controller.upload(ip, local_path, remote_path)
    return jsonify({'success': success, 'message': msg})

if __name__ == '__main__':
    print("AWD 控制台启动中...")
    print(f"请访问: http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
