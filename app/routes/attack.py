from flask import request, jsonify
from app.services import ssh_manager
from . import bp

@bp.route('/api/attack/get_flag', methods=['POST'])
def api_attack_get_flag():
    """获取 Flag"""
    data = request.json
    ip = data.get('ip')
    port = data.get('port', 80)
    result = ssh_manager.get_attack_flag(ip, port)
    return jsonify(result)

@bp.route('/api/attack/execute_cmd', methods=['POST'])
def api_attack_execute_cmd():
    """执行自定义命令"""
    data = request.json
    ip = data.get('ip')
    port = data.get('port', 80)
    cmd = data.get('cmd')
    if not cmd:
        return jsonify({'success': False, 'output': 'Command required'})
    result = ssh_manager.execute_attack_cmd(ip, port, cmd)
    return jsonify(result)

@bp.route('/api/attack/config', methods=['GET', 'POST'])
def attack_config():
    if request.method == 'POST':
        data = request.json
        template = data.get('template', '')
        # excluded_ips assumed comma-separated string
        excluded = data.get('excluded_ips', '') 
        return jsonify(ssh_manager.set_enemy_config(template, excluded))
    else:
        status = ssh_manager.get_attack_status()
        return jsonify({
            'template': status.get('network_template', ''),
            'excluded_ips': ', '.join(status.get('excluded_ips', [])),
            'targets': status.get('targets', {})
        })

@bp.route('/api/attack/status', methods=['GET'])
def attack_status():
    return jsonify(ssh_manager.get_attack_status())
