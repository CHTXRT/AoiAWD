from flask import request, jsonify, current_app
import subprocess
import os
import threading
from app.services import ssh_manager
from . import bp

@bp.route('/api/connect', methods=['POST'])
def api_connect():
    data = request.json
    success, msg = ssh_manager.connect(data['ip'], data.get('port', 22))
    return jsonify({'success': success, 'message': msg})

@bp.route('/api/disconnect', methods=['POST'])
def api_disconnect():
    data = request.json
    success, msg = ssh_manager.disconnect(data['ip'], data.get('port', 22))
    return jsonify({'success': success, 'message': msg})

@bp.route('/api/execute', methods=['POST'])
def api_execute():
    data = request.json
    output = ssh_manager.execute(data['ip'], data.get('port', 22), data['cmd'])
    return jsonify({'output': output})

@bp.route('/api/execute_console', methods=['POST'])
def api_execute_console():
    """Console 用：带工作目录跟踪的命令执行"""
    data = request.json
    output, cwd = ssh_manager.execute_with_cwd(data['ip'], data.get('port', 22), data['cmd'])
    return jsonify({'output': output, 'cwd': cwd})

@bp.route('/api/execute_wwwdata', methods=['POST'])
def api_execute_wwwdata():
    """以 www-data 权限执行命令"""
    data = request.json
    output = ssh_manager.execute_as_wwwdata(data['ip'], data.get('port', 22), data['cmd'])
    return jsonify({'output': output})

@bp.route('/api/setup_wwwdata', methods=['POST'])
def api_setup_wwwdata():
    """手动部署 www-data shell"""
    data = request.json
    ip, port = data['ip'], data.get('port', 22)
    threading.Thread(target=ssh_manager.setup_wwwdata_shell, args=(ip, int(port))).start()
    return jsonify({'status': 'ok', 'message': 'www-data shell 部署中...'})

@bp.route('/api/remove_target', methods=['POST'])
def remove_target():
    data = request.json
    success = ssh_manager.remove_target(data['ip'], data.get('port', 22))
    if success:
        return jsonify({'status': 'ok'})
    else:
        return jsonify({'status': 'error', 'message': 'Target not found'}), 404

@bp.route('/api/update_password', methods=['POST'])
def update_password():
    data = request.json
    success, msg = ssh_manager.update_password(data['ip'], data.get('port', 22), data['password'])
    return jsonify({'success': success, 'message': msg})

@bp.route('/api/connect_all', methods=['POST'])
def api_connect_all():
    """一键全连"""
    def _run():
        ssh_manager.connect_all()
    threading.Thread(target=_run).start()
    return jsonify({'status': 'ok', 'message': '正在连接所有靶机...'})

@bp.route('/api/disconnect_all', methods=['POST'])
def api_disconnect_all():
    """一键全断"""
    results = ssh_manager.disconnect_all()
    return jsonify({'status': 'ok', 'results': results})

@bp.route('/api/batch_execute', methods=['POST'])
def api_batch_execute():
    """批量执行命令"""
    data = request.json
    cmd = data.get('cmd', '')
    if not cmd:
        return jsonify({'error': '命令不能为空'}), 400
    results = ssh_manager.batch_execute(cmd)
    return jsonify({'status': 'ok', 'results': results})

@bp.route('/api/check_connections', methods=['POST'])
def api_check_connections():
    """检查连接健康"""
    results = ssh_manager.check_connections()
    return jsonify({'status': 'ok', 'results': results})

@bp.route('/api/open_xshell', methods=['POST'])
def open_xshell():
    data = request.json
    ip = data.get('ip')
    port = int(data.get('port', 22))
    
    # Security: Retrieve credentials from backend instead of frontend
    target = ssh_manager.tm.get_target(ip, port)
    if not target:
        return jsonify({'success': False, 'message': 'Target not found'})
    
    user = target.get('user', 'root')
    password = target.get('password')
    
    if not password:
        return jsonify({'success': False, 'message': 'No password for target'})

    # Use app.utils.xshell to generate session file
    from app.utils import xshell
    xsh = xshell.Xsh(ip, user, port, password=password)
    
    if not os.path.exists("data/xshell"):
        os.makedirs("data/xshell")
    
    xsh_path = os.path.abspath(f"data/xshell/{ip}_{port}.xsh")
    with open(xsh_path, "w") as f:
        f.write(str(xsh))

    try:
        # Launch Xshell with the session file
        subprocess.Popen(f'Xshell "{xsh_path}"', shell=True)
        return jsonify({'success': True, 'message': 'Xshell started (Session File)'})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@bp.route('/api/open_xshell_wwwdata', methods=['POST'])
def open_xshell_wwwdata():
    data = request.get_json() or {}
    ip = data.get('ip') or ''
    port = int(data.get('port', 22))
    
    # Security: Retrieve credentials from backend
    target = ssh_manager.tm.get_target(ip, port)
    if not target:
        return jsonify({'success': False, 'message': 'Target not found'})

    user = 'www-data' # www-data shell usually runs as www-data user (or we use su/sudo if needed, but here we assume direct credential or shell access)
    # Actually, for www-data shell persistence, we might use a specific user if configured, 
    # but the previous method used 'root' mostly or passed user.
    # The 'wwwdata_password' or similar might be stored.
    # Re-reading original code: it accepted user/pass from frontend.
    # Let's check target for specific www-data credentials if any, otherwise fallback to target's main user if that was the intent,
    # OR if this is about the 'undead shell' or specific backdoor access. 
    # The original code had: execute_cmd='/tmp/mujica -p'. 
    
    password = target.get('password') # Fallback to root password if no specific www-data payload password? 
    # Wait, open_xshell_wwwdata implies connecting TO the machine to USE the www-data shell? 
    # Or connecting AS www-data? 
    # Original used: Xsh(..., execute_cmd='/tmp/mujica -p'). This implies we log in (as root/user) and run a command.
    
    from app.utils import xshell
    
    # We use the main credentials to login, then execute the tool
    xsh = xshell.Xsh(ip, target.get('user', 'root'), port, password=password, execute_cmd='/tmp/mujica -p')
    
    if not os.path.exists("data/xshell"):
        os.makedirs("data/xshell")
        
    xsh_path = os.path.abspath(f"data/xshell/{ip}_{port}_wd.xsh")
    with open(xsh_path, "w") as f:
        f.write(str(xsh))
    try:
        subprocess.Popen(f'Xshell "{xsh_path}"', shell=True)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    return jsonify({'status': 'ok', 'message': 'Xshell for www-data started'})
