from flask import request, jsonify, current_app
import os
import threading
from werkzeug.utils import secure_filename
from app.services import ssh_manager
from . import bp

@bp.route('/api/rerun_preload', methods=['POST'])
def rerun_preload():
    data = request.json
    threading.Thread(target=ssh_manager.run_preload_tasks, args=(data['ip'], data['port'], True)).start()
    return jsonify({'status': 'ok', 'message': 'Preload tasks queued'})

@bp.route('/api/rerun_backup', methods=['POST'])
def rerun_backup():
    data = request.json
    threading.Thread(target=ssh_manager.backup_target, args=(data['ip'], data['port'], None, True)).start()
    return jsonify({'status': 'ok', 'message': 'Backup tasks queued'})

@bp.route('/api/preload/add_file', methods=['POST'])
def add_preload_file():
    file = request.files['file']
    remote_path = request.form['remote_path']
    
    filename = secure_filename(file.filename)
    local_path = os.path.join(current_app.config['PRELOAD_FOLDER'], filename)
    file.save(local_path)
    
    ssh_manager.preload_config['files'].append({
        'filename': filename,
        'remote_path': remote_path
    })
    ssh_manager.save_preload_config()
    return jsonify({'status': 'ok'})

@bp.route('/api/preload/add_cmd', methods=['POST'])
def add_preload_cmd():
    cmd = request.json['cmd']
    ssh_manager.preload_config['commands'].append(cmd)
    ssh_manager.save_preload_config()
    return jsonify({'status': 'ok'})

@bp.route('/api/preload/remove', methods=['POST'])
def remove_preload():
    data = request.json
    idx = data['index']
    
    if data['type'] == 'file':
        ssh_manager.preload_config['files'].pop(int(idx))
    elif data['type'] == 'cmd':
        ssh_manager.preload_config['commands'].pop(int(idx))
    
    ssh_manager.save_preload_config()
    return jsonify({'status': 'ok'})

@bp.route('/api/snapshot', methods=['POST'])
def api_snapshot():
    """建立文件快照基线"""
    data = request.json
    ip, port = data['ip'], data.get('port', 22)
    threading.Thread(target=ssh_manager.snapshot_files, args=(ip, port)).start()
    return jsonify({'status': 'ok', 'message': '快照任务已启动'})

@bp.route('/api/scan_backdoor', methods=['POST'])
def api_scan_backdoor():
    """扫描后门/不死马"""
    data = request.json
    ip, port = data['ip'], data.get('port', 22)
    threading.Thread(target=ssh_manager.scan_backdoor, args=(ip, port)).start()
    return jsonify({'status': 'ok', 'message': '后门扫描已启动'})

@bp.route('/api/backdoor_results', methods=['POST'])
def api_backdoor_results():
    """获取后门扫描结果"""
    data = request.json
    ip, port = data['ip'], data.get('port', 22)
    target = next((t for t in ssh_manager.targets if t['ip'] == ip and t['port'] == int(port)), None)
    if not target:
        return jsonify({'error': '靶机未找到'}), 404
    return jsonify({
        'backdoor_scan': target.get('backdoor_scan'),
        'snapshot_time': target.get('snapshot_time'),
        'snapshot_count': len(target.get('file_snapshot', {})),
    })

@bp.route('/api/restore_backup', methods=['POST'])
def api_restore_backup():
    """还原备份"""
    data = request.json
    ip, port = data['ip'], data.get('port', 22)
    success, msg = ssh_manager.restore_backup(ip, port)
    return jsonify({'success': success, 'message': msg})

@bp.route('/api/scheduled_tasks', methods=['GET'])
def api_get_scheduled_tasks():
    """获取定时任务列表"""
    return jsonify({'tasks': ssh_manager.get_scheduled_tasks()})

@bp.route('/api/scheduled_task/add', methods=['POST'])
def api_add_scheduled_task():
    """添加定时任务"""
    data = request.json
    name = data.get('name', '')
    cmd = data.get('cmd', '')
    interval = data.get('interval', 60)
    if not name or not cmd:
        return jsonify({'error': '名称和命令不能为空'}), 400
    ssh_manager.add_scheduled_task(name, cmd, interval)
    return jsonify({'status': 'ok', 'message': f'定时任务 {name} 已添加'})

@bp.route('/api/scheduled_task/remove', methods=['POST'])
def api_remove_scheduled_task():
    """移除定时任务"""
    data = request.json
    name = data.get('name', '')
    if ssh_manager.remove_scheduled_task(name):
        return jsonify({'status': 'ok', 'message': f'定时任务 {name} 已移除'})
    return jsonify({'error': '任务未找到'}), 404

@bp.route('/api/local_ip', methods=['GET'])
def api_get_local_ip():
    """获取本机 IP"""
    return jsonify({'local_ip': ssh_manager.get_local_ip()})

@bp.route('/api/local_ip', methods=['POST'])
def api_set_local_ip():
    """设置本机 IP"""
    data = request.json
    ip = data.get('ip', '')
    ssh_manager.set_local_ip(ip)
    return jsonify({'status': 'ok', 'local_ip': ip})

@bp.route('/api/deploy_aoi', methods=['POST'])
def api_deploy_aoi():
    """手动部署 AOI 工具到指定靶机"""
    data = request.json
    ip = data['ip']
    port = int(data.get('port', 22))
    def _run():
        ssh_manager.deploy_aoi_tools(ip, port)
    threading.Thread(target=_run).start()
    return jsonify({'status': 'ok', 'message': 'AOI 部署已启动'})
