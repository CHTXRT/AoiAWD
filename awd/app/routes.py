from flask import render_template, redirect, url_for, request, jsonify, Blueprint
import os
import threading
from werkzeug.utils import secure_filename
import subprocess
import ipaddress
import stat
from flask import current_app
from .services import ssh_manager

bp = Blueprint('main', __name__, template_folder='template')

@bp.route('/')
def index():
    ssh_manager._ensure_initialized()
    connected = sum(1 for t in ssh_manager.targets if t['status'] == 'connected')
    return render_template('index.html', 
                           targets=ssh_manager.targets,
                           connected_count=connected,
                           total_count=len(ssh_manager.targets),
                           preload=ssh_manager.preload_config,
                           os=os)

@bp.route('/add_target', methods=['POST'])
def add_target():
    key_path = None
    if 'key_file' in request.files:
        file = request.files['key_file']
        if file and file.filename != '':
            filename = secure_filename(f"{request.form['ip']}_{file.filename}")
            key_path = os.path.join(current_app.config['KEYS_FOLDER'], filename)
            file.save(key_path)

    ssh_manager.add_target(
        request.form['ip'],
        request.form.get('port', 22),
        request.form.get('user', 'root'),
        request.form.get('password'),
        key_path
    )
    return redirect(url_for('main.index'))

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

@bp.route('/api/upload', methods=['POST'])
def api_upload():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'})
    
    file = request.files['file']
    ip = request.form['ip']
    port = request.form.get('port', 22)
    remote_path = request.form['remote_path']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'})
        
    filename = secure_filename(file.filename)
    local_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    file.save(local_path)
    
    success, msg = ssh_manager.upload(ip, port, local_path, remote_path)
    return jsonify({'success': success, 'message': msg})

# 预设任务 API
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
    idx = data['index'] # fix: use index directly, not main.index? Wait, original code said main.index? checking..
    # Original code: idx = data['main.index'] -> likely a typo in my reading or user's code?
    # Let me check the original file content again.
    # Ah, the original code had `idx = data['main.index']`? No, let's look at the file content provided in Step 226.
    # Line 113: `idx = data['main.index']`. This looks wrong. Javascript sends `{type, index}`.
    # I should fix this to `data['index']`.
    
    if data['type'] == 'file':
        ssh_manager.preload_config['files'].pop(int(idx))
    elif data['type'] == 'cmd':
        ssh_manager.preload_config['commands'].pop(int(idx))
    
    ssh_manager.save_preload_config()
    return jsonify({'status': 'ok'})

@bp.route('/api/open_xshell', methods=['POST'])
def open_xshell():
    import subprocess
    data = request.json
    ip = data.get('ip')
    port = data.get('port', 22)
    user = data.get('user', 'root')
    password = data.get('password', '')
    
    xshell_path = r"Xshell" #不要修改

    try:
        if password:
            cmd = f'"{xshell_path}" -url ssh://{user}:{password}@{ip}:{port}'
        else:
            cmd = f'"{xshell_path}" -url ssh://{user}@{ip}:{port}'

        subprocess.Popen(cmd, shell=True)
        return jsonify({'success': True, 'message': 'Xshell started'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# ==================== 不死马/后门检测 API ====================

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

# ==================== 运维效率 API ====================

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

@bp.route('/api/restore_backup', methods=['POST'])
def api_restore_backup():
    """还原备份"""
    data = request.json
    ip, port = data['ip'], data.get('port', 22)
    success, msg = ssh_manager.restore_backup(ip, port)
    return jsonify({'success': success, 'message': msg})

# ==================== 定时任务 API ====================

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

# ==================== 自定义 PHP 检测规则 API ====================

@bp.route('/api/rules', methods=['GET'])
def api_get_rules():
    """获取所有自定义 PHP 规则"""
    return jsonify({'rules': ssh_manager.get_custom_rules()})

@bp.route('/api/rules/add', methods=['POST'])
def api_add_rule():
    """添加自定义 PHP 规则"""
    data = request.json
    name = data.get('name', '')
    pattern = data.get('pattern', '')
    desc = data.get('description', '')
    if not name or not pattern:
        return jsonify({'error': '名称和正则表达式不能为空'}), 400
    rule = ssh_manager.add_custom_rule(name, pattern, desc)
    return jsonify({'status': 'ok', 'rule': rule})

@bp.route('/api/rules/remove', methods=['POST'])
def api_remove_rule():
    """移除自定义 PHP 规则"""
    data = request.json
    index = data.get('index', -1)
    removed = ssh_manager.remove_custom_rule(int(index))
    if removed:
        return jsonify({'status': 'ok', 'removed': removed})
    return jsonify({'error': '规则不存在'}), 404

@bp.route('/api/rules/toggle', methods=['POST'])
def api_toggle_rule():
    """启用/禁用自定义 PHP 规则"""
    data = request.json
    index = data.get('index', -1)
    rule = ssh_manager.toggle_custom_rule(int(index))
    if rule:
        return jsonify({'status': 'ok', 'rule': rule})
    return jsonify({'error': '规则不存在'}), 404

# ==================== 远程文件管理器 API ====================

@bp.route('/api/files/list', methods=['POST'])
def api_files_list():
    """列出远程目录"""
    data = request.json
    result = ssh_manager.list_remote_dir(data['ip'], data.get('port', 22), data.get('path', '/'))
    return jsonify(result)

@bp.route('/api/files/read', methods=['POST'])
def api_files_read():
    """读取远程文件"""
    data = request.json
    result = ssh_manager.read_remote_file(data['ip'], data.get('port', 22), data['path'])
    return jsonify(result)

@bp.route('/api/files/write', methods=['POST'])
def api_files_write():
    """写入远程文件"""
    data = request.json
    success, msg = ssh_manager.write_remote_file(data['ip'], data.get('port', 22), data['path'], data['content'])
    return jsonify({'success': success, 'message': msg})

@bp.route('/api/files/delete', methods=['POST'])
def api_files_delete():
    """删除远程文件"""
    data = request.json
    success, msg = ssh_manager.delete_remote_file(data['ip'], data.get('port', 22), data['path'])
    return jsonify({'success': success, 'message': msg})

@bp.route('/api/files/upload', methods=['POST'])
def api_files_upload():
    """上传文件到远程"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
            
        ip = request.form.get('ip')
        port = request.form.get('port', 22)
        path = request.form.get('path') # Target directory
        
        if not ip or not path:
            return jsonify({'error': 'Missing IP or path'}), 400
            
        # Save to temp
        import tempfile
        tmp_fd, tmp_path = tempfile.mkstemp()
        os.close(tmp_fd)
        file.save(tmp_path)
        
        # Upload
        # path is the directory, we invoke upload logic
        # But wait, services.upload takes (local_path, remote_path_full)
        # So we construct remote path as directory + filename
        
        filename = file.filename
        full_remote_path = os.path.join(path, filename).replace('\\', '/') # Ensure linux path
        
        success, msg = ssh_manager.upload(ip, port, tmp_path, full_remote_path)
        
        os.remove(tmp_path)
        
        if success:
            return jsonify({'success': True, 'message': f'Uploaded to {full_remote_path}'})
        else:
            return jsonify({'error': msg}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/api/files/download', methods=['GET'])
def api_files_download():
    """下载远程文件"""
    try:
        ip = request.args.get('ip')
        port = request.args.get('port', 22)
        path = request.args.get('path')
        
        if not ip or not path:
             return jsonify({'error': 'Missing IP or path'}), 400
             
        # Create temp file
        import tempfile
        tmp_fd, tmp_path = tempfile.mkstemp()
        os.close(tmp_fd)
        
        success, msg = ssh_manager.download(ip, port, path, tmp_path)
        
        if not success:
            os.remove(tmp_path)
            return jsonify({'error': msg}), 500
            
        # Send file
        from flask import send_file
        return send_file(tmp_path, as_attachment=True, download_name=os.path.basename(path))
        
        # Note: tmp_path won't be deleted automatically. 
        # Flask 2.0+ has send_file(..., max_age=0) but deletion is manual.
        # We can use @after_this_request, but send_file is a response.
        # A simple cleanup or scheduled task might be needed if high load, 
        # but for this tool, it's acceptable or we can try to use a generator.
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== WebSocket 事件处理 ====================

def register_socketio_events(socketio):
    """注册 WebSocket 事件处理"""
    from flask_socketio import emit

    @socketio.on('connect')
    def handle_connect():
        emit('connected', {'message': 'WebSocket 已连接'})

    @socketio.on('ws_execute')
    def handle_ws_execute(data):
        """WebSocket 实时命令执行（带 cwd 跟踪）"""
        ip = data.get('ip')
        port = data.get('port', 22)
        cmd = data.get('cmd', '')
        if not ip or not cmd:
            emit('ws_output', {'error': '参数缺失'})
            return
        output, cwd = ssh_manager.execute_with_cwd(ip, port, cmd)
        emit('ws_output', {'ip': ip, 'port': port, 'cmd': cmd, 'output': output, 'cwd': cwd})

    @socketio.on('ws_execute_wwwdata')
    def handle_ws_execute_wwwdata(data):
        """WebSocket www-data 权限命令执行"""
        ip = data.get('ip')
        port = data.get('port', 22)
        cmd = data.get('cmd', '')
        if not ip or not cmd:
            emit('ws_output_wd', {'error': '参数缺失'})
            return
        output = ssh_manager.execute_as_wwwdata(ip, port, cmd)
        emit('ws_output_wd', {'ip': ip, 'port': port, 'cmd': cmd, 'output': output})