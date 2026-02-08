from flask import render_template, redirect, url_for, request, jsonify, Blueprint
import os
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