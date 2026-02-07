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
    ssh_manager.add_target(
        request.form['ip'],
        request.form.get('port', 22),
        request.form.get('user', 'root'),
        request.form.get('password'),
        None
    )
    return redirect(url_for('main.index'))

@bp.route('/api/remove_target', methods=['POST'])
def remove_target():
    data = request.json
    success = ssh_manager.remove_target(data['ip'])
    if success:
        return jsonify({'status': 'ok'})
    else:
        return jsonify({'status': 'error', 'message': 'Target not found'}), 404

@bp.route('/api/update_password', methods=['POST'])
def update_password():
    data = request.json
    success, msg = ssh_manager.update_password(data['ip'], data['password'])
    return jsonify({'success': success, 'message': msg})

@bp.route('/api/connect', methods=['POST'])
def api_connect():
    data = request.json
    success, msg = ssh_manager.connect(data['ip'])
    return jsonify({'success': success, 'message': msg})

@bp.route('/api/disconnect', methods=['POST'])
def api_disconnect():
    data = request.json
    success, msg = ssh_manager.disconnect(data['ip'])
    return jsonify({'success': success, 'message': msg})

@bp.route('/api/execute', methods=['POST'])
def api_execute():
    data = request.json
    output = ssh_manager.execute(data['ip'], data['cmd'])
    return jsonify({'output': output})

@bp.route('/api/upload', methods=['POST'])
def api_upload():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'})
    
    file = request.files['file']
    ip = request.form['ip']
    remote_path = request.form['remote_path']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'})
        
    filename = secure_filename(file.filename)
    local_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    file.save(local_path)
    
    success, msg = ssh_manager.upload(ip, local_path, remote_path)
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
    idx = data['main.index']
    if data['type'] == 'file':
        ssh_manager.preload_config['files'].pop(idx)
    elif data['type'] == 'cmd':
        ssh_manager.preload_config['commands'].pop(idx)
    
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
    
    xshell_path = r"E:\xshell8\Xshell.exe" #不要修改
    if not os.path.exists(xshell_path):
        xshell_path = r"C:\Program Files\NetSarang\Xshell 7\Xshell.exe"
    
    if not os.path.exists(xshell_path):
        return jsonify({'success': False, 'message': 'Xshell executable not found. Please configure path.'})

    try:
        if password:
            cmd = f'"{xshell_path}" -url ssh://{user}:{password}@{ip}:{port}'
        else:
            cmd = f'"{xshell_path}" -url ssh://{user}@{ip}:{port}'

        subprocess.Popen(cmd, shell=True)
        return jsonify({'success': True, 'message': 'Xshell started'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})