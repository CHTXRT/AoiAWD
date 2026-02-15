from flask import render_template, redirect, url_for, request, current_app
import os
from werkzeug.utils import secure_filename
from app.services import ssh_manager
from . import bp

@bp.route('/')
def index():
    ssh_manager._ensure_initialized()
    connected = sum(1 for t in ssh_manager.targets if t['status'] == 'connected')
    return render_template('index.html', 
                           targets=ssh_manager.targets,
                           connected_count=connected,
                           total_count=len(ssh_manager.targets),
                           preload=ssh_manager.preload_config,
                           local_ip=ssh_manager.get_local_ip(),
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
        key_path,
        request.form.get('name')
    )
    return redirect(url_for('main.index'))
