from flask import request, jsonify, current_app, send_file
import os
import tempfile
from werkzeug.utils import secure_filename
from app.services import ssh_manager
from . import bp

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
        tmp_fd, tmp_path = tempfile.mkstemp()
        os.close(tmp_fd)
        
        success, msg = ssh_manager.download(ip, port, path, tmp_path)
        
        if not success:
            os.remove(tmp_path)
            return jsonify({'error': msg}), 500
            
        # Send file
        return send_file(tmp_path, as_attachment=True, download_name=os.path.basename(path))
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
