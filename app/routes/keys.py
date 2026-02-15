from flask import request, jsonify, current_app
import os
from werkzeug.utils import secure_filename
from app.services import ssh_manager
from . import bp

@bp.route('/api/keys', methods=['GET'])
def api_keys_list():
    """获取所有密钥列表"""
    return jsonify({'keys': ssh_manager.get_all_keys_info()})

@bp.route('/api/keys/upload', methods=['POST'])
def api_keys_upload():
    """批量上传密钥"""
    if 'files[]' not in request.files:
         # 尝试从 files 字段获取（单个或多个）
         pass
    
    uploaded = []
    # 从 files[] 或 files 字段获取
    files = request.files.getlist('files[]')
    if not files:
        files = request.files.getlist('files')

    if not files:
         return jsonify({'error': 'No files uploaded'}), 400
         
    for file in files:
        if file.filename == '': continue
        filename = secure_filename(file.filename)
        save_path = os.path.join(current_app.config['KEYS_FOLDER'], filename)
        file.save(save_path)
        uploaded.append(filename)
        
    return jsonify({'status': 'ok', 'uploaded': uploaded})

@bp.route('/api/keys/delete', methods=['POST'])
def api_keys_delete():
    """删除密钥"""
    data = request.json
    filename = data.get('filename')
    success, msg = ssh_manager.delete_key(filename)
    if success:
        return jsonify({'status': 'ok'})
    else:
        return jsonify({'error': msg}), 400
