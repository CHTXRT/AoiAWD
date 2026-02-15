import os

class KeyManager:
    def __init__(self):
        self.keys_folder = None
        self.app = None

    def init_app(self, app):
        self.app = app
        self.keys_folder = app.config['KEYS_FOLDER']

    def get_available_keys(self):
        keys = []
        if self.keys_folder and os.path.exists(self.keys_folder):
            for f in os.listdir(self.keys_folder):
                path = os.path.join(self.keys_folder, f)
                if os.path.isfile(path):
                    keys.append(path)
        return keys

    def get_all_keys_info(self, targets):
        """需要传入 targets 列表来计算关联信息"""
        keys_info = []
        if not self.keys_folder or not os.path.exists(self.keys_folder):
            return []

        for f in os.listdir(self.keys_folder):
            path = os.path.join(self.keys_folder, f)
            if not os.path.isfile(path): continue
            
            used_by = []
            for t in targets:
                t_key = t.get('key_path')
                if t_key:
                    if os.path.abspath(t_key) == os.path.abspath(path):
                        used_by.append(f"{t['ip']}:{t['port']}")
            
            try:
                stat_info = os.stat(path)
                keys_info.append({
                    'name': f,
                    'size': stat_info.st_size,
                    'mtime': stat_info.st_mtime,
                    'used_by': used_by
                })
            except Exception: pass
            
        return keys_info

    def delete_key(self, filename):
        path = os.path.join(self.keys_folder, filename)
        if os.path.dirname(os.path.abspath(path)) != os.path.abspath(self.keys_folder):
            return False, "非法路径"
            
        if os.path.exists(path) and os.path.isfile(path):
            try:
                os.remove(path)
                return True, "已删除"
            except Exception as e:
                return False, str(e)
        return False, "文件不存在"
