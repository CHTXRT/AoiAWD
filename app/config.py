import os

class Config:
    # app/config.py is in .../awd/app/config.py
    # We want BASE_DIR to be .../awd/
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    
    UPLOAD_FOLDER = os.path.join(DATA_DIR, 'uploads')
    KEYS_FOLDER = os.path.join(BASE_DIR, 'keys')
    PRELOAD_FOLDER = os.path.join(DATA_DIR, 'preload')
    BACKUPS_FOLDER = os.path.join(DATA_DIR, 'backups')
    CONFIG_FILE = os.path.join(DATA_DIR, 'preload_config.json')
    TARGETS_FILE = os.path.join(DATA_DIR, 'targets.json')
    
    @staticmethod
    def init_app(app):
        # 确保目录存在
        for folder in [app.config['UPLOAD_FOLDER'], app.config['KEYS_FOLDER'], app.config['PRELOAD_FOLDER'], app.config['BACKUPS_FOLDER']]:
            if not os.path.exists(folder):
                os.makedirs(folder)

        # 确保日志目录存在 (logs moved to data/logs)
        log_dir = os.path.join(Config.DATA_DIR, 'logs')
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)