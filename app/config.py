import os
import secrets
import string

class Config:
    # app/config.py is in .../awd/app/config.py
    # We want BASE_DIR to be .../awd/
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    
    UPLOAD_FOLDER = os.path.join(DATA_DIR, 'uploads')
    KEYS_FOLDER = os.path.join(DATA_DIR, 'keys')
    PRELOAD_FOLDER = os.path.join(DATA_DIR, 'preload')
    BACKUPS_FOLDER = os.path.join(DATA_DIR, 'backups')
    CONFIG_FILE = os.path.join(DATA_DIR, 'preload_config.json')
    TARGETS_FILE = os.path.join(DATA_DIR, 'targets.json')
    IMMORTAL_LOG_FILE = os.path.join(DATA_DIR, 'immortal_alerts.json')
    
    # Agent Settings
    AGENT_CALLBACK_PORT = 8024
    AGENT_AUTO_DEPLOY = True  # 连接PHP靶机时自动部署Agent
    AGENT_AUTO_START_MONITOR = True  # 部署成功后自动启动不死马监控
    AGENT_WATCH_DIR = '/var/www/html'
    
    # Connection Settings
    AUTO_CONNECT_ALL_ON_START = False  # 启动时是否自动连接所有靶机
    AUTO_RECONNECT_DISCONNECTED = False  # 是否自动重连断开的靶机

    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
    
    # Team Token Logic
    # 1. Environment Variable
    # 2. Randomly Generated
    _generated_token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
    TEAM_TOKEN = os.environ.get('AWD_TEAM_TOKEN', _generated_token)

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