import signal
import sys
import logging
from app import create_app, socketio

# 确保日志在最早阶段初始化
from app.utils.logger import setup_logger
setup_logger()
logger = logging.getLogger('System')

def signal_handler(sig, frame):
    logger.info('正在停止 AWD 控制台...')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':
    logger.info("AWD 控制台启动中...")
    app = create_app()
    
    # Log Team Token
    token = app.config['TEAM_TOKEN']
    logger.info("="*50)
    logger.info(f"[SECURITY] AWD TEAM TOKEN: {token}")
    logger.info("="*50)
    logger.info(f"请访问: http://localhost:8080")
    
    # Important: Werkzeug's _internal logger might be re-enabled by debug=True
    logging.getLogger('werkzeug').disabled = True 
    
    # Enable Windows ANSI color support for legacy terminals
    import os
    if os.name == 'nt':
        os.system('')

    # Use log_output=False (if available) or rely on disabled logger
    socketio.run(app, host='0.0.0.0', port=8080, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)
