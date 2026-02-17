import signal
import sys
from app import create_app, socketio

def signal_handler(sig, frame):
    print('\n正在停止 AWD 控制台...')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':
    print("AWD 控制台启动中...")
    app = create_app()
    
    # Print Team Token
    token = app.config['TEAM_TOKEN']
    print("\n" + "="*50)
    print(" \033[91m[SECURITY] AWD TEAM TOKEN: " + token + "\033[0m")
    print("="*50 + "\n")
    
    print(f"请访问: http://localhost:8080")
    
    # [LOGGING] Ensure logger is set up (Safe to call multiple times now)
    from app.utils.logger import setup_logger
    setup_logger()
    
    # Important: Werkzeug's _internal logger might be re-enabled by debug=True
    import logging
    logging.getLogger('werkzeug').disabled = True 
    
    # Enable Windows ANSI color support for legacy terminals
    import os
    if os.name == 'nt':
        os.system('')

    # Use log_output=False (if available) or rely on disabled logger
    socketio.run(app, host='0.0.0.0', port=8080, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)
