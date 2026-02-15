from flask_socketio import emit
from app.services import ssh_manager

def register_socketio_events(socketio):
    """注册 WebSocket 事件处理"""

    @socketio.on('connect')
    def handle_connect():
        emit('connected', {'message': 'WebSocket 已连接'})

    @socketio.on('ws_execute')
    def handle_ws_execute(data):
        """WebSocket 实时命令执行（带 cwd 跟踪）"""
        ip = data.get('ip')
        port = data.get('port', 22)
        cmd = data.get('cmd', '')
        if not ip or not cmd:
            emit('ws_output', {'error': '参数缺失'})
            return
        output, cwd = ssh_manager.execute_with_cwd(ip, port, cmd)
        emit('ws_output', {'ip': ip, 'port': port, 'cmd': cmd, 'output': output, 'cwd': cwd})

    @socketio.on('ws_execute_wwwdata')
    def handle_ws_execute_wwwdata(data):
        """WebSocket www-data 权限命令执行"""
        ip = data.get('ip')
        port = data.get('port', 22)
        cmd = data.get('cmd', '')
        if not ip or not cmd:
            emit('ws_output_wd', {'error': '参数缺失'})
            return
        output = ssh_manager.execute_as_wwwdata(ip, port, cmd)
        emit('ws_output_wd', {'ip': ip, 'port': port, 'cmd': cmd, 'output': output})
