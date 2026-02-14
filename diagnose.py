
import sys
import platform
import subprocess
import socket
import os

def print_header(title):
    print(f"\n{'='*20} {title} {'='*20}")

def check_python_info():
    print_header("系统与 Python 信息")
    print(f"OS: {platform.system()} {platform.release()} {platform.version()}")
    print(f"Python: {sys.version}")
    print(f"Executable: {sys.executable}")

def check_dependencies():
    print_header("关键依赖库版本")
    packages = [
        "flask", 
        "flask-socketio", 
        "python-socketio", 
        "python-engineio", 
        "werkzeug", 
        "gevent", 
        "eventlet",
        "simple-websocket"
    ]
    
    found_any = False
    for package in packages:
        try:
            # try to get version using pip
            result = subprocess.run(
                [sys.executable, "-m", "pip", "show", package], 
                capture_output=True, 
                text=True
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.startswith("Name:") or line.startswith("Version:"):
                        print(line)
                print("-" * 10)
                found_any = True
            else:
                print(f"{package}: 未安装")
        except Exception as e:
            print(f"检查 {package} 失败: {e}")

def check_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    return result == 0

def check_ports():
    print_header("端口占用检查")
    ports = [8080, 7890, 5000]
    for port in ports:
        try:
            is_open = check_port(port)
            status = "被占用 (Possible Conflict)" if is_open else "可用 (Available)"
            print(f"Port {port}: {status}")
        except Exception as e:
            print(f"Port {port}: 检查失败 ({e})")

def simple_flask_test():
    print_header("Flask 最小化启动测试")
    print("尝试在 127.0.0.1:0 (随机闲置端口) 启动 Flask...")
    try:
        from flask import Flask
        app = Flask(__name__)
        print("Flask 导入成功")
        # 简单测试，不实际 block 住
        print("Flask 对象创建成功")
    except ImportError:
        print("CRITICAL: 无法导入 Flask")
    except Exception as e:
        print(f"Flask 初始化失败: {e}")

def simple_socketio_test():
    print_header("SocketIO 初始化测试")
    try:
        from flask import Flask
        from flask_socketio import SocketIO
        app = Flask(__name__)
        # 尝试使用 threading 模式初始化，这是最通用的
        socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")
        print("SocketIO (threading mode) 初始化成功")
    except ImportError:
        print("CRITICAL: 无法导入 Flask-SocketIO")
    except Exception as e:
        print(f"SocketIO 初始化失败 (threading mode): {e}")

    # 同时测试默认模式
    try:
        socketio_default = SocketIO(app, cors_allowed_origins="*")
        print("SocketIO (default mode) 初始化成功")
    except:
        pass


if __name__ == "__main__":
    try:
        check_python_info()
        check_dependencies()
        check_ports()
        simple_flask_test()
        simple_socketio_test()
        print_header("诊断完成")
        print("请将上述输出发给技术支持进行分析。")
    except Exception as e:
        print(f"\n诊断脚本发生未捕获异常: {e}")
