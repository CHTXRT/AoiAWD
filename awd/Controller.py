import os
import paramiko
import threading
import json
import stat
import time
import ipaddress
from flask import Flask, request, jsonify, render_template, redirect, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__, template_folder='template')

# 配置路径
# 修改为当前文件所在目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['KEYS_FOLDER'] = os.path.join(BASE_DIR, 'keys')
app.config['PRELOAD_FOLDER'] = os.path.join(BASE_DIR, 'preload')
app.config['CONFIG_FILE'] = os.path.join(BASE_DIR, 'preload_config.json')
app.config['TARGETS_FILE'] = os.path.join(BASE_DIR, 'targets.json')

# 确保目录存在
for folder in [app.config['UPLOAD_FOLDER'], app.config['KEYS_FOLDER'], app.config['PRELOAD_FOLDER']]:
    if not os.path.exists(folder):
        os.makedirs(folder)

class SSHController:
    def __init__(self):
        self.sessions = {}  # ip -> client
        self.targets = []   # List of dicts
        self.lock = threading.Lock()
        self.preload_config = self.load_preload_config()
        self.load_targets()

    def load_preload_config(self):
        if os.path.exists(app.config['CONFIG_FILE']):
            try:
                with open(app.config['CONFIG_FILE'], 'r') as f:
                    return json.load(f)
            except:
                pass
        return {'files': [], 'commands': []}

    def save_preload_config(self):
        with open(app.config['CONFIG_FILE'], 'w') as f:
            json.dump(self.preload_config, f, indent=4)

    def load_targets(self):
        """从文件加载靶机列表"""
        if os.path.exists(app.config['TARGETS_FILE']):
            try:
                with open(app.config['TARGETS_FILE'], 'r') as f:
                    loaded = json.load(f)
                    self.targets = []
                    if isinstance(loaded, list):
                        for t in loaded:
                            # 确保数据有效性
                            if not isinstance(t, dict) or 'ip' not in t:
                                continue
                            # 确保加载时去除空格
                            t['ip'] = str(t['ip']).strip()
                            t['status'] = 'disconnected'
                            self.targets.append(t)
                print(f"Loaded {len(self.targets)} targets from {app.config['TARGETS_FILE']}")
            except Exception as e:
                print(f"Error loading targets: {e}")
                self.targets = []

    def save_targets(self):
        """保存靶机列表到文件"""
        try:
            with open(app.config['TARGETS_FILE'], 'w') as f:
                # 保存时只保留配置信息，不保存状态
                targets_to_save = []
                for t in self.targets:
                    targets_to_save.append({
                        'ip': t['ip'],
                        'port': t['port'],
                        'user': t['user'],
                        'password': t.get('password'),
                        'key_path': t.get('key_path')
                    })
                json.dump(targets_to_save, f, indent=4)
            print(f"Targets saved successfully to {app.config['TARGETS_FILE']}")
        except Exception as e:
            print(f"Error saving targets: {e}")

    def parse_ip_range(self, ip_input):
        """解析 IP 范围，支持 192.168.1.10-20 格式"""
        ips = []
        ip_input = ip_input.strip()
        
        if '-' in ip_input:
            try:
                # 处理 192.168.1.10-20
                base_part, end_range = ip_input.rsplit('-', 1)
                
                # 检查 base_part 是否是完整 IP
                try:
                    ipaddress.ip_address(base_part)
                    # 如果是完整IP，提取最后一段
                    base_ip_obj = ipaddress.ip_address(base_part)
                    start_num = int(str(base_ip_obj).split('.')[-1])
                    prefix = '.'.join(str(base_ip_obj).split('.')[:-1])
                except ValueError:
                    # 如果不是完整IP（虽然不太可能，通常用户输入完整IP），尝试手动分割
                    parts = base_part.split('.')
                    if len(parts) == 4:
                        start_num = int(parts[-1])
                        prefix = '.'.join(parts[:-1])
                    else:
                        return [ip_input] # 无法解析，原样返回

                end_num = int(end_range)
                
                # 确保范围有效
                if start_num > end_num:
                    start_num, end_num = end_num, start_num
                
                for i in range(start_num, end_num + 1):
                    ips.append(f"{prefix}.{i}")
                    
            except Exception as e:
                print(f"Error parsing IP range: {e}")
                ips.append(ip_input) # 解析失败，原样返回
        else:
            ips.append(ip_input)
            
        return ips

    def add_target(self, ip_input, port=22, user='root', password=None, key_path=None):
        if not ip_input:
            return
        
        ips = self.parse_ip_range(ip_input)
        
        with self.lock:
            for ip in ips:
                # 检查是否已存在
                exists = False
                for t in self.targets:
                    if t['ip'] == ip:
                        exists = True
                        break
                
                if not exists:
                    self.targets.append({
                        'ip': ip,
                        'port': int(port),
                        'user': user,
                        'password': password,
                        'key_path': key_path,
                        'status': 'disconnected'
                    })
            self.save_targets()

    def remove_target(self, ip):
        """移除靶机"""
        if not ip:
            return False
        ip = ip.strip()
        print(f"Attempting to remove target: '{ip}'")
        with self.lock:
            self.disconnect(ip)
            
            original_len = len(self.targets)
            self.targets = [t for t in self.targets if t['ip'] != ip]
            
            if len(self.targets) < original_len:
                print(f"Target {ip} removed from memory list. Saving to file...")
                self.save_targets()
                return True
            else:
                print(f"Target {ip} not found in list. Available: {[t['ip'] for t in self.targets]}")
                return False

    def get_available_keys(self):
        keys = []
        if os.path.exists(app.config['KEYS_FOLDER']):
            for f in os.listdir(app.config['KEYS_FOLDER']):
                path = os.path.join(app.config['KEYS_FOLDER'], f)
                if os.path.isfile(path):
                    keys.append(path)
        return keys

    def connect(self, ip):
        ip = ip.strip()
        target = next((t for t in self.targets if t['ip'] == ip), None)
        if not target:
            return False, "Target not found"

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            connected = False
            
            # 1. 尝试指定密钥
            if target.get('key_path') and os.path.exists(target['key_path']):
                try:
                    client.connect(ip, port=target['port'], username=target['user'], key_filename=target['key_path'], timeout=5)
                    connected = True
                except Exception as e:
                    print(f"[{ip}] Saved key failed: {e}")
            
            # 2. 尝试密码
            if not connected and target.get('password'):
                try:
                    client.connect(ip, port=target['port'], username=target['user'], password=target['password'], timeout=5)
                    connected = True
                except Exception as e:
                    print(f"[{ip}] Password failed: {e}")

            # 3. 尝试匹配目录下的所有密钥
            if not connected:
                keys = self.get_available_keys()
                keys.sort(key=lambda k: 0 if ip in k else 1)
                for key in keys:
                    try:
                        client.connect(ip, port=target['port'], username=target['user'], key_filename=key, timeout=5)
                        target['key_path'] = key
                        connected = True
                        break
                    except:
                        continue
            
            if connected:
                self.sessions[ip] = client
                target['status'] = 'connected'
                self.save_targets() # 更新 key_path
                # 执行预设任务
                threading.Thread(target=self.run_preload_tasks, args=(ip,)).start()
                return True, "Connected successfully. Preload tasks started."
            
            return False, "Authentication failed"

        except Exception as e:
            target['status'] = 'error'
            return False, str(e)

    def disconnect(self, ip):
        """断开连接"""
        ip = ip.strip()
        target = next((t for t in self.targets if t['ip'] == ip), None)
        if ip in self.sessions:
            try:
                self.sessions[ip].close()
            except:
                pass
            del self.sessions[ip]
        
        if target:
            target['status'] = 'disconnected'
        return True, "Disconnected"

    def run_preload_tasks(self, ip):
        """执行预设的文件上传和命令"""
        print(f"[{ip}] Starting preload tasks...")
        
        # 1. 上传文件
        for file_item in self.preload_config.get('files', []):
            local_path = os.path.join(app.config['PRELOAD_FOLDER'], file_item['filename'])
            if os.path.exists(local_path):
                self.upload(ip, local_path, file_item['remote_path'])
                print(f"[{ip}] Uploaded {file_item['filename']}")

        # 2. 执行命令
        for cmd in self.preload_config.get('commands', []):
            time.sleep(0.5)
            output = self.execute(ip, cmd)
            print(f"[{ip}] Executed: {cmd}\\nOutput: {output.strip()}")

    def execute(self, ip, cmd):
        ip = ip.strip()
        if ip not in self.sessions:
            return "Not connected"
        try:
            transport = self.sessions[ip].get_transport()
            if not transport or not transport.is_active():
                self.connect(ip)
            
            stdin, stdout, stderr = self.sessions[ip].exec_command(cmd, timeout=10)
            return stdout.read().decode() + stderr.read().decode()
        except Exception as e:
            return f"Error: {str(e)}"

    def upload(self, ip, local_path, remote_path):
        ip = ip.strip()
        if ip not in self.sessions:
            return False, "Not connected"
        try:
            sftp = self.sessions[ip].open_sftp()
            
            target_path = remote_path
            is_directory = False
            
            if target_path.endswith('/'):
                is_directory = True
            else:
                try:
                    attr = sftp.stat(target_path)
                    if stat.S_ISDIR(attr.st_mode):
                        is_directory = True
                except:
                    pass
            
            if is_directory:
                filename = os.path.basename(local_path)
                if not target_path.endswith('/'):
                    target_path += '/'
                target_path += filename
                
            sftp.put(local_path, target_path)
            sftp.close()
            return True, f"Success: {target_path}"
        except Exception as e:
            return False, str(e)

controller = SSHController()

@app.route('/')
def index():
    connected = sum(1 for t in controller.targets if t['status'] == 'connected')
    return render_template('index.html', 
                           targets=controller.targets,
                           connected_count=connected,
                           total_count=len(controller.targets),
                           preload=controller.preload_config,
                           os=os)

@app.route('/add_target', methods=['POST'])
def add_target():
    controller.add_target(
        request.form['ip'],
        request.form.get('port', 22),
        request.form.get('user', 'root'),
        request.form.get('password'),
        None
    )
    return redirect(url_for('index'))

@app.route('/api/remove_target', methods=['POST'])
def remove_target():
    data = request.json
    success = controller.remove_target(data['ip'])
    if success:
        return jsonify({'status': 'ok'})
    else:
        return jsonify({'status': 'error', 'message': 'Target not found'}), 404

@app.route('/api/connect', methods=['POST'])
def api_connect():
    data = request.json
    success, msg = controller.connect(data['ip'])
    return jsonify({'success': success, 'message': msg})

@app.route('/api/disconnect', methods=['POST'])
def api_disconnect():
    data = request.json
    success, msg = controller.disconnect(data['ip'])
    return jsonify({'success': success, 'message': msg})

@app.route('/api/execute', methods=['POST'])
def api_execute():
    data = request.json
    output = controller.execute(data['ip'], data['cmd'])
    return jsonify({'output': output})

@app.route('/api/upload', methods=['POST'])
def api_upload():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'})
    
    file = request.files['file']
    ip = request.form['ip']
    remote_path = request.form['remote_path']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'})
        
    filename = secure_filename(file.filename)
    local_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(local_path)
    
    success, msg = controller.upload(ip, local_path, remote_path)
    return jsonify({'success': success, 'message': msg})

# 预设任务 API
@app.route('/api/preload/add_file', methods=['POST'])
def add_preload_file():
    file = request.files['file']
    remote_path = request.form['remote_path']
    
    filename = secure_filename(file.filename)
    local_path = os.path.join(app.config['PRELOAD_FOLDER'], filename)
    file.save(local_path)
    
    controller.preload_config['files'].append({
        'filename': filename,
        'remote_path': remote_path
    })
    controller.save_preload_config()
    return jsonify({'status': 'ok'})

@app.route('/api/preload/add_cmd', methods=['POST'])
def add_preload_cmd():
    cmd = request.json['cmd']
    controller.preload_config['commands'].append(cmd)
    controller.save_preload_config()
    return jsonify({'status': 'ok'})

@app.route('/api/preload/remove', methods=['POST'])
def remove_preload():
    data = request.json
    idx = data['index']
    if data['type'] == 'file':
        controller.preload_config['files'].pop(idx)
    elif data['type'] == 'cmd':
        controller.preload_config['commands'].pop(idx)
    
    controller.save_preload_config()
    return jsonify({'status': 'ok'})

@app.route('/api/open_xshell', methods=['POST'])
def open_xshell():
    import subprocess
    data = request.json
    ip = data.get('ip')
    port = data.get('port', 22)
    user = data.get('user', 'root')
    password = data.get('password', '')
    
    xshell_path = r"E:\xshell8\Xshell.exe" #不要修改
    if not os.path.exists(xshell_path):
        xshell_path = r"C:\Program Files\NetSarang\Xshell 7\Xshell.exe"
    
    if not os.path.exists(xshell_path):
        return jsonify({'success': False, 'message': 'Xshell executable not found. Please configure path.'})

    try:
        if password:
            cmd = f'"{xshell_path}" -url ssh://{user}:{password}@{ip}:{port}'
        else:
            cmd = f'"{xshell_path}" -url ssh://{user}@{ip}:{port}'

        subprocess.Popen(cmd, shell=True)
        return jsonify({'success': True, 'message': 'Xshell started'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    print("AWD 控制台启动中...")
    print(f"请访问: http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
