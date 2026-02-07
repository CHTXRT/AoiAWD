import os
import json
import time
import threading
import paramiko
import ipaddress
import stat
from flask import current_app

class SSHController:
    def __init__(self):
        self.sessions = {}
        self.targets = []
        self.lock = threading.Lock()
        self.preload_config = None # 先设为 None，延迟加载
        self._initialized = False

    def _ensure_initialized(self):
        """确保在有 Flask 上下文时加载配置"""
        if not self._initialized:
            self.preload_config = self.load_preload_config()
            self.load_targets()
            self._initialized = True

    def load_preload_config(self):
        if os.path.exists(current_app.config['CONFIG_FILE']):
            try:
                with open(current_app.config['CONFIG_FILE'], 'r') as f:
                    return json.load(f)
            except:
                pass
        return {'files': [], 'commands': []}

    def save_preload_config(self):
        with open(current_app.config['CONFIG_FILE'], 'w') as f:
            json.dump(self.preload_config, f, indent=4)

    def load_targets(self):
        """从文件加载靶机列表"""
        if os.path.exists(current_app.config['TARGETS_FILE']):
            try:
                with open(current_app.config['TARGETS_FILE'], 'r') as f:
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
                print(f"Loaded {len(self.targets)} targets from {current_app.config['TARGETS_FILE']}")
            except Exception as e:
                print(f"Error loading targets: {e}")
                self.targets = []

    def save_targets(self):
        """保存靶机列表到文件"""
        try:
            with open(current_app.config['TARGETS_FILE'], 'w') as f:
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
            print(f"Targets saved successfully to {current_app.config['TARGETS_FILE']}")
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

    def update_password(self, ip, password):
        """更新靶机密码"""
        if not ip:
            return False, "IP required"
        ip = ip.strip()
        
        with self.lock:
            target = next((t for t in self.targets if t['ip'] == ip), None)
            if not target:
                return False, "Target not found"
            
            target['password'] = password
            # 如果已连接，更新连接参数（这里选择断开重连或者仅更新配置，简单起见仅更新配置，下次连接生效）
            # 或者尝试实时更新 session 的密码（复杂且不一定支持），所以简单处理：
            if target['status'] == 'connected':
                # 可选：强制断开让用户重连，或者保持连接但更新存储的密码
                pass
                
            self.save_targets()
            return True, "Password updated"

    def get_available_keys(self):
        keys = []
        if os.path.exists(current_app.config['KEYS_FOLDER']):
            for f in os.listdir(current_app.config['KEYS_FOLDER']):
                path = os.path.join(current_app.config['KEYS_FOLDER'], f)
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
            local_path = os.path.join(current_app.config['PRELOAD_FOLDER'], file_item['filename'])
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

ssh_manager = SSHController()