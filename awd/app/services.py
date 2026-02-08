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
        self.sessions = {} # ip:port -> paramiko.SSHClient
        self.targets = []
        self.lock = threading.RLock() # 递归锁，防止死锁
        self.preload_config = {'files': [], 'commands': []}
        
        # Paths (initialized in init_app)
        self.keys_folder = None
        self.preload_folder = None
        self.backups_folder = None
        self.data_dir = None
        self.config_file = None
        self.targets_file = None
        
    def init_app(self, app):
        """Initialize with app config for thread safety"""
        self.keys_folder = app.config['KEYS_FOLDER']
        self.preload_folder = app.config['PRELOAD_FOLDER']
        self.backups_folder = app.config['BACKUPS_FOLDER']
        self.data_dir = app.config['DATA_DIR']
        self.config_file = app.config['CONFIG_FILE']
        self.targets_file = app.config['TARGETS_FILE']
        
        self.load_targets()
        self.load_preload_config()

    def _ensure_initialized(self):
        """确保在有 Flask 上下文时加载配置"""
        # With init_app, this check might be simplified or removed if init_app is guaranteed to run.
        # For now, we'll keep a basic check if targets are loaded.
        if not self.targets and self.data_dir: # Check if targets are empty and paths are set
            self.load_targets()
            self.load_preload_config() # Also ensure preload config is loaded

    def load_preload_config(self):
        if self.config_file and os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    self.preload_config = json.load(f)
            except:
                pass
        else:
             self.preload_config = {'files': [], 'commands': []}

    def save_preload_config(self):
        if self.config_file:
            with open(self.config_file, 'w') as f:
                json.dump(self.preload_config, f, indent=4)

    def load_targets(self):
        """从文件加载靶机列表"""
        if self.targets_file and os.path.exists(self.targets_file):
            try:
                with open(self.targets_file, 'r') as f:
                    loaded = json.load(f)
                    self.targets = []
                    if isinstance(loaded, list):
                        for t in loaded:
                            if not isinstance(t, dict): continue
                            # Ensure defaults
                            t.setdefault('status', 'disconnected')
                            self.targets.append(t)
                print(f"Loaded {len(self.targets)} targets from {self.targets_file}")
            except Exception as e:
                print(f"Error loading targets: {e}")
                self.targets = []
        else:
            self.targets = []

    def save_targets(self):
        """保存靶机列表到文件"""
        if self.targets_file:
            try:
                with open(self.targets_file, 'w') as f:
                    # 保存时只保留配置信息，不保存状态
                    targets_to_save = []
                    for t in self.targets:
                        targets_to_save.append({
                            'ip': t['ip'],
                            'port': t['port'],
                            'user': t['user'],
                            'password': t.get('password'),
                            'key_path': t.get('key_path'),
                            'preload_done': t.get('preload_done'),
                            'backup_path': t.get('backup_path'),
                            'detection': t.get('detection') # Save detection results too
                        })
                    json.dump(targets_to_save, f, indent=4)
                print(f"Targets saved successfully to {self.targets_file}")
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
        port = int(port)
        
        with self.lock:
            for ip in ips:
                # 检查是否已存在 (IP + Port)
                exists = False
                for t in self.targets:
                    if t['ip'] == ip and t['port'] == port:
                        exists = True
                        break
                
                if not exists:
                    self.targets.append({
                        'ip': ip,
                        'port': port,
                        'user': user,
                        'password': password,
                        'key_path': key_path,
                        'status': 'disconnected'
                    })
            self.save_targets()

    def remove_target(self, ip, port):
        """移除靶机"""
        if not ip:
            return False
        ip = ip.strip()
        port = int(port)
        print(f"Attempting to remove target: '{ip}:{port}'")
        with self.lock:
            self.disconnect(ip, port)
            
            original_len = len(self.targets)
            self.targets = [t for t in self.targets if not (t['ip'] == ip and t['port'] == port)]
            
            if len(self.targets) < original_len:
                print(f"Target {ip}:{port} removed from memory list. Saving to file...")
                self.save_targets()
                return True
            else:
                print(f"Target {ip}:{port} not found in list.")
                return False

    def update_password(self, ip, port, password):
        """更新靶机密码"""
        if not ip:
            return False, "IP required"
        ip = ip.strip()
        port = int(port)
        
        with self.lock:
            target = next((t for t in self.targets if t['ip'] == ip and t['port'] == port), None)
            if not target:
                return False, "Target not found"
            
            target['password'] = password
            if target['status'] == 'connected':
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

    def connect(self, ip, port, private_key_path=None):
        ip = ip.strip()
        port = int(port)
        target = next((t for t in self.targets if t['ip'] == ip and t['port'] == port), None)
        if not target:
            return False, "Target not found"

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            connected = False
            
            # 1. 尝试显式指定的密钥 (Explicit Key)
            if private_key_path and os.path.exists(private_key_path):
                print(f"[{ip}:{port}] Trying explicit key: {private_key_path}")
                try:
                    client.connect(ip, port=target['port'], username=target['user'], key_filename=private_key_path, timeout=5)
                    connected = True
                    # 如果成功，更新 target 的 key_path，以便下次自动使用
                    target['key_path'] = private_key_path 
                except Exception as e:
                    print(f"[{ip}:{port}] Explicit key failed: {e}")

            # 2. 尝试已保存的密钥 (Saved Key)
            if not connected and target.get('key_path') and os.path.exists(target['key_path']):
                # 如果显式指定的和保存的一样，就不用重试了 (但这应该由调用者控制，或者这里简单判断)
                if private_key_path != target['key_path']:
                    print(f"[{ip}:{port}] Trying saved key: {target['key_path']}")
                    try:
                        client.connect(ip, port=target['port'], username=target['user'], key_filename=target['key_path'], timeout=5)
                        connected = True
                    except Exception as e:
                        print(f"[{ip}:{port}] Saved key failed: {e}")
            
            # 3. 尝试密码 (Password)
            if not connected and target.get('password'):
                print(f"[{ip}:{port}] Trying password...")
                try:
                    client.connect(ip, port=target['port'], username=target['user'], password=target['password'], timeout=5)
                    connected = True
                except Exception as e:
                    print(f"[{ip}:{port}] Password failed: {e}")

            # 4. 尝试匹配目录下的所有密钥 (Key Directory Fallback)
            if not connected:
                print(f"[{ip}:{port}] Falling back to key directory scan...")
                keys = self.get_available_keys()
                
                # 优化排序策略:
                # 1. 文件名包含 IP 的最优先 (match_score = 0)
                # 2. 其他按默认顺序 (match_score = 1)
                # 可以在这里增加过滤逻辑，例如：如果 key 文件名包含其他 IP 且不包含当前 IP，则得分为 2 (最后尝试或跳过)
                
                def sort_key(k_path):
                    k_name = os.path.basename(k_path)
                    if ip in k_name:
                        return 0
                    # 简单 heuristic: 包含数字和点，看起来像 IP，但不是当前 IP
                    # 这里为了安全起见，只是降低优先级，不完全跳过，除非数量巨大
                    return 1

                keys.sort(key=sort_key)
                
                for key in keys:
                    # 快速失败尝试: timeout 设为 2秒
                    try:
                        # print(f"[{ip}:{port}] Trying fallback key: {os.path.basename(key)}")
                        client.connect(ip, port=target['port'], username=target['user'], key_filename=key, timeout=2)
                        target['key_path'] = key
                        connected = True
                        print(f"[{ip}:{port}] Match found: {key}")
                        break
                    except:
                        continue
            
            if connected:
                session_key = f"{ip}:{port}"
                self.sessions[session_key] = client
                target['status'] = 'connected'

                # 4. Detect Target Type
                threading.Thread(target=self.detect_target_type, args=(ip, port)).start()
                
                self.save_targets() # 更新 key_path
                # 执行预设任务 (默认不强制重跑，会检查状态)
                threading.Thread(target=self.run_preload_tasks, args=(ip, port)).start()
                return True, "Connected successfully. Preload tasks started."
            
            return False, "Authentication failed"

        except Exception as e:
            target['status'] = 'error'
            return False, str(e)

    def detect_target_type(self, ip, port):
        """识别靶机类型 (PHP/Python/Pwn)"""
        print(f"[{ip}:{port}] DEBUG: Starting detection...")
        detection = {'types': [], 'evidence': {}}
        target = next((t for t in self.targets if t['ip'] == ip and t['port'] == port), None)
        if not target: 
             print(f"[{ip}:{port}] DEBUG: Target not found in list during detection.")
             return

        try:
            # Check PHP
            # 1. Look for .php files (Primary Check)
            out_php_find = self.execute(ip, port, "find /var/www/html -name '*.php' | head -n 5")
            print(f"[{ip}:{port}] DEBUG: PHP check (find *.php) output: {out_php_find}")
            
            if out_php_find and '.php' in out_php_find:
                detection['types'].append('php')
                detection['evidence']['php_scripts'] = out_php_find.strip()

            # 2. Look for web root files (Secondary, only for info if PHP detected or specific request)
            # User requested NOT to show web root files as evidence for detection, 
            # but we might still want to know if index.php exists for other logic.
            # For now, we purely rely on find *.php for the 'php' type assignment.
            
            # out_php = self.execute(ip, port, "ls /var/www/html")
            # if out_php and ("index.php" in out_php or "html" in out_php):
            #    if 'php' not in detection['types']:
            #        detection['types'].append('php') # Old logic, removed as per request
            #    detection['evidence']['web_root_files'] = out_php.strip() # Removed as per request

            # Check Python (/home has .py)

            # Check Python (/home has .py)
            out_py = self.execute(ip, port, "find /home -name '*.py' | head -n 5")
            print(f"[{ip}:{port}] DEBUG: Python check output: {out_py}")
            if out_py and '.py' in out_py:
                detection['types'].append('python')
                detection['evidence']['python'] = out_py.strip()

                detection['evidence']['php'] = out_php.strip()

            # Check Pwn (/home has executable with no extension)
            # ! -name "*.*" ensures no extension
            out_pwn = self.execute(ip, port, "find /home -type f -executable ! -name '*.*' | head -n 5")
            if out_pwn and out_pwn.strip():
                detection['types'].append('pwn')
                detection['evidence']['pwn'] = out_pwn.strip()

        except Exception as e:
            print(f"[{ip}:{port}] Detection error: {e}")

        with self.lock:
            target['detection'] = detection
            self.save_targets()
        print(f"[{ip}:{port}] Detection complete: {detection['types']}")
        
        # 触发自动备份
        if detection['types']:
             print(f"[{ip}:{port}] DEBUG: Triggering backup for types: {detection['types']}")
             self.backup_target(ip, port, detection)
        else:
             print(f"[{ip}:{port}] DEBUG: No types detected, skipping backup.")

        # 如果是 PHP，开启新线程扫描危险函数 (满足用户多线程需求)
        if 'php' in detection['types']:
            print(f"[{ip}:{port}] DEBUG: Triggering PHP scan...")
            threading.Thread(target=self.scan_php_vulns, args=(ip, port)).start()
        else:
            print(f"[{ip}:{port}] DEBUG: Not PHP, skipping scan.")

    def scan_php_vulns(self, ip, port):
        """扫描 PHP 危险函数"""
        target = next((t for t in self.targets if t['ip'] == ip and t['port'] == port), None)
        if not target: return

        print(f"[{ip}:{port}] Starting PHP vulnerability scan...")
        # 扫描常见 Webshell/RCE 函数 (Use raw string for regex)
        cmd = r"grep -rnE 'system\(|exec\(|passthru\(|shell_exec\(|popen\(|proc_open\(|eval\(' /var/www/html | head -n 20"
        
        try:
            output = self.execute(ip, port, cmd)
            if output and output.strip():
                with self.lock:
                    if 'detection' not in target: target['detection'] = {}
                    target['detection']['php_vulns'] = output.strip()
                    self.save_targets()
                print(f"[{ip}:{port}] PHP Scan found risks!")
            else:
                print(f"[{ip}:{port}] PHP Scan clean.")
        except Exception as e:
            print(f"[{ip}:{port}] Scan error: {e}")

    def backup_target(self, ip, port, detection=None, force_rerun=False):
        """根据检测结果自动备份"""
        target = next((t for t in self.targets if t['ip'] == ip and t['port'] == port), None)
        if not target: return

        # Avoid redundant backups unless forced
        if target.get('backup_done') and not force_rerun:
            print(f"[{ip}:{port}] Backup already done. Skipping.")
            return

        if not detection:
             detection = target.get('detection', {'types': []})

        print(f"[{ip}:{port}] Starting automated backup...")
        # Use self.backups_folder (thread-safe) instead of current_app
        if not self.backups_folder:
            print(f"[{ip}:{port}] Error: Backups folder not initialized.")
            return

        if not os.path.exists(self.backups_folder):
            os.makedirs(self.backups_folder)
            
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        
        try:
            # PHP Backup
            if 'php' in detection['types']:
                remote_src = "/var/www/html"
                backup_name = f"{ip}_{port}_php_{timestamp}.tar"
                local_dst = os.path.join(self.backups_folder, backup_name)
                
                # Check if file already exists locally (deduplication)
                if os.path.exists(local_dst):
                    print(f"[{ip}:{port}] Backup file {backup_name} already exists locally. Skipping download.")
                    with self.lock:
                        target = next((t for t in self.targets if t['ip'] == ip and t['port'] == port), None)
                        if target:
                            target['backup_path'] = local_dst
                            target['backup_done'] = True
                            self.save_targets()
                    return

                print(f"[{ip}:{port}] Backing up PHP: {remote_src} -> {local_dst}")
                # 1. Tar remote (ignore errors with || true)
                self.execute(ip, port, f"tar -cf /tmp/{backup_name} {remote_src} 2>/dev/null || true")
                # 2. Download
                self.download(ip, port, f"/tmp/{backup_name}", local_dst)
                # 3. Clean remote
                self.execute(ip, port, f"rm /tmp/{backup_name}")

            # Python Backup
            if 'python' in detection['types'] and 'python' in detection['evidence']:
                evidence = detection['evidence']['python']
                # Try to guess root dir from evidence (e.g., /home/ctf/app.py -> /home/ctf)
                remote_src = os.path.dirname(evidence.split('\n')[0])
                backup_name = f"{ip}_{port}_python_{timestamp}.tar"
                local_dst = os.path.join(self.backups_folder, backup_name)
                
                print(f"[{ip}:{port}] Backing up Python: {remote_src} -> {local_dst}")
                self.execute(ip, port, f"tar -cf /tmp/{backup_name} {remote_src} 2>/dev/null || true")
                self.download(ip, port, f"/tmp/{backup_name}", local_dst)
                self.execute(ip, port, f"rm /tmp/{backup_name}")

            # Pwn Backup
            if 'pwn' in detection['types'] and 'pwn' in detection['evidence']:
                remote_src = detection['evidence']['pwn'].split('\n')[0]
                backup_name = f"{ip}_{port}_pwn_{timestamp}_{os.path.basename(remote_src)}"
                local_dst = os.path.join(self.backups_folder, backup_name)
                
                print(f"[{ip}:{port}] Backing up Pwn: {remote_src} -> {local_dst}")
                self.download(ip, port, remote_src, local_dst)

            # Py/Pwn backup logic skipped for brevity, assuming similar structure logic
            
            # 保存备份路径到 target
            with self.lock:
                target = next((t for t in self.targets if t['ip'] == ip and t['port'] == port), None)
                if target:
                    target['backup_path'] = local_dst
                    target['backup_done'] = True
                    self.save_targets()
            
            print(f"[{ip}:{port}] Backup completed successfully.")
                    
        except Exception as e:
            print(f"[{ip}:{port}] Backup error: {e}")

    def download(self, ip, port, remote_path, local_path):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
        
        if session_key not in self.sessions:
            return False, "Not connected"
        try:
            sftp = self.sessions[session_key].open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            return True, f"Downloaded: {local_path}"
        except Exception as e:
            return False, str(e)

    def disconnect(self, ip, port):
        """断开连接"""
        ip = ip.strip()
        port = int(port)
        target = next((t for t in self.targets if t['ip'] == ip and t['port'] == port), None)
        
        session_key = f"{ip}:{port}"
        if session_key in self.sessions:
            try:
                self.sessions[session_key].close()
            except:
                pass
            del self.sessions[session_key]
        
        if target:
            target['status'] = 'disconnected'
        return True, "Disconnected"

    def run_preload_tasks(self, ip, port, force_rerun=False):
        """执行预设的文件上传和命令"""
        target = next((t for t in self.targets if t['ip'] == ip and t['port'] == port), None)
        if not target: return

        # 检查是否已完成
        if not force_rerun and target.get('preload_done'):
            print(f"[{ip}:{port}] Preload tasks already done. Skipping.")
            return

        print(f"[{ip}:{port}] Starting preload tasks...")
        
        # 1. 上传文件
        if self.preload_folder:
            for file_item in self.preload_config.get('files', []):
                local_path = os.path.join(self.preload_folder, file_item['filename'])
                if os.path.exists(local_path):
                    self.upload(ip, port, local_path, file_item['remote_path'])
                    print(f"[{ip}:{port}] Uploaded {file_item['filename']}")
        else:
             print(f"[{ip}:{port}] Warning: Preload folder not initialized.")

        # 2. 执行命令
        for cmd in self.preload_config.get('commands', []):
            time.sleep(0.5)
            output = self.execute(ip, port, cmd)
            print(f"[{ip}:{port}] Executed: {cmd}\\nOutput: {output.strip()}")

        # 标记为已完成并保存
        target['preload_done'] = True
        self.save_targets()
        print(f"[{ip}:{port}] Preload tasks completed.")

    def execute(self, ip, port, cmd):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
        
        if session_key not in self.sessions:
            return "Not connected"
        try:
            transport = self.sessions[session_key].get_transport()
            if not transport or not transport.is_active():
                self.connect(ip, port)
            
            stdin, stdout, stderr = self.sessions[session_key].exec_command(cmd, timeout=10)
            return stdout.read().decode() + stderr.read().decode()
        except Exception as e:
            return f"Error: {str(e)}"

    def upload(self, ip, port, local_path, remote_path):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
        
        if session_key not in self.sessions:
            return False, "Not connected"
        try:
            sftp = self.sessions[session_key].open_sftp()
            
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