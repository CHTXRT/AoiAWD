import os
import json
import time
import hashlib
import re
import threading
import paramiko
import ipaddress
import stat
import requests
from flask import current_app, render_template

class SSHController:
    def __init__(self):
        self.sessions = {} # ip:port -> paramiko.SSHClient
        self.targets = []
        self.lock = threading.RLock() # 递归锁，防止死锁
        self.preload_config = {'files': [], 'commands': []}
        
        # Console 工作目录跟踪（模拟终端状态）
        self.console_cwd = {}  # {"ip:port": "/current/dir"}
        self.socketio = None
        
        # 定时任务
        self.scheduled_tasks = {}  # {name: {cmd, interval, last_run}}
        self._scheduler_running = False
        self._scheduler_thread = None
        
        # 自定义 PHP 检测规则
        self.custom_php_rules = []
        self.custom_rules_file = None
        
        # Paths (initialized in init_app)
        self.keys_folder = None
        self.preload_folder = None
        self.backups_folder = None
        self.data_dir = None
        self.config_file = None
        self.targets_file = None

    def set_socketio(self, socketio):
        self.socketio = socketio

    def notify_target_update(self, target, action='update'):
        if not self.socketio: return
        t_data = target.copy()
        if 'detection' in t_data and t_data['detection']:
            det = t_data['detection'].copy()
            if 'types' in det and isinstance(det['types'], set):
                det['types'] = list(det['types'])
            t_data['detection'] = det
        
        # Render HTML snippets
        html_main = ''
        html_detail = ''
        if self.app and action != 'remove':
             try:
                 with self.app.app_context():
                     html_main = render_template('target_main_row.html', t=target)
                     html_detail = render_template('target_detail_row.html', t=target)
             except Exception as e:
                 print(f"Template render error: {e}")
        
        try:
            self.socketio.emit('target_update', {
                'action': action, 
                'target': t_data,
                'html_main': html_main,
                'html_detail': html_detail
            })
        except Exception as e:
            print(f"SocketIO emit error: {e}")
        

        
    def init_app(self, app):
        """Initialize with app config for thread safety"""
        self.app = app # Save app instance for context
        self.keys_folder = app.config['KEYS_FOLDER']
        self.preload_folder = app.config['PRELOAD_FOLDER']
        self.backups_folder = app.config['BACKUPS_FOLDER']
        self.data_dir = app.config['DATA_DIR']
        self.config_file = app.config['CONFIG_FILE']
        self.targets_file = app.config['TARGETS_FILE']
        
        self.load_targets()
        self.load_preload_config()
        self.custom_rules_file = os.path.join(self.data_dir, 'custom_php_rules.json')
        self.load_custom_rules()

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
                    # Use the last added target reference
                    new_target = self.targets[-1]
                    self.notify_target_update(new_target, action='add')

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
                # Notify frontend about removal
                self.notify_target_update({'ip': ip, 'port': port}, action='remove')
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
        folder = self.keys_folder
        if not folder and self.app:
            folder = self.app.config.get('KEYS_FOLDER')
            
        if folder and os.path.exists(folder):
            for f in os.listdir(folder):
                path = os.path.join(folder, f)
                if os.path.isfile(path):
                    keys.append(path)
        return keys

    def connect(self, ip, port, private_key_path=None):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
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
                self.sessions[session_key] = client
                target['status'] = 'connected'
                self.notify_target_update(target)

                # 4. Detect Target Type
                threading.Thread(target=self.detect_target_type, args=(ip, port)).start()
                
                self.save_targets() # 更新 key_path
                # 执行预设任务 (默认不强制重跑，会检查状态)
                threading.Thread(target=self.run_preload_tasks, args=(ip, port)).start()
                return True, "Connected successfully. Preload tasks started."
            
            return False, "Authentication failed"

        except Exception as e:
            target['status'] = 'error'
            self.notify_target_update(target)
            return False, str(e)

    def detect_target_type(self, ip, port):
        """识别靶机类型 (PHP/Python/Pwn)"""
        print(f"[{ip}:{port}] DEBUG: Starting detection...")
        target = next((t for t in self.targets if t['ip'] == ip and t['port'] == port), None)
        if not target: 
             print(f"[{ip}:{port}] DEBUG: Target not found in list during detection.")
             return
        
        target['status'] = 'detecting...'
        self.notify_target_update(target)

        detection = {'types': [], 'evidence': {}}
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
            target['status'] = 'connected'
            self.notify_target_update(target)
            self.save_targets()
        print(f"[{ip}:{port}] Detection complete: {detection['types']}")
        
        # 触发自动备份
        if detection['types']:
             print(f"[{ip}:{port}] DEBUG: Triggering backup for types: {detection['types']}")
             self.backup_target(ip, port, detection)
        else:
             print(f"[{ip}:{port}] DEBUG: No types detected, skipping backup.")

        # 如果是 PHP，开启新线程扫描危险函数
        if 'php' in detection['types']:
            print(f"[{ip}:{port}] DEBUG: Triggering PHP scan...")
            threading.Thread(target=self.scan_php_vulns, args=(ip, port)).start()
            # 部署 www-data 权限后门
            threading.Thread(target=self.setup_wwwdata_shell, args=(ip, port)).start()

        # 如果是 Python，开启新线程扫描危险函数
        if 'python' in detection['types']:
            print(f"[{ip}:{port}] DEBUG: Triggering Python scan...")
            threading.Thread(target=self.scan_python_vulns, args=(ip, port)).start()

        if not detection['types']:
            print(f"[{ip}:{port}] DEBUG: No types detected, skipping scan.")

    def scan_php_vulns(self, ip, port):
        """扫描 PHP 危险函数（内置 + 自定义规则）"""
        target = next((t for t in self.targets if t['ip'] == ip and t['port'] == port), None)
        if not target: return

        print(f"[{ip}:{port}] Starting PHP vulnerability scan...")
        target['status'] = 'scanning...'
        self.notify_target_update(target)

        # 内置规则
        builtin_patterns = [
            'system\\(', 'exec\\(', 'passthru\\(', 'shell_exec\\(',
            'popen\\(', 'proc_open\\(', 'eval\\(',
            'assert\\(', 'preg_replace.*\\/e',
            'base64_decode\\(', 'file_put_contents\\(',
        ]
        # 加载自定义规则
        custom_patterns = [r['pattern'] for r in self.custom_php_rules if r.get('enabled', True)]
        all_patterns = builtin_patterns + custom_patterns

        # 拼接 grep 表达式
        grep_expr = '|'.join(all_patterns)
        cmd = f"grep -rnE '{grep_expr}' /var/www/html --include='*.php' | head -n 30"

        try:
            output = self.execute(ip, port, cmd)
            processed_lines = []
            if output and output.strip():
                for line in output.strip().split('\n'):
                    parts = line.split(':', 2)
                    if len(parts) >= 3:
                        content = parts[2]
                        risk_tag = 'Unknown'
                        for p in all_patterns:
                            if re.search(p, content):
                                risk_tag = p.replace('\\(', '').replace('\\)', '').replace('.*', ' ').replace('\\/', '/')
                                break
                        if risk_tag == 'preg_replace /e': risk_tag = 'preg_replace /e'
                        processed_lines.append(f"{parts[0]}:{parts[1]}:{risk_tag}:{content}")
                    else:
                        processed_lines.append(line)
                
                final_output = '\n'.join(processed_lines)

                with self.lock:
                    if 'detection' not in target: target['detection'] = {}
                    target['detection']['php_vulns'] = final_output
                    self.save_targets()
                print(f"[{ip}:{port}] PHP Scan found risks!")
            else:
                print(f"[{ip}:{port}] PHP Scan clean.")
                
            target['status'] = 'connected'
            self.notify_target_update(target)
            self.save_targets()
        except Exception as e:
            print(f"[{ip}:{port}] Scan error: {e}")

    def scan_python_vulns(self, ip, port):
        """扫描 Python 危险函数"""
        target = next((t for t in self.targets if t['ip'] == ip and t['port'] == port), None)
        if not target: return

        print(f"[{ip}:{port}] Starting Python vulnerability scan...")
        target['status'] = 'scanning...'
        self.notify_target_update(target)
        
        # Python 危险函数模式
        patterns = [
            'eval\\(', 'exec\\(', 'compile\\(',
            'os\\.system\\(', 'os\\.popen\\(',
            'subprocess\\.', 'commands\\.',
            'pickle\\.loads', 'yaml\\.load\\(',
            '__import__\\(', 'importlib\\.import',
            'input\\(.*\\)',  # Python 2 input() is eval
        ]
        grep_expr = '|'.join(patterns)
        # 排除 upload/uploads 目录
        cmd = f"grep -rnE '{grep_expr}' /home --include='*.py' --exclude-dir=upload --exclude-dir=uploads | head -n 30"

        try:
            output = self.execute(ip, port, cmd)
            processed_lines = []
            if output and output.strip():
                for line in output.strip().split('\n'):
                    parts = line.split(':', 2)
                    if len(parts) >= 3:
                        content = parts[2]
                        risk_tag = 'Unknown'
                        for p in patterns:
                            if re.search(p, content):
                                risk_tag = p.replace('\\(', '').replace('\\)', '').replace('.*', ' ').replace('\\.', '.')
                                break
                        processed_lines.append(f"{parts[0]}:{parts[1]}:{risk_tag}:{content}")
                    else:
                        processed_lines.append(line)
                
                final_output = '\n'.join(processed_lines)

                with self.lock:
                    if 'detection' not in target: target['detection'] = {}
                    target['detection']['python_vulns'] = final_output
                    self.save_targets()
                print(f"[{ip}:{port}] Python Scan found risks!")
            else:
                print(f"[{ip}:{port}] Python Scan clean.")
            
            target['status'] = 'connected'
            self.notify_target_update(target)
            self.save_targets()
        except Exception as e:
            print(f"[{ip}:{port}] Python scan error: {e}")

    def setup_wwwdata_shell(self, ip, port):
        """
        Refactored www-data shell acquisition:
        1. Upload PHP payload: <?php system('cp /bin/bash /tmp/mujica;chmod u+s /tmp/mujica');?>
        2. Trigger via HTTP
        3. Delete PHP file
        4. Enable frontend button
        """
        target = next((t for t in self.targets if t['ip'] == ip and t['port'] == port), None)
        if not target: return

        print(f"[{ip}:{port}] Initializing www-data shell setup...")

        # 1. Upload PHP payload
        php_filename = f'.shell_{int(time.time())}.php'
        # Strict user payload
        php_content = "<?php system('cp /bin/bash /tmp/mujica;chmod u+s /tmp/mujica');?>"
        
        web_roots = ['/var/www/html', '/var/www', '/opt/lampp/htdocs']
        uploaded_path = None
        
        for web_root in web_roots:
            # Check directory existence first
            check_dir = self.execute(ip, port, f"ls -d {web_root}")
            if 'No such file' in check_dir or not check_dir.strip():
                print(f"[{ip}:{port}] Web root not found or empty: {web_root}")
                continue
                
            remote_path = f'{web_root}/{php_filename}'
            print(f"[{ip}:{port}] Attempting upload to: {remote_path}")
            self.execute(ip, port, f"echo '{php_content}' > {remote_path}")
            
            # Verify upload (User Requirement: Confirm via command execution)
            # using ls -la to show file details
            verify_cmd = f"ls -la {remote_path}"
            print(f"[{ip}:{port}] Verifying upload with: {verify_cmd}")
            check_file = self.execute(ip, port, verify_cmd)
            
            if check_file and "No such file" not in check_file and remote_path in check_file:
                print(f"[{ip}:{port}] Payload successfully uploaded. Details: {check_file.strip()}")
                uploaded_path = remote_path
                break
            else:
                 print(f"[{ip}:{port}] Upload verification failed for {remote_path}. Output: {check_file.strip() if check_file else 'None'}")
        
        if not uploaded_path:
            print(f"[{ip}:{port}] Failed to upload PHP payload to any candidate web root.")
            return

        time.sleep(1) 
        
        # 2. Trigger via HTTP
        triggered = False
        ports_to_try = [80, 8080, 8888]
        for try_port in ports_to_try:
            try:
                url = f'http://{ip}:{try_port}/{php_filename}'
                print(f"[{ip}:{port}] Triggering payload via: {url}")
                resp = requests.get(url, timeout=3)
                print(f"[{ip}:{port}] Trigger response code: {resp.status_code}")
                # We don't check output here as payload has no echo, just side effect
                triggered = True
                break
            except Exception as e:
                print(f"[{ip}:{port}] Trigger failed for port {try_port}: {e}")
        
        # 3. Delete PHP file (Cleanup)
        self.execute(ip, port, f"rm -f {uploaded_path}")
        print(f"[{ip}:{port}] Cleanup complete (Removed {uploaded_path}).")

        # 4. Verify & Enable Frontend
        # Check if /tmp/mujica exists and has SUID bit
        print(f"[{ip}:{port}] Verifying SUID binary /tmp/mujica...")
        check = self.execute(ip, port, "ls -la /tmp/mujica 2>/dev/null")
        print(f"[{ip}:{port}] Verification Result: {check.strip() if check else 'No output'}")
        
        if check and 'mujica' in check and (('rws' in check) or ('s' in check.split()[0])):
            print(f"[{ip}:{port}] www-data shell verified (SUID). Enabling frontend access.")
            with self.lock:
                target['wwwdata_shell'] = True
                target['wwwdata_strategy'] = 'suid' # Mark as SUID strategy
                self.notify_target_update(target)
                self.save_targets()
        else:
             print(f"[{ip}:{port}] www-data shell verification FAILED. /tmp/mujica missing or not SUID.")

        print(f"[{ip}:{port}] www-data shell 所有策略均失败")
        with self.lock:
            target['wwwdata_shell'] = False
            self.save_targets()

    def execute_as_wwwdata(self, ip, port, cmd):
        """以 www-data 权限执行命令"""
        target = next((t for t in self.targets if t['ip'] == ip and t['port'] == int(port)), None)
        if not target:
            return 'Error: 靶机未找到'
        if not target.get('wwwdata_shell'):
            return 'Error: www-data shell 未部署'

        strategy = target.get('wwwdata_strategy', 'sudo')
        # 根据策略构造命令
        if strategy == 'sudo':
            wrapped_cmd = f'sudo -u www-data bash -c "{cmd}"'
        elif strategy == 'su':
            wrapped_cmd = f'su -s /bin/bash www-data -c "{cmd}"'
        elif strategy == 'runuser':
            wrapped_cmd = f'runuser -u www-data -- bash -c "{cmd}"'
        elif strategy == 'suid':
            wrapped_cmd = f'/tmp/mujica -p -c "{cmd}"'
        else:
            wrapped_cmd = f'sudo -u www-data bash -c "{cmd}"'

        return self.execute(ip, int(port), wrapped_cmd)

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
        target['status'] = 'backing up...'
        self.notify_target_update(target)

        # Use self.backups_folder (thread-safe) instead of current_app
        if not self.backups_folder:
            print(f"[{ip}:{port}] Error: Backups folder not initialized.")
            return

        if not os.path.exists(self.backups_folder):
            os.makedirs(self.backups_folder)
            
        # Create target specific backup directory
        target_backup_dir = os.path.join(self.backups_folder, f"{ip}_{port}")
        if not os.path.exists(target_backup_dir):
            os.makedirs(target_backup_dir)
        
        try:
            # PHP Backup
            if 'php' in detection['types']:
                remote_src = "/var/www/html"
                backup_name = "web.tar"
                local_dst = os.path.join(target_backup_dir, backup_name)
                
                # Check if file already exists locally
                if os.path.exists(local_dst) and not force_rerun:
                    print(f"[{ip}:{port}] Backup file {backup_name} already exists. Skipping download.")
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
                backup_name = "web.tar"
                local_dst = os.path.join(target_backup_dir, backup_name)
                
                print(f"[{ip}:{port}] Backing up Python: {remote_src} -> {local_dst}")
                self.execute(ip, port, f"tar -cf /tmp/{backup_name} {remote_src} 2>/dev/null || true")
                self.download(ip, port, f"/tmp/{backup_name}", local_dst)
                self.execute(ip, port, f"rm /tmp/{backup_name}")

            # Pwn Backup
            if 'pwn' in detection['types'] and 'pwn' in detection['evidence']:
                remote_src = detection['evidence']['pwn'].split('\n')[0]
                backup_name = os.path.basename(remote_src)
                local_dst = os.path.join(target_backup_dir, backup_name)
                
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
            target['status'] = 'connected'
            self.notify_target_update(target)
            self.save_targets()
                    
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

    def list_remote_dir(self, ip, port, path):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
        
        if session_key not in self.sessions:
            return {'error': 'Not connected'}
            
        try:
            sftp = self.sessions[session_key].open_sftp()
            try:
                files = []
                # listdir_attr returns SFTPAttributes
                for entry in sftp.listdir_attr(path):
                    files.append({
                        'name': entry.filename,
                        'size': entry.st_size,
                        'mtime': entry.st_mtime,
                        'is_dir': stat.S_ISDIR(entry.st_mode),
                        'is_link': stat.S_ISLNK(entry.st_mode),
                        'perms': stat.filemode(entry.st_mode)
                    })
                return {'files': files}
            finally:
                sftp.close()
        except Exception as e:
            return {'error': str(e)}

    def read_remote_file(self, ip, port, path):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
        
        if session_key not in self.sessions:
            return {'error': 'Not connected'}
            
        try:
            sftp = self.sessions[session_key].open_sftp()
            try:
                with sftp.open(path, 'r') as f:
                    content = f.read()
                    try:
                        return {'content': content.decode('utf-8')}
                    except UnicodeDecodeError:
                        return {'content': '[Binary file or unsupported encoding]'}
            finally:
                sftp.close()
        except Exception as e:
            return {'error': str(e)}

    def write_remote_file(self, ip, port, path, content):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
        
        if session_key not in self.sessions:
            return {'error': 'Not connected'}
            
        try:
            sftp = self.sessions[session_key].open_sftp()
            try:
                with sftp.open(path, 'w') as f:
                    # content is str, write expects bytes or str? paramiko file write expects str if mode is 'w' or bytes?
                    # usually str in text mode.
                    f.write(content)
                return {'success': True, 'message': 'Saved successfully'}
            finally:
                sftp.close()
        except Exception as e:
            return {'error': str(e)}

    def delete_remote_file(self, ip, port, path):
        output = self.execute(ip, port, f"rm -rf '{path}'")
        return {'success': True, 'message': 'Deleted'}

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
            self.notify_target_update(target)
            
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

    def execute_with_cwd(self, ip, port, cmd):
        """带工作目录跟踪的命令执行（用于 Console）"""
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"

        # 获取当前 cwd
        cwd = self.console_cwd.get(session_key, '~')

        # 构造完整命令：先 cd 到当前目录，再执行用户命令，最后 pwd 获取新目录
        full_cmd = f"cd {cwd} 2>/dev/null; {cmd}; echo '___CWD___'; pwd"
        raw_output = self.execute(ip, port, full_cmd)

        if raw_output and '___CWD___' in raw_output:
            parts = raw_output.rsplit('___CWD___', 1)
            output = parts[0].rstrip('\n')
            new_cwd = parts[1].strip()
            if new_cwd:
                self.console_cwd[session_key] = new_cwd
            return output, new_cwd
        return raw_output, cwd

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
            
            # Verify via remote shell command (User Requirement)
            # Using verify_cmd to check file existence
            verify_cmd = f"ls -la {target_path}"
            check = self.execute(ip, port, verify_cmd)
            
            if check and "No such file" not in check:
                 return True, f"Success: {target_path} (Verified with '{verify_cmd}')"
            else:
                 return False, f"Upload verification failed: File not found via '{verify_cmd}'"
        except Exception as e:
            return False, str(e)

    # ==================== 不死马/后门检测 ====================

    # 后门特征正则
    BACKDOOR_PATTERNS = [
        (r'@?\s*eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)', 'PHP 一句话木马'),
        (r'@?\s*assert\s*\(\s*\$_(POST|GET|REQUEST)', 'PHP assert 后门'),
        (r'@?\s*system\s*\(\s*\$_(POST|GET|REQUEST)', 'PHP 命令执行后门'),
        (r'ignore_user_abort\s*\(\s*true\s*\)', 'PHP 不死马特征'),
        (r'set_time_limit\s*\(\s*0\s*\)', 'PHP 不死马特征'),
        (r'file_put_contents\s*\(.+base64_decode', 'PHP 文件写入后门'),
        (r'preg_replace\s*\(.*/e', 'PHP preg_replace /e 后门'),
        (r'create_function\s*\(', 'PHP 动态函数后门'),
        (r'call_user_func\s*\(\s*\$_(POST|GET|REQUEST)', 'PHP 回调后门'),
        (r'\$\w+\s*\(\s*\$_(POST|GET|REQUEST)', 'PHP 可变函数后门'),
        (r'base64_decode\s*\(\s*\$_(POST|GET|REQUEST)', 'PHP Base64 执行'),
        (r'__import__\s*\(\s*["\']os["\']\)', 'Python 命令执行'),
        (r'exec\s*\(.*request\.(form|args|data)', 'Python exec 后门'),
        (r'eval\s*\(.*request\.(form|args|data)', 'Python eval 后门'),
        (r'subprocess\.\w+\(.*request', 'Python subprocess 后门'),
        (r'os\.system\s*\(.*request', 'Python os.system 后门'),
        (r'os\.popen\s*\(.*request', 'Python os.popen 后门'),
    ]

    def snapshot_files(self, ip, port):
        """建立文件快照基线（路径→MD5 映射）"""
        target = next((t for t in self.targets if t['ip'] == ip and t['port'] == int(port)), None)
        if not target:
            return False, '靶机未找到'

        print(f"[{ip}:{port}] 建立文件快照基线...")
        snapshot = {}

        # 扫描目录列表
        scan_dirs = ['/var/www/html', '/home']
        for scan_dir in scan_dirs:
            # 获取所有文件的路径和 MD5（/home 下排除 upload/uploads 目录）
            exclude = "-not -path '*/upload/*' -not -path '*/uploads/*'" if 'home' in scan_dir else ''
            cmd = f"find {scan_dir} -type f {exclude} -exec md5sum {{}} \\; 2>/dev/null"
            output = self.execute(ip, int(port), cmd)
            if output and 'Error' not in output:
                for line in output.strip().split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        md5_hash, filepath = parts
                        snapshot[filepath] = md5_hash

        with self.lock:
            target['file_snapshot'] = snapshot
            target['snapshot_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
            self.save_targets()

        print(f"[{ip}:{port}] 快照完成，共记录 {len(snapshot)} 个文件")
        return True, f'快照完成，共 {len(snapshot)} 个文件'

    def scan_backdoor(self, ip, port):
        """扫描不死马/后门文件"""
        target = next((t for t in self.targets if t['ip'] == ip and t['port'] == int(port)), None)
        if not target:
            return {'error': '靶机未找到'}

        print(f"[{ip}:{port}] 开始后门扫描...")
        results = {
            'new_files': [],       # 新增文件
            'modified_files': [],  # 被修改的文件
            'deleted_files': [],   # 被删除的文件
            'backdoors': [],       # 匹配到后门特征的文件
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        }

        baseline = target.get('file_snapshot', {})

        # 获取当前文件状态
        current_files = {}
        scan_dirs = ['/var/www/html', '/home']
        for scan_dir in scan_dirs:
            exclude = "-not -path '*/upload/*' -not -path '*/uploads/*'" if 'home' in scan_dir else ''
            cmd = f"find {scan_dir} -type f {exclude} -exec md5sum {{}} \\; 2>/dev/null"
            output = self.execute(ip, int(port), cmd)
            if output and 'Error' not in output:
                for line in output.strip().split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        md5_hash, filepath = parts
                        current_files[filepath] = md5_hash

        # 对比差异
        if baseline:
            for filepath, md5_hash in current_files.items():
                if filepath not in baseline:
                    results['new_files'].append(filepath)
                elif baseline[filepath] != md5_hash:
                    results['modified_files'].append(filepath)

            for filepath in baseline:
                if filepath not in current_files:
                    results['deleted_files'].append(filepath)

        # 对新增和修改的文件进行后门特征扫描
        suspect_files = results['new_files'] + results['modified_files']
        # 如果没有基线，扫描所有 PHP/Python 文件
        if not baseline:
            suspect_files = [f for f in current_files.keys()
                           if f.endswith(('.php', '.py', '.phtml', '.pht', '.php5'))]

        for filepath in suspect_files[:50]:  # 限制扫描数量防止超时
            if not filepath.endswith(('.php', '.py', '.phtml', '.pht', '.php5', '.inc')):
                continue
            cmd = f"cat '{filepath}' 2>/dev/null"
            content = self.execute(ip, int(port), cmd)
            if content and 'Error' not in content:
                matches = self._match_backdoor_patterns(content)
                if matches:
                    results['backdoors'].append({
                        'file': filepath,
                        'matches': matches,
                        'is_new': filepath in results['new_files'],
                    })

        # 保存扫描结果
        with self.lock:
            target['backdoor_scan'] = results
            self.save_targets()

        total_issues = len(results['new_files']) + len(results['modified_files']) + len(results['backdoors'])
        print(f"[{ip}:{port}] 后门扫描完成: {len(results['new_files'])} 新增, {len(results['modified_files'])} 修改, {len(results['backdoors'])} 后门")
        return results

    def _match_backdoor_patterns(self, content):
        """匹配后门特征"""
        matches = []
        for pattern, desc in self.BACKDOOR_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                matches.append(desc)
        return list(set(matches))

    # ==================== 运维效率工具 ====================

    def connect_all(self):
        """一键连接所有靶机"""
        results = []
        threads = []

        def _connect_one(target):
            ip, port = target['ip'], target['port']
            if target['status'] == 'connected':
                results.append({'ip': ip, 'port': port, 'success': True, 'message': '已连接'})
                return
            success, msg = self.connect(ip, port)
            results.append({'ip': ip, 'port': port, 'success': success, 'message': msg})

        for t in self.targets:
            th = threading.Thread(target=_connect_one, args=(t,))
            threads.append(th)
            th.start()

        for th in threads:
            th.join(timeout=15)

        return results

    def disconnect_all(self):
        """一键断开所有靶机"""
        results = []
        for t in self.targets:
            if t['status'] == 'connected':
                success, msg = self.disconnect(t['ip'], t['port'])
                results.append({'ip': t['ip'], 'port': t['port'], 'message': msg})
        return results

    def batch_execute(self, cmd):
        """批量执行命令（所有已连接靶机）"""
        results = {}
        threads = []
        results_lock = threading.Lock()

        def _exec_one(ip, port):
            output = self.execute(ip, port, cmd)
            with results_lock:
                results[f"{ip}:{port}"] = output

        for t in self.targets:
            if t['status'] == 'connected':
                th = threading.Thread(target=_exec_one, args=(t['ip'], t['port']))
                threads.append(th)
                th.start()

        for th in threads:
            th.join(timeout=15)

        return results

    def check_connections(self):
        """检查所有 SSH 连接的健康状态"""
        results = []
        for t in self.targets:
            if t['status'] != 'connected':
                continue
            ip, port = t['ip'], t['port']
            session_key = f"{ip}:{port}"
            alive = False

            if session_key in self.sessions:
                try:
                    transport = self.sessions[session_key].get_transport()
                    if transport and transport.is_active():
                        transport.send_ignore()
                        alive = True
                except Exception:
                    alive = False

            if not alive:
                t['status'] = 'disconnected'
                if session_key in self.sessions:
                    try:
                        self.sessions[session_key].close()
                    except Exception:
                        pass
                    del self.sessions[session_key]

            results.append({'ip': ip, 'port': port, 'alive': alive})

        self.save_targets()
        return results

    def restore_backup(self, ip, port):
        """还原备份到靶机"""
        target = next((t for t in self.targets if t['ip'] == ip and t['port'] == int(port)), None)
        if not target:
            return False, '靶机未找到'

        backup_path = target.get('backup_path')
        if not backup_path or not os.path.exists(backup_path):
            return False, '备份文件不存在'

        print(f"[{ip}:{port}] 开始还原备份: {backup_path}")
        try:
            # 上传备份文件到靶机
            remote_tmp = f"/tmp/{os.path.basename(backup_path)}"
            self.upload(ip, int(port), backup_path, remote_tmp)

            # 如果是 tar 文件则解压
            if backup_path.endswith('.tar'):
                self.execute(ip, int(port), f"tar -xf {remote_tmp} -C / 2>/dev/null")
                self.execute(ip, int(port), f"rm {remote_tmp}")
                return True, '备份还原成功'
            else:
                # 对于 Pwn 二进制文件，需要知道原路径
                detection = target.get('detection', {})
                if 'pwn' in detection.get('evidence', {}):
                    original_path = detection['evidence']['pwn'].split('\n')[0]
                    self.execute(ip, int(port), f"cp {remote_tmp} {original_path} && chmod +x {original_path}")
                    self.execute(ip, int(port), f"rm {remote_tmp}")
                    return True, '二进制文件还原成功'
                return True, f'备份文件已上传到 {remote_tmp}'

        except Exception as e:
            print(f"[{ip}:{port}] 还原失败: {e}")
            return False, str(e)

    # ==================== 定时任务 ====================

    def add_scheduled_task(self, name, cmd, interval):
        """添加定时任务"""
        self.scheduled_tasks[name] = {
            'cmd': cmd,
            'interval': int(interval),  # 秒
            'last_run': 0,
            'created_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        # 启动调度器（如果未启动）
        self._start_scheduler()
        return True

    def remove_scheduled_task(self, name):
        """移除定时任务"""
        if name in self.scheduled_tasks:
            del self.scheduled_tasks[name]
            return True
        return False

    def get_scheduled_tasks(self):
        """获取所有定时任务"""
        return self.scheduled_tasks

    def _start_scheduler(self):
        """启动定时任务调度线程"""
        if self._scheduler_running:
            return
        self._scheduler_running = True
        self._scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self._scheduler_thread.start()
        print("定时任务调度器已启动")

    def _scheduler_loop(self):
        """定时任务调度主循环"""
        while self._scheduler_running:
            try:
                now = time.time()
                for name, task in list(self.scheduled_tasks.items()):
                    if now - task['last_run'] >= task['interval']:
                        print(f"[定时任务] 执行: {name} -> {task['cmd']}")
                        # 在所有已连接的靶机上执行
                        self.batch_execute(task['cmd'])
                        task['last_run'] = now
            except Exception as e:
                print(f"[定时任务] 调度器错误: {e}")
            time.sleep(5)  # 每 5 秒检查一次

    # ==================== 自定义 PHP 检测规则 ====================

    def load_custom_rules(self):
        """从文件加载自定义 PHP 检测规则"""
        if self.custom_rules_file and os.path.exists(self.custom_rules_file):
            try:
                with open(self.custom_rules_file, 'r', encoding='utf-8') as f:
                    self.custom_php_rules = json.load(f)
                print(f"已加载 {len(self.custom_php_rules)} 条自定义 PHP 规则")
            except Exception as e:
                print(f"加载自定义规则失败: {e}")
                self.custom_php_rules = []
        else:
            self.custom_php_rules = []

    def save_custom_rules(self):
        """保存自定义 PHP 检测规则到文件"""
        if self.custom_rules_file:
            try:
                with open(self.custom_rules_file, 'w', encoding='utf-8') as f:
                    json.dump(self.custom_php_rules, f, ensure_ascii=False, indent=2)
            except Exception as e:
                print(f"保存自定义规则失败: {e}")

    def add_custom_rule(self, name, pattern, description=''):
        """添加自定义 PHP 检测规则"""
        rule = {
            'name': name,
            'pattern': pattern,
            'description': description,
            'enabled': True,
        }
        self.custom_php_rules.append(rule)
        self.save_custom_rules()
        return rule

    def remove_custom_rule(self, index):
        """移除自定义 PHP 检测规则"""
        if 0 <= index < len(self.custom_php_rules):
            removed = self.custom_php_rules.pop(index)
            self.save_custom_rules()
            return removed
        return None

    def toggle_custom_rule(self, index):
        """启用/禁用自定义规则"""
        if 0 <= index < len(self.custom_php_rules):
            self.custom_php_rules[index]['enabled'] = not self.custom_php_rules[index]['enabled']
            self.save_custom_rules()
            return self.custom_php_rules[index]
        return None

    def get_custom_rules(self):
        """获取所有自定义规则"""
        return self.custom_php_rules

    # ==================== 远程文件管理器 ====================

    def list_remote_dir(self, ip, port, path='/'):
        """列出远程目录内容"""
        # 使用 ls -la 获取详细列表，stat 格式化输出
        cmd = f"ls -la {path} 2>/dev/null"
        output = self.execute(ip, int(port), cmd)
        if not output or 'Error' in output or 'Not connected' in output:
            return {'error': output or '未连接'}

        files = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('total'):
                continue
            parts = line.split(None, 8)
            if len(parts) >= 9:
                perms, links, owner, group, size, *date_parts, name = parts
                # 跳过 . 和 ..
                if name in ('.', '..'):
                    continue
                files.append({
                    'name': name,
                    'perms': perms,
                    'owner': owner,
                    'group': group,
                    'size': size,
                    'date': ' '.join(date_parts),
                    'is_dir': perms.startswith('d'),
                    'is_link': perms.startswith('l'),
                })
        return {'path': path, 'files': files}

    def read_remote_file(self, ip, port, path):
        """读取远程文件内容"""
        # 先检查文件大小，防止读取超大文件
        size_cmd = f"stat -c%s {path} 2>/dev/null"
        size_out = self.execute(ip, int(port), size_cmd)
        try:
            size = int(size_out.strip())
            if size > 1024 * 1024:  # 1MB 限制
                return {'error': '文件过大 (>1MB)，请通过 SSH 操作'}
        except:
            pass

        cmd = f"cat {path} 2>/dev/null"
        output = self.execute(ip, int(port), cmd)
        if output is None or 'Not connected' in str(output):
            return {'error': output or '未连接'}
        return {'path': path, 'content': output}

    def write_remote_file(self, ip, port, path, content):
        """写入远程文件"""
        # 使用 heredoc 写入文件，避免转义问题
        # 先 base64 编码再解码写入
        import base64
        encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        cmd = f"echo '{encoded}' | base64 -d > {path}"
        output = self.execute(ip, int(port), cmd)
        if output and 'Error' in output:
            return False, output
        return True, '文件已保存'

    def delete_remote_file(self, ip, port, path):
        """删除远程文件"""
        # 安全检查：不允许删除关键目录
        dangerous = ['/', '/home', '/var', '/var/www', '/var/www/html', '/etc', '/usr', '/bin', '/tmp']
        if path.rstrip('/') in dangerous:
            return False, '禁止删除系统关键路径'
        cmd = f"rm -f {path} 2>/dev/null"
        output = self.execute(ip, int(port), cmd)
        if output and 'Error' in output:
            return False, output
        return True, '文件已删除'


ssh_manager = SSHController()