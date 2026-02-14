import os
import json
import threading
import paramiko
import ipaddress
import stat
import time
import shlex
from flask import render_template

class SSHManager:
    def __init__(self):
        self.sessions = {} # ip:port -> paramiko.SSHClient
        self.targets = []
        self.lock = threading.RLock() # 递归锁，防止死锁
        self.console_cwd = {}  # {"ip:port": "/current/dir"}
        self.socketio = None
        self.app = None
        
        # Paths
        self.keys_folder = None
        self.data_dir = None
        self.targets_file = None
        self.local_ip = ''
        
        # Locks
        self.session_locks = {} # ip:port -> threading.RLock

    def _get_session_lock(self, session_key):
        if session_key not in self.session_locks:
            with self.lock:
                if session_key not in self.session_locks:
                    self.session_locks[session_key] = threading.RLock()
        return self.session_locks[session_key]

    def init_app(self, app):
        """Initialize with app config for thread safety"""
        self.app = app
        self.keys_folder = app.config['KEYS_FOLDER']
        self.data_dir = app.config['DATA_DIR']
        self.targets_file = app.config['TARGETS_FILE']
        
        self.load_targets()
        self._load_local_ip()

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

    def _load_local_ip(self):
        if self.data_dir:
            ip_file = os.path.join(self.data_dir, 'local_ip.txt')
            if os.path.exists(ip_file):
                try:
                    with open(ip_file, 'r') as f:
                        self.local_ip = f.read().strip()
                except:
                    pass

    def _save_local_ip(self):
        if self.data_dir:
            ip_file = os.path.join(self.data_dir, 'local_ip.txt')
            with open(ip_file, 'w') as f:
                f.write(self.local_ip)

    def set_local_ip(self, ip):
        self.local_ip = ip.strip()
        self._save_local_ip()
        print(f"[Config] 本机 IP 已设置为: {self.local_ip}")
        return True

    def get_local_ip(self):
        return self.local_ip

    def load_targets(self):
        if self.targets_file and os.path.exists(self.targets_file):
            try:
                with open(self.targets_file, 'r') as f:
                    loaded = json.load(f)
                    self.targets = []
                    if isinstance(loaded, list):
                        for t in loaded:
                            if not isinstance(t, dict): continue
                            t.setdefault('status', 'disconnected')
                            self.targets.append(t)
                print(f"Loaded {len(self.targets)} targets from {self.targets_file}")
            except Exception as e:
                print(f"Error loading targets: {e}")
                self.targets = []
        else:
            self.targets = []

    def save_targets(self):
        if self.targets_file:
            try:
                with open(self.targets_file, 'w') as f:
                    targets_to_save = []
                    for t in self.targets:
                        targets_to_save.append({
                            'ip': t['ip'],
                            'port': t['port'],
                            'name': t.get('name'),
                            'user': t['user'],
                            'password': t.get('password'),
                            'key_path': t.get('key_path'),
                            'status': t.get('status'), # Optional to save status? Maybe not needed but useful
                            'preload_done': t.get('preload_done'),
                            'backup_path': t.get('backup_path'),
                            'detection': t.get('detection'),
                             # Persist new fields if any
                            'wwwdata_shell': t.get('wwwdata_shell'),
                            'wwwdata_strategy': t.get('wwwdata_strategy'),
                            'wwwdata_password': t.get('wwwdata_password'),
                            'aoi_deployed': t.get('aoi_deployed'),
                            'file_snapshot': t.get('file_snapshot'),
                            'snapshot_time': t.get('snapshot_time'),
                            'backup_done': t.get('backup_done'),
                            'backdoor_scan': t.get('backdoor_scan')
                        })
                    json.dump(targets_to_save, f, indent=4)
            except Exception as e:
                print(f"Error saving targets: {e}")

    def parse_ip_range(self, ip_input):
        ips = []
        ip_input = ip_input.strip()
        if '-' in ip_input:
            try:
                base_part, end_range = ip_input.rsplit('-', 1)
                try:
                    ipaddress.ip_address(base_part)
                    base_ip_obj = ipaddress.ip_address(base_part)
                    start_num = int(str(base_ip_obj).split('.')[-1])
                    prefix = '.'.join(str(base_ip_obj).split('.')[:-1])
                except ValueError:
                    parts = base_part.split('.')
                    if len(parts) == 4:
                        start_num = int(parts[-1])
                        prefix = '.'.join(parts[:-1])
                    else:
                        return [ip_input]

                end_num = int(end_range)
                if start_num > end_num:
                    start_num, end_num = end_num, start_num
                
                for i in range(start_num, end_num + 1):
                    ips.append(f"{prefix}.{i}")
            except Exception as e:
                print(f"Error parsing IP range: {e}")
                ips.append(ip_input)
        else:
            ips.append(ip_input)
        return ips

    def add_target(self, ip_input, port=22, user='root', password=None, key_path=None, name=None):
        if not ip_input:
            return
        
        ips = self.parse_ip_range(ip_input)
        port = int(port)
        
        with self.lock:
            for ip in ips:
                exists = False
                for t in self.targets:
                    if t['ip'] == ip and t['port'] == port:
                        exists = True
                        break
                
                if not exists:
                    self.targets.append({
                        'ip': ip,
                        'port': port,
                        'name': name,
                        'user': user,
                        'password': password,
                        'key_path': key_path,
                        'status': 'disconnected'
                    })
                    new_target = self.targets[-1]
                    self.notify_target_update(new_target, action='add')

            self.save_targets()

    def remove_target(self, ip, port):
        if not ip: return False
        ip = ip.strip()
        port = int(port)
        with self.lock:
            self.disconnect(ip, port)
            original_len = len(self.targets)
            self.targets = [t for t in self.targets if not (t['ip'] == ip and t['port'] == port)]
            if len(self.targets) < original_len:
                self.save_targets()
                self.notify_target_update({'ip': ip, 'port': port}, action='remove')
                return True
            return False

    def update_password(self, ip, port, password):
        if not ip: return False, "IP required"
        ip = ip.strip()
        port = int(port)
        with self.lock:
            target = next((t for t in self.targets if t['ip'] == ip and t['port'] == port), None)
            if not target: return False, "Target not found"
            target['password'] = password
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
        if not target: return False, "Target not found"

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            connected = False
            # 1. Explicit Key
            if private_key_path and os.path.exists(private_key_path):
                try:
                    client.connect(ip, port=target['port'], username=target['user'], key_filename=private_key_path, timeout=5)
                    connected = True
                    target['key_path'] = private_key_path 
                except Exception: pass

            # 2. Saved Key
            if not connected and target.get('key_path') and os.path.exists(target['key_path']):
                if private_key_path != target['key_path']:
                    try:
                        client.connect(ip, port=target['port'], username=target['user'], key_filename=target['key_path'], timeout=5)
                        connected = True
                    except Exception: pass
            
            # 3. Password
            if not connected and target.get('password'):
                try:
                    client.connect(ip, port=target['port'], username=target['user'], password=target['password'], timeout=5)
                    connected = True
                except Exception: pass

            # 4. Key Directory Fallback
            if not connected:
                keys = self.get_available_keys()
                def sort_key(k_path):
                    k_name = os.path.basename(k_path)
                    if ip in k_name: return 0
                    return 1
                keys.sort(key=sort_key)
                
                for key in keys:
                    try:
                        client.connect(ip, port=target['port'], username=target['user'], key_filename=key, timeout=2)
                        target['key_path'] = key
                        connected = True
                        break
                    except: continue
            
            if connected:
                self.sessions[session_key] = client
                target['status'] = 'connected'
                self.notify_target_update(target)
                self.save_targets()
                return True, "Connected successfully"
            
            return False, "Authentication failed"

        except Exception as e:
            target['status'] = 'error'
            self.notify_target_update(target)
            return False, str(e)

    def disconnect(self, ip, port):
        ip = ip.strip()
        port = int(port)
        target = next((t for t in self.targets if t['ip'] == ip and t['port'] == port), None)
        session_key = f"{ip}:{port}"
        
        if session_key in self.sessions:
            try: self.sessions[session_key].close()
            except: pass
            del self.sessions[session_key]
        
        if target:
            target['status'] = 'disconnected'
            self.notify_target_update(target)
            
        return True, "Disconnected"

    def execute(self, ip, port, cmd):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
        
        with self._get_session_lock(session_key):
            if session_key not in self.sessions:
                return "Not connected"
            try:
                transport = self.sessions[session_key].get_transport()
                if not transport or not transport.is_active():
                    self.connect(ip, port)
                
                # Double check after potential reconnect
                if session_key not in self.sessions:
                     return "Not connected"

                stdin, stdout, stderr = self.sessions[session_key].exec_command(cmd, timeout=10)
                return stdout.read().decode() + stderr.read().decode()
            except Exception as e:
                return f"Error: {str(e)}"

    def execute_with_cwd(self, ip, port, cmd):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
        cwd = self.console_cwd.get(session_key, '~')
        
        # Robust path handling: quote path, but keep ~ as is
        if cwd == '~':
            cd_cmd = 'cd'
        else:
            cd_cmd = f"cd {shlex.quote(cwd)}"
            
        full_cmd = f"({cd_cmd} 2>/dev/null; {cmd}; echo '___CWD___'; pwd) 2>&1"
        
        raw_output = self.execute(ip, port, full_cmd)

        if raw_output and '___CWD___' in raw_output:
            parts = raw_output.rsplit('___CWD___', 1)
            output = parts[0].rstrip('\n')
            new_cwd = parts[1].strip()
            if new_cwd:
                self.console_cwd[session_key] = new_cwd
            else:
                 # If pwd returns empty (unlikely), keep old
                 pass
            return output, new_cwd
        return raw_output, cwd

    def upload(self, ip, port, local_path, remote_path):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
        
        with self._get_session_lock(session_key):
            try:
                # Check connection and reconnect if needed
                if session_key not in self.sessions:
                    connected, msg = self.connect(ip, port)
                    if not connected: return False, f"Reconnect failed: {msg}"

                transport = self.sessions[session_key].get_transport()
                if not transport or not transport.is_active():
                    connected, msg = self.connect(ip, port)
                    if not connected: return False, f"Reconnect failed: {msg}"
            
                sftp = self.sessions[session_key].open_sftp()
                try:
                    target_path = remote_path
                    is_directory = False
                    
                    if target_path.endswith('/'):
                        is_directory = True
                    else:
                        try:
                            attr = sftp.stat(target_path)
                            if stat.S_ISDIR(attr.st_mode):
                                is_directory = True
                        except: pass
                    
                    if is_directory:
                        filename = os.path.basename(local_path)
                        if not target_path.endswith('/'):
                            target_path += '/'
                        target_path += filename
                        
                    sftp.put(local_path, target_path)
                finally:
                    sftp.close()
                
                # Verify (using execute, which handles its own locking, but we are holding the lock! 
                # SSHClient.exec_command is thread-safe on different channels, but since we are holding the lock, 
                # we need execute to NOT deadlock if we called it from here.
                # WAIT. execute uses 'with self._get_session_lock(session_key)'.
                # RLock would solve this, but we used Lock.
                # FIX: Change _get_session_lock to return RLock or duplicate code. 
                # Or simply don't call execute inside the lock?
                # Calling execute inside the lock is safer for serialization.
                # So I MUST change Lock to RLock in _get_session_lock.
                
                verify_cmd = f"ls -la {target_path}"
                # We can't call self.execute because it will try to acquire the same lock.
                # So we must use RLock.
                
                # Temporarily, proceed with this replacement, and I will update _get_session_lock to use RLock in the next step.
                
                stdin, stdout, stderr = self.sessions[session_key].exec_command(verify_cmd, timeout=10)
                check = stdout.read().decode()
                
                if check and "No such file" not in check:
                     return True, f"Success: {target_path}"
                else:
                     return False, f"Upload verification failed"
            except Exception as e:
                print(f"Upload error: {e}")
                return False, str(e)

    def download(self, ip, port, remote_path, local_path):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
        
        with self._get_session_lock(session_key):
            if session_key not in self.sessions: return False, "Not connected"
            try:
                sftp = self.sessions[session_key].open_sftp()
                try:
                    sftp.get(remote_path, local_path)
                finally:
                    sftp.close()
                return True, f"Downloaded: {local_path}"
            except Exception as e:
                return False, str(e)

    def list_remote_dir(self, ip, port, path):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
        
        with self._get_session_lock(session_key):
            if session_key not in self.sessions: return {'error': 'Not connected'}
            try:
                sftp = self.sessions[session_key].open_sftp()
                try:
                    files = []
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
                finally: sftp.close()
            except Exception as e: return {'error': str(e)}

    def read_remote_file(self, ip, port, path):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
        
        with self._get_session_lock(session_key):
            if session_key not in self.sessions: return {'error': 'Not connected'}
            try:
                sftp = self.sessions[session_key].open_sftp()
                try:
                    with sftp.open(path, 'r') as f:
                        content = f.read()
                        try: return {'content': content.decode('utf-8')}
                        except UnicodeDecodeError: return {'content': '[Binary file]'}
                finally: sftp.close()
            except Exception as e: return {'error': str(e)}

    def write_remote_file(self, ip, port, path, content):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
        
        with self._get_session_lock(session_key):
            if session_key not in self.sessions: return {'error': 'Not connected'}
            try:
                sftp = self.sessions[session_key].open_sftp()
                try:
                    with sftp.open(path, 'w') as f:
                        f.write(content)
                    return {'success': True, 'message': 'Saved successfully'}
                finally: sftp.close()
            except Exception as e: return {'error': str(e)}

    def delete_remote_file(self, ip, port, path):
        # execute handles locking, but for consistency we can lock here too if needed.
        # Actually, execute handles it. But let's follow pattern or just rely on execute.
        # Since execute uses _get_session_lock, it's safe.
        self.execute(ip, port, f"rm -rf '{path}'")
        return {'success': True, 'message': 'Deleted'}

    def connect_all(self):
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
        for th in threads: th.join(timeout=15)
        return results

    def disconnect_all(self):
        results = []
        for t in self.targets:
            if t['status'] == 'connected':
                success, msg = self.disconnect(t['ip'], t['port'])
                results.append({'ip': t['ip'], 'port': t['port'], 'message': msg})
        return results

    def batch_execute(self, cmd):
        results = {}
        threads = []
        results_lock = threading.Lock()
        def _exec_one(ip, port):
            output = self.execute(ip, port, cmd)
            with results_lock: results[f"{ip}:{port}"] = output
        for t in self.targets:
            if t['status'] == 'connected':
                th = threading.Thread(target=_exec_one, args=(t['ip'], t['port']))
                threads.append(th)
                th.start()
        for th in threads: th.join(timeout=15)
        return results

    def check_connections(self):
        results = []
        for t in self.targets:
            if t['status'] != 'connected': continue
            ip, port = t['ip'], t['port']
            session_key = f"{ip}:{port}"
            alive = False
            if session_key in self.sessions:
                try:
                    transport = self.sessions[session_key].get_transport()
                    if transport and transport.is_active():
                        transport.send_ignore()
                        alive = True
                except: alive = False
            if not alive:
                t['status'] = 'disconnected'
                if session_key in self.sessions:
                    try: self.sessions[session_key].close()
                    except: pass
                    del self.sessions[session_key]
            results.append({'ip': ip, 'port': port, 'alive': alive})
        self.save_targets()
        return results
