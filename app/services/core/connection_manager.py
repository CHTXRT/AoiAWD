import paramiko
import threading
import os
import stat
import shlex

class ConnectionManager:
    def __init__(self, target_manager, key_manager):
        self.tm = target_manager
        self.km = key_manager
        self.sessions = {} # ip:port -> client
        self.session_locks = {}
        self.global_lock = threading.RLock()
        self.console_cwd = {}

    def _get_session_lock(self, session_key):
        if session_key not in self.session_locks:
            with self.global_lock:
                if session_key not in self.session_locks:
                    self.session_locks[session_key] = threading.RLock()
        return self.session_locks[session_key]

    def connect(self, ip, port, private_key_path=None):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
        
        target = self.tm.get_target(ip, port)
        if not target: return False, "Target not found"

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            connected = False
            # 1. Explicit Key
            if private_key_path and os.path.exists(private_key_path):
                try:
                    client.connect(ip, port=port, username=target['user'], key_filename=private_key_path, timeout=5)
                    connected = True
                    target['key_path'] = private_key_path 
                except Exception: pass

            # 2. Saved Key
            if not connected and target.get('key_path') and os.path.exists(target['key_path']):
                if private_key_path != target['key_path']:
                    try:
                        client.connect(ip, port=port, username=target['user'], key_filename=target['key_path'], timeout=5)
                        connected = True
                    except Exception: pass
            
            # 3. Password
            if not connected and target.get('password'):
                try:
                    client.connect(ip, port=port, username=target['user'], password=target['password'], timeout=5)
                    connected = True
                except Exception: pass

            # 4. Fallback Keys
            if not connected:
                keys = self.km.get_available_keys()
                def sort_key(k_path):
                    k_name = os.path.basename(k_path)
                    if ip in k_name: return 0
                    return 1
                keys.sort(key=sort_key)
                
                for key in keys:
                    try:
                        client.connect(ip, port=port, username=target['user'], key_filename=key, timeout=2)
                        target['key_path'] = key
                        connected = True
                        break
                    except: continue
            
            if connected:
                self.sessions[session_key] = client
                target['status'] = 'connected'
                self.tm.notify_target_update(target)
                self.tm.save_targets()
                return True, "Connected successfully"
            
            return False, "Authentication failed"

        except Exception as e:
            target['status'] = 'error'
            self.tm.notify_target_update(target)
            return False, str(e)

    def disconnect(self, ip, port):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
        
        if session_key in self.sessions:
            try: self.sessions[session_key].close()
            except: pass
            del self.sessions[session_key]
        
        target = self.tm.get_target(ip, port)
        if target:
            target['status'] = 'disconnected'
            self.tm.notify_target_update(target)
            
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
            return output, new_cwd
        return raw_output, cwd

    def upload(self, ip, port, local_path, remote_path):
        ip = ip.strip()
        port = int(port)
        session_key = f"{ip}:{port}"
        
        with self._get_session_lock(session_key):
            try:
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
                
                # Verification using exec_command directly to reuse the lock context if needed,
                # but paramiko exec_command is thread safe on channel level. 
                # Since we are holding _get_session_lock(session_key), calling self.execute would deadlock 
                # because self.execute also re-acquires _get_session_lock.
                # SO I MUST USE RLock in _get_session_lock. (Which I did: threading.RLock)
                
                verify_cmd = f"ls -la {target_path}"
                check = self.execute(ip, port, verify_cmd)
                
                if check and "No such file" not in check and "Error:" not in check:
                     return True, f"Success: {target_path}"
                else:
                     return False, f"Upload verification failed: {check}"
            except Exception as e:
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

        for t in self.tm.targets:
            th = threading.Thread(target=_connect_one, args=(t,))
            threads.append(th)
            th.start()
        for th in threads: th.join(timeout=15)
        return results

    def disconnect_all(self):
        results = []
        for t in self.tm.targets:
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
        for t in self.tm.targets:
            if t['status'] == 'connected':
                th = threading.Thread(target=_exec_one, args=(t['ip'], t['port']))
                threads.append(th)
                th.start()
        for th in threads: th.join(timeout=15)
        return results

    def check_connections(self):
        results = []
        for t in self.tm.targets:
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
        self.tm.save_targets()
        return results
