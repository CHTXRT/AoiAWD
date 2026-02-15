import threading
import time
import os
import shlex

class ImmortalShellKiller:
    def __init__(self, connection_manager, target_manager, socketio=None):
        print(f"ImmortalShellKiller Initialized. ID={id(self)}", flush=True)
        self.cm = connection_manager
        self.tm = target_manager
        self.socketio = socketio
        self.monitors = {} # "ip:port" -> threading.Event (stop_event)
        self.lock = threading.Lock()

    def set_socketio(self, socketio):
        self.socketio = socketio
        print(f"Immortal Shell Killer (ID={id(self)}): SocketIO set to {socketio}", flush=True)

    def start_monitoring(self, ip, port):
        key = f"{ip}:{port}"
        with self.lock:
            if key in self.monitors:
                print(f"[{key}] Immortal Killer already running.")
                return
            
            stop_event = threading.Event()
            self.monitors[key] = stop_event
            
            t = threading.Thread(target=self._monitoring_loop, args=(ip, port, stop_event), daemon=True)
            t.start()
            print(f"[{key}] Immortal Killer started. (InstanceID={id(self)})", flush=True)

    def stop_monitoring(self, ip, port):
        key = f"{ip}:{port}"
        with self.lock:
            if key in self.monitors:
                self.monitors[key].set()
                del self.monitors[key]
                print(f"[{key}] Immortal Killer stopped.")

    def _monitoring_loop(self, ip, port, stop_event):
        while not stop_event.is_set():
            try:
                self._scan_and_kill(ip, port)
            except Exception as e:
                print(f"[{ip}:{port}] Immortal Killer Error: {e}", flush=True)
            
            # Sleep 20s
            if stop_event.wait(20):
                break

    def _scan_and_kill(self, ip, port):
        # 1. Find newly modified PHP files (last 5 mins)
        cmd_find = "find /var/www/html -type f -name '*.php' -mmin -5 2>/dev/null"
        files_out = self.cm.execute(ip, port, cmd_find)
        
        if not files_out: return

        files = [f.strip() for f in files_out.split('\n') if f.strip().endswith('.php')]
        
        for file_path in files:
            # EXCLUSION: TapeWorm and other AOI tools
            filename = os.path.basename(file_path)
            if filename.startswith('TapeWorm') or filename.startswith('.tapeworm'):
                continue

            if self._check_features(ip, port, file_path):
                self._remediate(ip, port, file_path)

    def _check_features(self, ip, port, file_path):
        # Read file content
        content = self.cm.read_remote_file(ip, port, file_path).get('content', '')
        if not content: return False
        
        # Rule A: Strong Feature (ignore_user_abort + set_time_limit)
        if 'ignore_user_abort' in content and 'set_time_limit' in content:
            return True
            
        # Rule B: Behavioral (sleep/usleep + write)
        has_sleep = 'sleep' in content or 'usleep' in content
        has_write = 'file_put_contents' in content or 'fwrite' in content
        if has_sleep and has_write:
            return True

        # Rule C: Generic Webshell Keywords (for recently modified files)
        # If a file is constantly modified and contains eval/assert, it's likely a target of an immortal shell or is one itself.
        suspicious_keywords = [
            'eval(', 'assert(', 'system(', 'shell_exec(', 'passthru(', 'pcntl_exec(', 'popen(', 'proc_open('
        ]
        if any(keyword in content for keyword in suspicious_keywords):
            return True
            
        return False

    def _remediate(self, ip, port, file_path):
        print(f"[{ip}:{port}] 🚨 Immortal Shell Detected: {file_path}", flush=True)
        
        remediation_log = []
        
        # 1. Kill Process
        # Try lsof first
        pids = self.cm.execute(ip, port, f"lsof -t {file_path}")
        if not pids: 
             # Fallback to fuser
             pids = self.cm.execute(ip, port, f"fuser {file_path} 2>/dev/null")
        
        if pids:
            for pid in pids.split():
                if pid.strip().isdigit():
                    self.cm.execute(ip, port, f"kill -9 {pid.strip()}")
                    remediation_log.append(f"Killed PID {pid.strip()}")
        else:
            remediation_log.append("No active process found")

        # 2. Restore / Delete
        # Check /tmp/html_bak first
        # Construct the path in /tmp/html_bak corresponding to /var/www/html/...
        # file_path is /var/www/html/subdir/shell.php
        # rel_path is subdir/shell.php
        rel_path = os.path.relpath(file_path, '/var/www/html').replace('\\', '/')
        if rel_path.startswith('/'): rel_path = rel_path[1:] # Should not happen with relpath but safe check
        
        backup_candidate = f"/tmp/html_bak/{rel_path}"
        
        print(f"[{ip}:{port}] Checking remote backup: {backup_candidate}", flush=True)
        
        check_backup = self.cm.execute(ip, port, f"test -f {backup_candidate} && echo EXISTS")
        
        if check_backup and "EXISTS" in check_backup:
            # Check if backup file is also infected
            backup_content = self.cm.read_remote_file(ip, port, backup_candidate).get('content', '')
            is_clean = True
            
            # Use same checks (generic keywords) to validate backup
            suspicious_keywords = ['eval(', 'assert(', 'system(', 'shell_exec(', 'passthru(', 'pcntl_exec(', 'popen(', 'proc_open(', 'ignore_user_abort', 'set_time_limit']
            if any(k in backup_content for k in suspicious_keywords):
                print(f"[{ip}:{port}] Backup is also infected! Deleting backup and target.", flush=True)
                is_clean = False
                self.cm.execute(ip, port, f"rm -f {backup_candidate}")

            if is_clean:
                self.cm.execute(ip, port, f"cp {backup_candidate} {file_path}")
                remediation_log.append("Restored from /tmp/html_bak")
            else:
                self.cm.execute(ip, port, f"rm -rf {file_path} && mkdir {file_path}")
                remediation_log.append("Deleted (Backup Infected) & Placeheld")
        else:
            # No backup, delete and placeholder
            self.cm.execute(ip, port, f"rm -rf {file_path} && mkdir {file_path}")
            remediation_log.append("Deleted & Placeheld (mkdir)")

        # 3. Lock
        self.cm.execute(ip, port, f"chattr +i {file_path} 2>/dev/null")
        remediation_log.append("Locked (chattr +i)")

        print(f"[{ip}:{port}] Remediation complete. Log: {remediation_log}", flush=True)
        # 4. Alert
        self._send_alert(ip, port, file_path, ", ".join(remediation_log))

    def _send_alert(self, ip, port, file_path, action):
        if not self.socketio: 
            print(f"[{ip}:{port}] SocketIO not initialized in ImmortalShellKiller (ID={id(self)})!", flush=True)
            return
        
        target = self.tm.get_target(ip, port)
        target_name = target.get('name', '') if target else ''
        
        # Time
        timestamp = time.strftime('%H:%M:%S')
        
        data = {
            'ip': ip,
            'port': port,
            'target_name': target_name,
            'file': file_path,
            'time': timestamp,
            'action': action,
            'type': 'immortal_shell'
        }
        print(f"[{ip}:{port}] Sending Alert via SocketIO: {data}", flush=True)
        try:
            self.socketio.emit('immortal_alert', data)
            print(f"[{ip}:{port}] SocketIO Emit Success", flush=True)
        except Exception as e:
            print(f"[{ip}:{port}] SocketIO Emit Error: {e}", flush=True)
