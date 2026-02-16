import threading
import time
import os
import shlex
import json
import hashlib
import tempfile
import tarfile

class ImmortalShellKiller:
    def __init__(self, connection_manager, target_manager, socketio=None):
        print(f"ImmortalShellKiller Initialized. ID={id(self)}", flush=True)
        self.cm = connection_manager
        self.tm = target_manager
        self.socketio = socketio
        self.monitors = {} # "ip:port" -> threading.Event (stop_event)
        self.lock = threading.Lock()
        
        # Load alerts
        import app.config
        self.log_file = app.config.Config.IMMORTAL_LOG_FILE
        self.alerts = self._load_alerts()
        
        # Persistent Killers State
        self.killers_file = 'data/active_killers.json'
        self.active_killers = {} # "ip:port:file_path" -> script_path
        self._load_active_killers()
        
        # Concurrency Control
        self.processing_files = set()
        self.processing_lock = threading.Lock()

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

    def is_monitoring(self, ip, port):
        """Check if monitoring is active for the given target."""
        key = f"{ip}:{port}"
        with self.lock:
            return key in self.monitors

    def _monitoring_loop(self, ip, port, stop_event):
        while not stop_event.is_set():
            try:
                self._scan_and_kill(ip, port)
            except Exception as e:
                print(f"[{ip}:{port}] Immortal Killer Error: {e}", flush=True)
            
            # Sleep 0.5s (Reduced from 1s for faster response)
            if stop_event.wait(0.5):
                break

    def _scan_and_kill(self, ip, port):
        # Check Maintenance Mode
        target = self.tm.get_target(ip, port)
        if target and target.get('maintenance_mode'):
            # print(f"[{ip}:{port}] Skipping Immortal Check (Maintenance Mode)", flush=True)
            return

        # 1. OPTIMIZED: Combine Find + Grep (Pre-filter on server side)
        # Scan for modified files AND suspicious content in one go.
        # This drastically reduces SSH round-trips (RTT) by avoiding 'cat' on innocent files.
        regex_pattern = r"eval\(|assert\(|system\(|shell_exec\(|passthru\(|pcntl_exec\(|popen\(|proc_open\(|ignore_user_abort|set_time_limit"
        
        # Using xargs grep -l to output only filenames
        # Exclude .quarantine explicitly
        cmd_find_grep = f"find /var/www/html -type f -name '*.php' -not -path '*/.quarantine/*' -mmin -5 -print0 2>/dev/null | xargs -0 grep -lE '{regex_pattern}'"
        
        files_out = self.cm.execute(ip, port, cmd_find_grep)
        
        if not files_out: return

        files = [f.strip() for f in files_out.split('\n') if f.strip().endswith('.php')]
        
        for file_path in files:
            # EXCLUSION: TapeWorm and other AOI tools
            filename = os.path.basename(file_path)
            if filename.startswith('TapeWorm') or filename.startswith('.tapeworm'):
                continue
            
            # EXCLUSION: Whitelist
            if target and 'whitelist' in target and file_path in target['whitelist']:
                print(f"[{ip}:{port}] Ignoring whitelisted file: {file_path}", flush=True)
                continue

            # Threaded Remediation
            key = f"{ip}:{port}:{file_path}"
            with self.processing_lock:
                if key in self.processing_files:
                    continue
                self.processing_files.add(key)
            
            threading.Thread(target=self._remediate_wrapper, args=(ip, port, file_path), daemon=True).start()

    def _remediate_wrapper(self, ip, port, file_path):
        try:
            self._remediate(ip, port, file_path)
        except Exception as e:
            print(f"[{ip}:{port}] Remediation Error ({file_path}): {e}", flush=True)
        finally:
            key = f"{ip}:{port}:{file_path}"
            with self.processing_lock:
                self.processing_files.discard(key)
        # ... (This method is kept but less used now due to pre-filter) ...
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
        suspicious_keywords = [
            'eval(', 'assert(', 'system(', 'shell_exec(', 'passthru(', 'pcntl_exec(', 'popen(', 'proc_open('
        ]
        if any(keyword in content for keyword in suspicious_keywords):
            return True
            
        return False

        return False

    def _is_safe_in_backup(self, ip, port, file_path):
        """Check if the file exists in backup and has same content (MD5)"""
        target = self.tm.get_target(ip, port)
        if not target or not target.get('backup_path'): return False
        
        backup_path = target['backup_path']
        if not os.path.exists(backup_path): return False
        
        try:
            # 1. Get Remote MD5
            remote_md5_out = self.cm.execute(ip, port, f"md5sum {file_path}")
            if not remote_md5_out or ' ' not in remote_md5_out: return False
            remote_md5 = remote_md5_out.split()[0].strip()
            
            # 2. Get Backup MD5
            # Extract from tar to stream/temp to calculate MD5
            rel_path = file_path.lstrip('/')
            with tarfile.open(backup_path, 'r') as tar:
                try:
                    member = tar.getmember(rel_path)
                    f_obj = tar.extractfile(member)
                    if f_obj:
                        backup_md5 = hashlib.md5(f_obj.read()).hexdigest()
                        if remote_md5 == backup_md5:
                            return True
                except KeyError:
                    pass # File not in backup
        except Exception as e:
            # print(f"Backup check error: {e}")
            pass
            
        return False

    def _remediate(self, ip, port, file_path):
        # 0. Safety Check: If file is identical to backup, IT IS SAFE.
        # This prevents locking legitimate files like Smarty/Composer that contain eval/popen.
        if self._is_safe_in_backup(ip, port, file_path):
            print(f"[{ip}:{port}] Skipping {file_path} (Matches Backup - False Positive)", flush=True)
            return

        print(f"[{ip}:{port}] 🚨 Immortal Shell Detected (Optimized): {file_path}", flush=True)
        
        remediation_log = []
        quarantine_path = None
        
        # 1. Kill Process
        pids = self.cm.execute(ip, port, f"lsof -t {file_path}")
        if not pids: 
             pids = self.cm.execute(ip, port, f"fuser {file_path} 2>/dev/null")
        
        if pids:
            for pid in pids.split():
                if pid.strip().isdigit():
                    self.cm.execute(ip, port, f"kill -9 {pid.strip()}")
                    remediation_log.append(f"Killed PID {pid.strip()}")

        # 2. Quarantine
        try:
            timestamp = int(time.time())
            filename = os.path.basename(file_path)
            quarantine_dir = "/tmp/.quarantine"
            quarantine_file = f"{quarantine_dir}/{filename}_{timestamp}"
            
            self.cm.execute(ip, port, f"mkdir -p {quarantine_dir}")
            self.cm.execute(ip, port, f"cp {file_path} {quarantine_file}")
            quarantine_path = quarantine_file
            remediation_log.append(f"Quarantined")
        except: pass

        # 3. Restore from LOCAL BACKUP (Optimized)
        target = self.tm.get_target(ip, port)
        backup_path = target.get('backup_path')
        
        restored = False
        if backup_path and os.path.exists(backup_path) and backup_path.endswith('.tar'):
            try:
                # E.g. /var/www/html/shell.php -> var/www/html/shell.php (tar usually strips /)
                rel_path_in_tar = file_path.lstrip('/')
                
                with tarfile.open(backup_path, 'r') as tar:
                    try:
                        member = tar.getmember(rel_path_in_tar)
                        # File found in backup! Extract it.
                        f_obj = tar.extractfile(member)
                        if f_obj:
                            # Create local temp
                            tmp_restore = os.path.join(tempfile.gettempdir(), f"restore_{filename}_{timestamp}")
                            with open(tmp_restore, 'wb') as f_dst:
                                f_dst.write(f_obj.read())
                            
                            # Upload to target
                            self.cm.upload(ip, port, tmp_restore, file_path)
                            os.remove(tmp_restore)
                            
                            restored = True
                            remediation_log.append("Restored from Local Backup")
                            print(f"[{ip}:{port}] Successfully restored {file_path} from local backup.", flush=True)
                    except KeyError:
                        # File not in backup (meaning it's a new malicious file)
                        # print(f"[{ip}:{port}] File {file_path} not found in backup (New File).", flush=True)
                        pass
            except Exception as e:
                print(f"[{ip}:{port}] Local Restore Error: {e}", flush=True)

        # 4. If not restored (New File or Restore Failed) -> Delete & Placeholder
        if not restored:
            # Force Delete & Mkdir Placeholder
            self.cm.execute(ip, port, f"rm -rf {file_path} && mkdir -p {file_path}")
            remediation_log.append("Deleted & Placeheld")

        # 5. Lock
        self.cm.execute(ip, port, f"chattr +i {file_path} 2>/dev/null")
        remediation_log.append("Locked")

        # 6. Alert
        self._send_alert(ip, port, file_path, ", ".join(remediation_log), quarantine_path)

    def _send_alert(self, ip, port, file_path, action, quarantine_path=None):
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
            'quarantine_path': quarantine_path,
            'type': 'immortal_shell'
        }
        
        # Persist alert
        with self.lock:
            self.alerts.append(data)
            self._save_alerts()
            
        print(f"[{ip}:{port}] Sending Alert via SocketIO: {data}", flush=True)
        
        if self.socketio: 
            try:
                self.socketio.emit('immortal_alert', data)
                print(f"[{ip}:{port}] SocketIO Emit Success", flush=True)
            except Exception as e:
                print(f"[{ip}:{port}] SocketIO Emit Error: {e}", flush=True)
        else:
            print(f"[{ip}:{port}] SocketIO not initialized in ImmortalShellKiller (ID={id(self)})!", flush=True)

    def restore_from_quarantine(self, ip, port, file_path, quarantine_path):
        print(f"[{ip}:{port}] Restoring {file_path} from {quarantine_path}...", flush=True)
        try:
            # 1. Unlock
            self.cm.execute(ip, port, f"chattr -i {file_path} 2>/dev/null")
            
            # 2. Check if quarantine file exists
            check = self.cm.execute(ip, port, f"test -f {quarantine_path} && echo EXISTS")
            if not check or "EXISTS" not in check:
                return False, "Quarantine file not found"
            
            # 3. Clean target (it might be a directory placeholder)
            self.cm.execute(ip, port, f"rm -rf {file_path}")
            
            # 4. Restore
            self.cm.execute(ip, port, f"cp {quarantine_path} {file_path}")
            
            # 5. Add to Whitelist
            self.tm.add_whitelist(ip, port, file_path)
            
            return True, "Restored and Whitelisted"
        except Exception as e:
            print(f"Restore error: {e}")
            return False, str(e)

    def _load_alerts(self):
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    return json.load(f)
            except: pass
        return []

    def _save_alerts(self):
        try:
            with open(self.log_file, 'w') as f:
                json.dump(self.alerts, f, indent=4)
        except Exception as e:
            print(f"Error saving alerts: {e}")

    def get_alerts(self):
        with self.lock:
            return list(self.alerts)

    def _load_active_killers(self):
        if os.path.exists(self.killers_file):
            try:
                with open(self.killers_file, 'r', encoding='utf-8') as f:
                    self.active_killers = json.load(f)
            except: self.active_killers = {}
    
    def _save_active_killers(self):
        try:
            with open(self.killers_file, 'w', encoding='utf-8') as f:
                json.dump(self.active_killers, f, ensure_ascii=False, indent=2)
        except: pass

    def start_persistent_kill(self, ip, port, file_path):
        key = f"{ip}:{port}:{file_path}"
        if key in self.active_killers:
             return True, "Already running"

        # Unique Script Name
        file_hash = hashlib.md5(file_path.encode()).hexdigest()[:8]
        script_name = f".wd_kill_{file_hash}.sh"
        remote_script_path = f"/tmp/{script_name}"
        
        # Generate Script Content
        # Using sleep 0.1 for 100ms interval. usleep is not always available.
        # mkdir -p to recreate directory if deleted.
        # chmod 000 to prevent writing.
        # chattr +i is also good but might need root. We assume www-data usually.
        script_content = f"""#!/bin/bash
# WD-Defender Persistent Killer for {file_path}
# ID: {file_hash}

TARGET="{file_path}"

while true; do
    if [ -f "$TARGET" ]; then
        rm -rf "$TARGET"
        # Kill process holding the file
        fuser -k -9 "$TARGET" >/dev/null 2>&1
    fi
    
    if [ ! -d "$TARGET" ]; then
        mkdir -p "$TARGET"
        chmod 000 "$TARGET"
    fi
    
    sleep 0.1
done
"""
        try:
            # Create local temp script
            local_tmp = os.path.join(tempfile.gettempdir(), script_name)
            with open(local_tmp, 'w', encoding='utf-8', newline='\n') as f:
                f.write(script_content)
            
            # Upload
            self.cm.upload(ip, port, local_tmp, remote_script_path)
            os.remove(local_tmp)
            
            # Execute
            self.cm.execute(ip, port, f"chmod +x {remote_script_path}")
            # nohup and background
            cmd = f"nohup {remote_script_path} >/dev/null 2>&1 &"
            self.cm.execute(ip, port, cmd)
            
            # Record state
            self.active_killers[key] = remote_script_path
            self._save_active_killers()
            
            return True, "Persistent killer started"
            
        except Exception as e:
            return False, str(e)

    def stop_persistent_kill(self, ip, port, file_path):
        key = f"{ip}:{port}:{file_path}"
        if key not in self.active_killers:
            return False, "Not running"
            
        script_path = self.active_killers[key]
        script_name = os.path.basename(script_path)
        
        try:
            # Kill process by script name
            # pkill -f script_name
            self.cm.execute(ip, port, f"pkill -f {script_name}")
            
            # Remove script
            self.cm.execute(ip, port, f"rm -rf {script_path}")
            
            # Remove from state
            del self.active_killers[key]
            self._save_active_killers()
            
            return True, "Persistent killer stopped"
        except Exception as e:
            return False, str(e)

    def get_persistent_status(self, ip, port, file_path):
        key = f"{ip}:{port}:{file_path}"
        return key in self.active_killers

    def get_active_killers(self):
        # Convert to list of dicts for frontend
        result = []
        for key, script_path in self.active_killers.items():
            # key = "ip:port:file_path"
            parts = key.split(':')
            if len(parts) >= 3:
                ip = parts[0]
                port = parts[1]
                file_path = parts[2]
                if len(parts) > 3: # Handle file paths with colons
                    file_path = ":".join(parts[2:])
                
                result.append({
                    'ip': ip,
                    'port': port,
                    'file': file_path,
                    'script': script_path,
                    'status': 'Running'
                })
        return result
