import socket
import threading
import json
import time
import os

class MonitorService:
    def __init__(self, connection_manager, target_manager, host='0.0.0.0', port=8024):
        self.cm = connection_manager
        self.tm = target_manager
        self.host = host
        self.port = port
        self.running = False
        self.socket = None
        self.thread = None
        self.logs = [] # In-memory log storage
        
    def start(self):
        if self.running: return
        self.running = True
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.thread = threading.Thread(target=self._accept_loop, daemon=True)
            self.thread.start()
            print(f"[MonitorService] Listening on {self.host}:{self.port}")
        except Exception as e:
            print(f"[MonitorService] Failed to start: {e}")
            self.running = False

    def stop(self):
        self.running = False
        if self.socket:
            try: self.socket.close()
            except: pass

    def _accept_loop(self):
        while self.running:
            try:
                conn, addr = self.socket.accept()
                threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
            except:
                if self.running: print("[MonitorService] Accept error")
                break

    def _handle_client(self, conn, addr):
        ip = addr[0]
        buffer = b""
        try:
            conn.settimeout(5)
            while True:
                chunk = conn.recv(4096)
                if not chunk: break
                buffer += chunk
                
                # Handle standard newline delimited JSON
                if b'\n' in buffer:
                    lines = buffer.split(b'\n')
                    # Process all complete lines
                    for line in lines[:-1]: 
                        self._process_log(ip, line)
                    # Keep incomplete remainder
                    buffer = lines[-1]
                    
        except Exception as e:
            pass
        finally:
            conn.close()

    def set_socketio(self, socketio):
        self.socketio = socketio

    def _save_alert(self, alert_data):
        """Persist alert to JSON file"""
        alerts_file = os.path.join('data', 'monitor_alerts.json')
        try:
            existing = []
            if os.path.exists(alerts_file):
                with open(alerts_file, 'r') as f:
                    existing = json.load(f)
            
            existing.append(alert_data)
            # Limit history
            if len(existing) > 1000: existing = existing[-1000:]
            
            with open(alerts_file, 'w') as f:
                json.dump(existing, f, indent=2)
        except Exception as e:
            print(f"Alert save error: {e}")

    def _check_rules(self, log_type, data):
        """Return (is_alert, message)"""
        is_alert = False
        msg = ""
        
        if log_type == 'file':
            path = data.get('path', '')
            event = data.get('event', '')
            
            # Rule 1: PHP/Py/Pl files created/modified in webroot
            if any(path.endswith(ext) for ext in ['.php', '.py', '.pl', '.sh']):
                is_alert = True
                msg = f"Suspicious Script {event}: {path}"
            
            # Rule 2: Hidden files
            if '/.' in path and not path.endswith('.swp'):
                is_alert = True
                msg = f"Hidden File {event}: {path}"

        elif log_type == 'process':
            cmd = data.get('cmd', '')
            
            # Rule 3: Reverse Shell Tools
            suspicious = ['nc ', 'netcat', 'bash -i', 'zsh -i', 'curl ', 'wget ', 'lynx ']
            if any(s in cmd for s in suspicious):
                is_alert = True
                msg = f"Suspicious Command: {cmd}"
                
        return is_alert, msg

    def _process_log(self, ip, data_bytes):
        try:
            line = data_bytes.decode(errors='ignore').strip()
            if not line: return
            
            payload = json.loads(line)
            log_type = payload.get('type')
            data = payload.get('data', {})
            
            # Timestamp
            timestamp = time.strftime('%H:%M:%S')
            
            log_entry = {
                'ip': ip,
                'time': timestamp,
                'type': log_type,
                'details': data
            }
            
            self.logs.append(log_entry)
            if len(self.logs) > 1000: self.logs.pop(0)
            
            # --- Rules & Alerting ---
            is_alert, alert_msg = self._check_rules(log_type, data)
            
            if is_alert:
                log_entry['alert'] = True
                log_entry['message'] = alert_msg
                print(f"[{ip}] 🚨 MONITOR ALERT: {alert_msg}")
                
                # Persist
                self._save_alert(log_entry)
                
                # WebSocket Push
                if hasattr(self, 'socketio') and self.socketio:
                    self.socketio.emit('monitor_alert', log_entry)
            
            # Emit raw log for live feed (optional, maybe too noisy?)
            # Let's emit it anyway for "Live Monitor" tab
            if hasattr(self, 'socketio') and self.socketio:
                self.socketio.emit('monitor_log', log_entry)

        except Exception as e:
            print(f"Log parsing error: {e}")

    def deploy_agent(self, ip, port):
        """Deploy PyGuard Agent (Prefer Python3, Fallback to Bash)"""
        
        # 1. Check Python3 Availability
        check_py = self.cm.execute(ip, int(port), "which python3")
        if not check_py or "no python3" in check_py.lower():
            # Fallback to Shell
            self.deploy_sh_agent(ip, port)
            return

        local_py = os.path.join('tools', 'py_guard.py')
        if not os.path.exists(local_py):
            print("Error: py_guard.py not found")
            return

        remote_path = '/tmp/py_guard.py'
        
        # 1. Upload
        print(f"[{ip}:{port}] Deploying PyGuard...", flush=True)
        self.cm.upload(ip, int(port), local_py, remote_path)
        
        # 2. Kill old instances
        self.cm.execute(ip, int(port), "pkill -f py_guard.py")
        
        # 3. Start Agent (Background)
        # Determine Local IP (Controller IP)
        # For now, let's assume the user configures it or we guess it.
        # Ideally, use connection manager to sniff, but here we'll use a config or interactive input.
        # Fallback to connection manager's knowledge or '172.16.x.1' convention?
        # A simpler way is to let the user or config specify the callback IP.
        # We will use the IP that the ConnectionManager uses to connect (not perfect but okay).
        
        # HACK: using a hardcoded callback IP or Config for now.
        # In real AWD, you know your IP. 
        # Let's try to get it from TargetManager if stored, else default.
        # Get Local IP
        callback_ip = self.tm.get_local_ip()
        if not callback_ip:
            print(f"[{ip}:{port}] Monitor Deploy Skipped: Local IP not set.", flush=True)
            return 
            
        cmd = f"nohup python3 {remote_path} {callback_ip} {self.port} >/dev/null 2>&1 &"
        self.cm.execute(ip, int(port), cmd)
        
    def deploy_sh_agent(self, ip, port):
        """Deploy Bash-based Agent (Fallback)"""
        local_sh = os.path.join('tools', 'sh_guard.sh')
        if not os.path.exists(local_sh): return

        remote_path = '/tmp/sh_guard.sh'
        callback_ip = self.tm.get_local_ip()
        if not callback_ip:
            print(f"[{ip}:{port}] ShellGuard Deploy Skipped: Local IP not set.", flush=True)
            return 

        print(f"[{ip}:{port}] Deploying Shell Guard (No Python detected)...", flush=True)
        self.cm.upload(ip, int(port), local_sh, remote_path)
        self.cm.execute(ip, int(port), f"chmod +x {remote_path}")
        self.cm.execute(ip, int(port), "pkill -f sh_guard.sh")
        
        cmd = f"nohup {remote_path} {callback_ip} {self.port} >/dev/null 2>&1 &"
        self.cm.execute(ip, int(port), cmd)
        print(f"[{ip}:{port}] Shell Guard started.", flush=True)
