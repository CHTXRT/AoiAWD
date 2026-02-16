import os
import json
import threading
import ipaddress
from flask import render_template

class TargetManager:
    def __init__(self):
        self.targets = []
        self.lock = threading.RLock()
        self.socketio = None
        self.app = None
        self.data_dir = None
        self.targets_file = None
        self.local_ip = ''

    def init_app(self, app):
        self.app = app
        self.data_dir = app.config['DATA_DIR']
        self.targets_file = app.config['TARGETS_FILE']
        self.load_targets()
        self._load_local_ip()

    def set_socketio(self, socketio):
        self.socketio = socketio

    def load_targets(self):
        if self.targets_file and os.path.exists(self.targets_file):
            try:
                with open(self.targets_file, 'r') as f:
                    loaded = json.load(f)
                    self.targets = []
                    if isinstance(loaded, list):
                        for t in loaded:
                            if not isinstance(t, dict): continue
                            # Always reset status on load, as connections are not persistent across restarts
                            t['status'] = 'disconnected'
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
                            'status': t.get('status'),
                            'preload_done': t.get('preload_done'),
                            'backup_path': t.get('backup_path'),
                            'detection': t.get('detection'),
                            'wwwdata_shell': t.get('wwwdata_shell'),
                            'wwwdata_strategy': t.get('wwwdata_strategy'),
                            'wwwdata_password': t.get('wwwdata_password'),
                            'aoi_deployed': t.get('aoi_deployed'),
                            'file_snapshot': t.get('file_snapshot'),
                            'snapshot_time': t.get('snapshot_time'),
                            'maintenance_mode': t.get('maintenance_mode'),
                            'backup_done': t.get('backup_done'),
                            'backdoor_scan': t.get('backdoor_scan'),
                            'whitelist': t.get('whitelist', [])
                        })
                    json.dump(targets_to_save, f, indent=4)
            except Exception as e:
                print(f"Error saving targets: {e}")

    def notify_target_update(self, target, action='update'):
        if not self.socketio: return
        t_data = target.copy()
        if 'detection' in t_data and t_data['detection']:
            det = t_data['detection'].copy()
            if 'types' in det and isinstance(det['types'], set):
                det['types'] = list(det['types'])
            t_data['detection'] = det
        
        # Security: Remove passwords from frontend payload
        if 'password' in t_data: del t_data['password']
        if 'wwwdata_password' in t_data: del t_data['wwwdata_password']
        
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

    def get_target(self, ip, port):
        return next((t for t in self.targets if t['ip'] == ip and t['port'] == int(port)), None)

    def add_target(self, ip_input, port=22, user='root', password=None, key_path=None, name=None):
        if not ip_input: return
        ips = self.parse_ip_range(ip_input)
        port = int(port)
        
        with self.lock:
            for ip in ips:
                if not self.get_target(ip, port):
                    self.targets.append({
                        'ip': ip,
                        'port': port,
                        'name': name,
                        'user': user,
                        'password': password,
                        'key_path': key_path,
                        'status': 'disconnected'
                    })
                    self.notify_target_update(self.targets[-1], action='add')
            self.save_targets()

    def remove_target(self, ip, port):
        if not ip: return False
        ip = ip.strip()
        port = int(port)
        with self.lock:
            # Note: Connection closing should be handled by ConnectionManager before calling this,
            # or we need a way to signal disconnect. 
            # Ideally, the Facade handles: conn_mgr.disconnect() -> target_mgr.remove()
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
            target = self.get_target(ip, port)
            if not target: return False, "Target not found"
            target['password'] = password
            self.save_targets()
            return True, "Password updated"

    def update_single_snapshot(self, ip, port, file_path, md5_hash):
        """Update snapshot for a single file (e.g. after whitelisting)"""
        target = self.get_target(ip, port)
        if not target: return
        
        with self.lock:
            if 'file_snapshot' not in target: target['file_snapshot'] = {}
            target['file_snapshot'][file_path] = md5_hash
            self.save_targets()

    def add_whitelist(self, ip, port, file_path):
        target = self.get_target(ip, port)
        if not target: return False
        
        with self.lock:
            if 'whitelist' not in target: target['whitelist'] = []
            if file_path not in target['whitelist']:
                target['whitelist'].append(file_path)
                self.save_targets()
                self.notify_target_update(target)
        return True

    def remove_whitelist(self, ip, port, file_path):
        target = self.get_target(ip, port)
        if not target: return False
        
        with self.lock:
            if 'whitelist' in target and file_path in target['whitelist']:
                target['whitelist'].remove(file_path)
                self.save_targets()
                self.notify_target_update(target)
        return True

    def toggle_maintenance_mode(self, ip, port, enabled):
        target = self.get_target(ip, port)
        if not target: return False
        
        with self.lock:
            target['maintenance_mode'] = bool(enabled)
            self.save_targets()
            self.notify_target_update(target)
        return True

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

    def _load_local_ip(self):
        if self.data_dir:
            ip_file = os.path.join(self.data_dir, 'local_ip.txt')
            if os.path.exists(ip_file):
                try:
                    with open(ip_file, 'r') as f:
                        self.local_ip = f.read().strip()
                except: pass

    def _save_local_ip(self):
        if self.data_dir:
            ip_file = os.path.join(self.data_dir, 'local_ip.txt')
            with open(ip_file, 'w') as f:
                f.write(self.local_ip)

    def set_local_ip(self, ip):
        self.local_ip = ip.strip()
        self._save_local_ip()
        return True

    def get_local_ip(self):
        return self.local_ip
