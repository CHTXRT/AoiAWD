import os
import sys
import time
import json
import socket
import struct
import ctypes
import threading
from ctypes import c_int, c_char_p, POINTER, Structure

# --- Inotify Definitions ---
class InotifyEvent(Structure):
    _fields_ = [
        ("wd", c_int),
        ("mask", c_int),
        ("cookie", c_int),
        ("len", c_int),
        ("name", c_char_p)
    ]

IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_CLOSE_NOWRITE = 0x00000010
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_ISDIR = 0x40000000

EVENT_MASK = IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM

libc = ctypes.CDLL('libc.so.6')

# --- Configuration ---
# --- Networking ---
SERVER_IP = '127.0.0.1' 
SERVER_PORT = 8024
WATCH_DIR = '/var/www/html'
RESOLVED_IP = None

def get_gateway_ip():
    try:
        with open("/proc/net/route") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue
                return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    except:
        return None

def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

def check_connection(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        s.close()
        return True
    except:
        return False

def get_working_server_ip(initial_ip, port):
    candidates = []
    if initial_ip: candidates.append(initial_ip)
    candidates.append('host.docker.internal')
    gateway = get_gateway_ip()
    if gateway: candidates.append(gateway)
    
    # Try resolving and connecting
    for host in candidates:
        ip = resolve_ip(host)
        if ip and check_connection(ip, port):
            return ip
            
    return initial_ip # Fallback to initial

def send_log(log_type, data):
    global RESOLVED_IP
    if not RESOLVED_IP:
        RESOLVED_IP = get_working_server_ip(SERVER_IP, SERVER_PORT)
        
    try:
        msg = json.dumps({'type': log_type, 'data': data})
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((RESOLVED_IP, SERVER_PORT))
        s.sendall(msg.encode() + b'\n')
        s.close()
    except Exception as e:
        # Retry once with re-resolution if failed
        RESOLVED_IP = None
        pass

# --- File Monitor ---
class FileMonitor:
    def __init__(self, watch_dir):
        self.watch_dir = watch_dir
        self.fd = libc.inotify_init()
        self.wd_map = {}

    def add_watch_recursive(self, path):
        try:
            wd = libc.inotify_add_watch(self.fd, path.encode(), EVENT_MASK)
            if wd >= 0:
                self.wd_map[wd] = path
                # print(f"Watching: {path}")
                
            # Add subdirectories
            for root, dirs, files in os.walk(path):
                for d in dirs:
                    full_path = os.path.join(root, d)
                    wd = libc.inotify_add_watch(self.fd, full_path.encode(), EVENT_MASK)
                    if wd >= 0:
                        self.wd_map[wd] = full_path
        except: pass

    def start(self):
        self.add_watch_recursive(self.watch_dir)
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        buf_size = 1024
        buf = ctypes.create_string_buffer(buf_size)
        
        while True:
            n = libc.read(self.fd, buf, buf_size)
            if n <= 0: continue
            
            i = 0
            while i < n:
                event = ctypes.cast(ctypes.byref(buf, i), POINTER(InotifyEvent)).contents
                wd = event.wd
                mask = event.mask
                name_len = event.len
                
                if name_len > 0:
                    name = ctypes.string_at(ctypes.byref(buf, i + 16)).decode()
                    path = self.wd_map.get(wd, "UNKNOWN")
                    full_path = os.path.join(path, name)
                    
                    event_type = []
                    if mask & IN_CREATE: event_type.append("CREATE")
                    if mask & IN_MODIFY: event_type.append("MODIFY")
                    if mask & IN_DELETE: event_type.append("DELETE")
                    if mask & IN_MOVED_TO: event_type.append("MOVED_TO")
                    if mask & IN_MOVED_FROM: event_type.append("MOVED_FROM")
                    
                    if event_type:
                        log_data = {
                            'path': full_path,
                            'event': ",".join(event_type),
                            'time': time.time()
                        }
                        
                        # If file is small, read content
                        if "MODIFY" in event_type or "CREATE" in event_type:
                            try:
                                if os.path.exists(full_path) and os.path.isfile(full_path) and os.path.getsize(full_path) < 4096:
                                    with open(full_path, 'rb') as f:
                                        log_data['content'] = f.read().decode(errors='ignore')
                            except: pass
                            
                        send_log('file', log_data)
                        
                        # If new directory, watch it
                        if (mask & IN_ISDIR) and (mask & IN_CREATE):
                            self.add_watch_recursive(full_path)

                i += 16 + name_len

# --- Process Monitor ---
class ProcessMonitor:
    def __init__(self):
        self.known_pids = set()

    def get_pids(self):
        try:
            return [int(pid) for pid in os.listdir('/proc') if pid.isdigit()]
        except: return []

    def get_process_info(self, pid):
        try:
            with open('/proc/{}/cmdline'.format(pid), 'rb') as f:
                cmdline = f.read().replace(b'\0', b' ').decode(errors='ignore').strip()
            
            with open('/proc/{}/status'.format(pid), 'r') as f:
                uid = "UNKNOWN"
                for line in f:
                    if line.startswith('Uid:'):
                        uid = line.split()[1]
                        break
            return {'pid': pid, 'cmd': cmdline, 'uid': uid}
        except:
            return None

    def start(self):
        # Initial snapshot
        self.known_pids = set(self.get_pids())
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            current_pids = set(self.get_pids())
            new_pids = current_pids - self.known_pids
            
            for pid in new_pids:
                info = self.get_process_info(pid)
                if info and info.get('uid') == '33': # Filter for www-data (UID 33)
                    info['time'] = time.time()
                    send_log('process', info)
            
            self.known_pids = current_pids
            time.sleep(0.5)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        SERVER_IP = sys.argv[1]
    if len(sys.argv) > 2:
        try: SERVER_PORT = int(sys.argv[2])
        except: pass
        
    print("Starting PyGuard Agent... Server Config: {}:{}".format(SERVER_IP, SERVER_PORT))

    # Resolve IP on startup
    RESOLVED_IP = get_working_server_ip(SERVER_IP, SERVER_PORT)
    print("Agent Network: Using Server IP: {}".format(RESOLVED_IP))
    
    # Start Monitors
    fm = FileMonitor(WATCH_DIR)
    fm.start()
    
    pm = ProcessMonitor()
    pm.start()

    # Start Heartbeat
    def heartbeat_loop():
        while True:
            send_log('heartbeat', {'time': time.time()})
            time.sleep(30)
            
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    
    # Keep main thread alive
    while True:
        time.sleep(10)
