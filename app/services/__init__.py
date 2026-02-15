from .core.target_manager import TargetManager
from .core.key_manager import KeyManager
from .core.connection_manager import ConnectionManager

from .security_scanner import SecurityScanner
from .defense_manager import DefenseManager
from .immortal_shell_killer import ImmortalShellKiller
from .attack_manager import AttackManager

import threading

class SSHControllerFacade:
    def __init__(self):
        self.tm = TargetManager()
        self.km = KeyManager()
        self.cm = ConnectionManager(self.tm, self.km)
        
        self.immortal_killer = ImmortalShellKiller(self.cm, self.tm)
        self.scanner = SecurityScanner(self.cm, self.tm)
        self.defense = DefenseManager(self.cm, self.tm, self.scanner, self.immortal_killer)
        self.attack = AttackManager(self.cm, self.tm)
        self.scanner.set_attack_manager(self.attack)

    def init_app(self, app):
        self.tm.init_app(app)
        self.km.init_app(app)
        self.scanner.init_app(app)
        self.defense.init_app(app)
        self.attack.init_app(app)

    @property
    def targets(self): return self.tm.targets

    @property
    def preload_config(self): return self.defense.preload_config

    def set_socketio(self, socketio): 
        self.tm.set_socketio(socketio)
        self.immortal_killer.set_socketio(socketio)

    # --- Target Manager Delegates ---
    def add_target(self, *args, **kwargs): return self.tm.add_target(*args, **kwargs)
    def remove_target(self, *args, **kwargs): 
        # First disconnect
        ip = args[0] if args else kwargs.get('ip')
        port = args[1] if len(args) > 1 else kwargs.get('port')
        if ip and port: self.cm.disconnect(ip, port)
        return self.tm.remove_target(*args, **kwargs)
        
    def get_local_ip(self): return self.tm.get_local_ip()
    def set_local_ip(self, *args, **kwargs): return self.tm.set_local_ip(*args, **kwargs)
    def update_password(self, *args, **kwargs): return self.tm.update_password(*args, **kwargs)
    def _ensure_initialized(self): 
         if not self.tm.targets and self.tm.targets_file:
             self.tm.load_targets()

    # --- Key Manager Delegates ---
    def get_all_keys_info(self, *args, **kwargs): return self.km.get_all_keys_info(self.tm.targets)
    def delete_key(self, *args, **kwargs): return self.km.delete_key(*args, **kwargs)

    # --- Connection Manager Delegates ---
    def connect(self, ip, port, private_key_path=None): 
        result = self.cm.connect(ip, port, private_key_path)
        if result[0]: # connected
            # Trigger detection then preload
            target_args = (ip, port)
            
            def _post_connect_sequence(ip, port):
                self.defense.detect_target_type(ip, port)
                self.defense.run_preload_tasks(ip, port)
                
            threading.Thread(target=_post_connect_sequence, args=target_args).start()
        return result

    def disconnect(self, *args, **kwargs): return self.cm.disconnect(*args, **kwargs)
    def execute(self, *args, **kwargs): return self.cm.execute(*args, **kwargs)
    def execute_with_cwd(self, *args, **kwargs): return self.cm.execute_with_cwd(*args, **kwargs)
    def upload(self, *args, **kwargs): return self.cm.upload(*args, **kwargs)
    def download(self, *args, **kwargs): return self.cm.download(*args, **kwargs)
    def list_remote_dir(self, *args, **kwargs): return self.cm.list_remote_dir(*args, **kwargs)
    def read_remote_file(self, *args, **kwargs): return self.cm.read_remote_file(*args, **kwargs)
    def write_remote_file(self, *args, **kwargs): return self.cm.write_remote_file(*args, **kwargs)
    def delete_remote_file(self, *args, **kwargs): return self.cm.delete_remote_file(*args, **kwargs)
    def connect_all(self): return self.cm.connect_all()
    def disconnect_all(self): return self.cm.disconnect_all()
    def batch_execute(self, *args, **kwargs): return self.cm.batch_execute(*args, **kwargs)
    def check_connections(self): return self.cm.check_connections()
    
    # --- Security Scanner Delegates ---
    def scan_php_vulns(self, *args, **kwargs): return self.scanner.scan_php_vulns(*args, **kwargs)
    def scan_python_vulns(self, *args, **kwargs): return self.scanner.scan_python_vulns(*args, **kwargs)
    def snapshot_files(self, *args, **kwargs): return self.scanner.snapshot_files(*args, **kwargs)
    def scan_backdoor(self, *args, **kwargs): return self.scanner.scan_backdoor(*args, **kwargs)
    def get_custom_rules(self): return self.scanner.get_custom_rules()
    def add_custom_rule(self, *args, **kwargs): return self.scanner.add_custom_rule(*args, **kwargs)
    def remove_custom_rule(self, *args, **kwargs): return self.scanner.remove_custom_rule(*args, **kwargs)
    def toggle_custom_rule(self, *args, **kwargs): return self.scanner.toggle_custom_rule(*args, **kwargs)

    # --- Defense Manager Delegates ---
    def backup_target(self, *args, **kwargs): return self.defense.backup_target(*args, **kwargs)
    def restore_backup(self, *args, **kwargs): return self.defense.restore_backup(*args, **kwargs)
    def deploy_aoi_tools(self, *args, **kwargs): return self.defense.deploy_aoi_tools(*args, **kwargs)
    def setup_wwwdata_shell(self, *args, **kwargs): return self.defense.setup_wwwdata_shell(*args, **kwargs)
    def execute_as_wwwdata(self, *args, **kwargs): return self.defense.execute_as_wwwdata(*args, **kwargs)
    def run_preload_tasks(self, *args, **kwargs): return self.defense.run_preload_tasks(*args, **kwargs)
    def save_preload_config(self): return self.defense.save_preload_config()
    def add_scheduled_task(self, *args, **kwargs): return self.defense.add_scheduled_task(*args, **kwargs)
    def remove_scheduled_task(self, *args, **kwargs): return self.defense.remove_scheduled_task(*args, **kwargs)
    def remove_scheduled_task(self, *args, **kwargs): return self.defense.remove_scheduled_task(*args, **kwargs)
    def get_scheduled_tasks(self): return self.defense.get_scheduled_tasks()

    # --- Immortal Shell Killer Delegates ---
    def start_immortal_killer(self, *args, **kwargs): return self.immortal_killer.start_monitoring(*args, **kwargs)
    def stop_immortal_killer(self, *args, **kwargs): return self.immortal_killer.stop_monitoring(*args, **kwargs)

    # --- Attack Manager Delegates ---
    def set_enemy_config(self, *args, **kwargs): return self.attack.set_enemy_config(*args, **kwargs)
    def get_attack_status(self): return self.attack.get_attack_status()
    def start_counter_attack_campaign(self, *args, **kwargs): return self.attack.start_counter_attack_campaign(*args, **kwargs)
    def execute_attack_cmd(self, *args, **kwargs): return self.attack.execute_cmd(*args, **kwargs)
    def get_attack_flag(self, *args, **kwargs): return self.attack.get_flag(*args, **kwargs)
    
# Singleton Instance
ssh_manager = SSHControllerFacade()
