from .ssh_manager import SSHManager
from .security_scanner import SecurityScanner
from .defense_manager import DefenseManager

class SSHControllerFacade:
    def __init__(self):
        self.ssh = SSHManager()
        self.scanner = SecurityScanner(self.ssh)
        self.defense = DefenseManager(self.ssh, self.scanner)

    def init_app(self, app):
        self.ssh.init_app(app)
        self.scanner.init_app(app)
        self.defense.init_app(app)

    @property
    def targets(self): return self.ssh.targets

    @property
    def preload_config(self): return self.defense.preload_config

    def set_socketio(self, socketio): self.ssh.set_socketio(socketio)

    # --- SSH Manager Delegates ---
    def add_target(self, *args, **kwargs): return self.ssh.add_target(*args, **kwargs)
    def remove_target(self, *args, **kwargs): return self.ssh.remove_target(*args, **kwargs)
    def update_password(self, *args, **kwargs): return self.ssh.update_password(*args, **kwargs)
    
    def connect(self, ip, port, private_key_path=None): 
        # 使用明确的参数签名，确保 ip/port 能被准确捕获
        result = self.ssh.connect(ip, port, private_key_path)
        if result[0]: # connected
            # Trigger detection
            import threading
            # 确保传递给 defense 的参数也是一致的
            target_args = (ip, port) 
            threading.Thread(target=self.defense.detect_target_type, args=target_args).start()
            threading.Thread(target=self.defense.run_preload_tasks, args=target_args).start()
        return result

    def disconnect(self, *args, **kwargs): return self.ssh.disconnect(*args, **kwargs)
    def execute(self, *args, **kwargs): return self.ssh.execute(*args, **kwargs)
    def execute_with_cwd(self, *args, **kwargs): return self.ssh.execute_with_cwd(*args, **kwargs)
    def upload(self, *args, **kwargs): return self.ssh.upload(*args, **kwargs)
    def download(self, *args, **kwargs): return self.ssh.download(*args, **kwargs)
    def list_remote_dir(self, *args, **kwargs): return self.ssh.list_remote_dir(*args, **kwargs)
    def read_remote_file(self, *args, **kwargs): return self.ssh.read_remote_file(*args, **kwargs)
    def write_remote_file(self, *args, **kwargs): return self.ssh.write_remote_file(*args, **kwargs)
    def delete_remote_file(self, *args, **kwargs): return self.ssh.delete_remote_file(*args, **kwargs)
    def connect_all(self): return self.ssh.connect_all()
    def disconnect_all(self): return self.ssh.disconnect_all()
    def batch_execute(self, *args, **kwargs): return self.ssh.batch_execute(*args, **kwargs)
    def check_connections(self): return self.ssh.check_connections()
    def get_local_ip(self): return self.ssh.get_local_ip()
    def set_local_ip(self, *args, **kwargs): return self.ssh.set_local_ip(*args, **kwargs)
    def _ensure_initialized(self): 
         # Simple check if targets loaded.
         if not self.ssh.targets and self.ssh.data_dir:
             self.ssh.load_targets()

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
    def get_scheduled_tasks(self): return self.defense.get_scheduled_tasks()
    
# Singleton Instance
ssh_manager = SSHControllerFacade()
