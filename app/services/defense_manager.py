import os
import time
import threading
import json
import base64
import logging
import subprocess

logger = logging.getLogger('Defense')
logger.setLevel(logging.INFO)

class DefenseManager:
    def __init__(self, connection_manager, target_manager, scanner, immortal_killer=None):
        self.cm = connection_manager
        self.tm = target_manager
        self.scanner = scanner
        self.immortal_killer = immortal_killer
        self.monitor_service = None # Will be set via setter or init
        self.backups_folder = None
        self.tools_folder = None
        self.preload_folder = None
        self.preload_config = {'files': [], 'commands': []}
        
        # Scheduled Tasks
        self.scheduled_tasks = {}
        self._scheduler_running = False
        self._scheduler_thread = None

    def set_monitor_service(self, monitor_service):
        self.monitor_service = monitor_service

    def init_app(self, app):
         self.backups_folder = app.config['BACKUPS_FOLDER']
         self.tools_folder = os.path.join(app.config['BASE_DIR'], 'tools')
         self.preload_folder = app.config['PRELOAD_FOLDER']
         self.config_file = app.config['CONFIG_FILE']
         self.load_preload_config()

    def load_preload_config(self):
        if self.config_file and os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    self.preload_config = json.load(f)
            except: pass
        else:
             self.preload_config = {'files': [], 'commands': []}

    def save_preload_config(self):
        if self.config_file:
            with open(self.config_file, 'w') as f:
                json.dump(self.preload_config, f, indent=4)

    def detect_target_type(self, ip, port):
        """识别靶机类型 (PHP/Python/Pwn) 并触发后续扫描/备份"""
        ip = ip.strip()
        port = int(port)
        logger.debug(f"[{ip}:{port}] Starting detection...")
        target = self.tm.get_target(ip, port)
        if not target: 
            logger.warning(f"[{ip}:{port}] Target not found in memory during detection.")
            return
        
        target['status'] = 'detecting...'
        self.tm.notify_target_update(target)

        detection = {'types': [], 'evidence': {}}
        try:
            # Check PHP
            out_php_find = self.cm.execute(ip, port, "find /var/www/html -name '*.php' | head -n 5")
            if out_php_find and '.php' in out_php_find:
                detection['types'].append('php')
                detection['evidence']['php_scripts'] = out_php_find.strip()

            # Check Python
            out_py = self.cm.execute(ip, port, "find /home -name '*.py' | head -n 5")
            if out_py and '.py' in out_py:
                detection['types'].append('python')
                detection['evidence']['python'] = out_py.strip()

            # Check Pwn
            out_pwn = self.cm.execute(ip, port, "find /home -type f -executable ! -name '*.*' | head -n 5")
            if out_pwn and out_pwn.strip():
                detection['types'].append('pwn')
                detection['evidence']['pwn'] = out_pwn.strip()

        except Exception as e: logger.error(f"Detection error: {e}")

        with self.tm.lock:
            target['detection'] = detection
            target['status'] = 'connected'
            self.tm.notify_target_update(target)
            self.tm.save_targets()

        if detection['types']:
             self.backup_target(ip, port, detection)
        
        if 'php' in detection['types']:
            threading.Thread(target=self.scanner.scan_php_vulns, args=(ip, port)).start()
            threading.Thread(target=self.setup_wwwdata_shell, args=(ip, port)).start()
            threading.Thread(target=self._detect_php_ini, args=(ip, port)).start()
            
            # Use sequential initialization for PHP defense to avoid conflict
            threading.Thread(target=self._init_php_defense, args=(ip, port)).start()


        if 'python' in detection['types']:
            threading.Thread(target=self.scanner.scan_python_vulns, args=(ip, port)).start()
            
        if 'pwn' in detection['types']:
            threading.Thread(target=self.auto_patch_pwn, args=(ip, port)).start()

    def backup_target(self, ip, port, detection=None, force_rerun=False):
        ip = ip.strip()
        port = int(port)
        target = self.tm.get_target(ip, port)
        if not target: return
        
        # Check if backup actually exists
        backup_path = target.get('backup_path')
        if target.get('backup_done') and not force_rerun:
            if backup_path and os.path.exists(backup_path):
                print(f"[{ip}:{port}] Backup already exists at {backup_path}, skipping.")
                return
            else:
                print(f"[{ip}:{port}] Backup flagged as done but file missing. Re-running backup.")

        if not detection: detection = target.get('detection', {'types': []})

        logger.info(f"[{ip}:{port}] Starting automated backup...")
        target['status'] = 'backing up...'
        self.tm.notify_target_update(target)

        if not self.backups_folder: return
        if not os.path.exists(self.backups_folder): os.makedirs(self.backups_folder)
        target_backup_dir = os.path.join(self.backups_folder, f"{ip}_{port}")
        if not os.path.exists(target_backup_dir): os.makedirs(target_backup_dir)
        
        try:
            # PHP Backup
            if 'php' in detection['types']:
                remote_src = "/var/www/html"
                backup_name = "web.tar"
                local_dst = os.path.join(target_backup_dir, backup_name)
                
                if not (os.path.exists(local_dst) and not force_rerun):
                    # Additional Raw Backup to /tmp
                    self.cm.execute(ip, port, "cp -r /var/www/html /tmp/html_bak 2>/dev/null || true")
                    
                    self.cm.execute(ip, port, f"tar -cf /tmp/{backup_name} {remote_src} 2>/dev/null || true")
                    self.cm.download(ip, port, f"/tmp/{backup_name}", local_dst)
                    self.cm.execute(ip, port, f"rm /tmp/{backup_name}")
                
                with self.tm.lock:
                    target['backup_path'] = local_dst

            # Python Backup
            if 'python' in detection['types'] and 'python' in detection['evidence']:
                evidence = detection['evidence']['python']
                remote_src = os.path.dirname(evidence.split('\\n')[0])
                backup_name = "web.tar"
                local_dst = os.path.join(target_backup_dir, backup_name)
                
                self.cm.execute(ip, port, f"tar -cf /tmp/{backup_name} {remote_src} 2>/dev/null || true")
                self.cm.download(ip, port, f"/tmp/{backup_name}", local_dst)
                self.cm.execute(ip, port, f"rm /tmp/{backup_name}")
                with self.tm.lock: target['backup_path'] = local_dst

            # Pwn Backup
            if 'pwn' in detection['types'] and 'pwn' in detection['evidence']:
                remote_src = detection['evidence']['pwn'].split('\\n')[0]
                backup_name = os.path.basename(remote_src)
                local_dst = os.path.join(target_backup_dir, backup_name)
                self.cm.download(ip, port, remote_src, local_dst)
                with self.tm.lock: target['backup_path'] = local_dst

            with self.tm.lock:
                target['backup_done'] = True
                self.tm.save_targets()
            
            target['status'] = 'connected'
            self.tm.notify_target_update(target)
            
        except Exception as e:
            logger.error(f"Backup error: {e}")

    def restore_backup(self, ip, port):
        target = self.tm.get_target(ip, port)
        if not target: 
            print(f"[{ip}:{port}] Restore failed: Target not found")
            return False, '靶机未找到'

        backup_path = target.get('backup_path')
        if not backup_path or not os.path.exists(backup_path):
            logger.error(f"[{ip}:{port}] Restore failed: Backup file not found ({backup_path})")
            return False, '备份文件不存在'

        logger.info(f"[{ip}:{port}] Restoring backup from {backup_path}...")
        try:
            remote_tmp = f"/tmp/{os.path.basename(backup_path)}"
            
            # Pwn Restore Logic
            detection = target.get('detection', {})
            if 'pwn' in detection.get('types', []):
                 original_path = detection['evidence']['pwn'].split('\\n')[0]
                 
                 # 1. Try restore from remote .bak (fastest)
                 backup_remote_path = f"{original_path}.bak"
                 check_bak = self.cm.execute(ip, int(port), f"test -f {backup_remote_path} && echo EXISTS")
                 
                 if 'EXISTS' in (check_bak or ''):
                     print(f"[{ip}:{port}] Restoring from remote backup {backup_remote_path}...")
                     self.cm.execute(ip, int(port), f"rm {original_path} && mv {backup_remote_path} {original_path} && chmod +x {original_path}")

                     with self.tm.lock:
                        target['pwn_patched'] = False
                        self.tm.notify_target_update(target)
                        self.tm.save_targets()
                     return True, 'Pwn 还原成功 (从远程 .bak 恢复)'
                 
                 # 2. If no .bak, upload local backup
                 print(f"[{ip}:{port}] No remote .bak found. Restoring from local backup...")
                 self.cm.upload(ip, int(port), backup_path, remote_tmp)
                 self.cm.execute(ip, int(port), f"cp {remote_tmp} {original_path} && chmod +x {original_path}")
                 self.cm.execute(ip, int(port), f"rm {remote_tmp}")
                 self.tm.notify_target_update(target)
                 return True, 'Pwn 还原成功 (从本地备份恢复)'

            # Standard Web Restore
            self.cm.upload(ip, int(port), backup_path, remote_tmp)
            
            if backup_path.endswith('.tar'):
                webroot = '/var/www/html'
                # 1. Prepare backup location (Use /tmp to avoid permission issues in /var/www)
                timestamp = int(time.time())
                backup_old = f"/tmp/html_backup_{timestamp}"
                print(f"[{ip}:{port}] Backing up current files to {backup_old}...", flush=True)
                
                self.cm.execute(ip, int(port), f"mkdir -p {backup_old}")
                
                # 2. Move contents
                # Capture output to debug
                cmd_mv = f"mv {webroot}/* {backup_old}/ 2>/dev/null; mv {webroot}/.[!.]* {backup_old}/ 2>/dev/null"
                out_mv = self.cm.execute(ip, int(port), cmd_mv)
               
                # 3. Webroot is now clean-ish. Ensure it exists.
                self.cm.execute(ip, int(port), f"mkdir -p {webroot}")

                # 4. Extract backup
                print(f"[{ip}:{port}] Extracting backup to {webroot}...", flush=True)
                res = self.cm.execute(ip, int(port), f"tar -xf {remote_tmp} -C / 2>/dev/null")
                
                # 5. Check if restore worked
                check = self.cm.execute(ip, int(port), f"ls -A {webroot}")
                if check:
                    self.cm.execute(ip, int(port), f"rm {remote_tmp}")
                    self.cm.execute(ip, int(port), f"rm {remote_tmp}")
                    logger.info(f"[{ip}:{port}] Backup restored. Old files moved to {backup_old}.")
                    self.tm.notify_target_update(target)
                    return True, f'备份还原成功 (旧文件已移至 {backup_old})'
                else:
                    # Restore failed? Rollback
                    logger.error(f"[{ip}:{port}] Restore seems failed (dir empty), rolling back...")
                    self.cm.execute(ip, int(port), f"rm -rf {webroot} && mv {backup_old} {webroot}")
                    return False, '还原失败，已回滚'
            else:
                detection = target.get('detection', {})
                if 'pwn' in detection.get('evidence', {}):
                    original_path = detection['evidence']['pwn'].split('\\n')[0]
                    self.cm.execute(ip, int(port), f"cp {remote_tmp} {original_path} && chmod +x {original_path}")
                    self.cm.execute(ip, int(port), f"rm {remote_tmp}")
                    print(f"[{ip}:{port}] Binary restored successfully.")
                    
                    self.tm.notify_target_update(target)
                    return True, '二进制文件还原成功'
                
                logger.info(f"[{ip}:{port}] Backup uploaded to {remote_tmp}.")
                self.tm.notify_target_update(target)
                return True, f'备份文件已上传到 {remote_tmp}'
        except Exception as e:
            logger.error(f"[{ip}:{port}] Restore error: {e}")
            return False, str(e)

    def auto_patch_pwn(self, ip, port):
        """自动 Patch Pwn 靶机"""
        target = self.tm.get_target(ip, port)
        if not target: return

        # 1. Wait for backup
        print(f"[{ip}:{port}] Waiting for backup before patching...", flush=True)
        retries = 0
        while not target.get('backup_done') and retries < 20:
             time.sleep(1)
             retries += 1
        
        backup_path = target.get('backup_path')
        if not backup_path or not os.path.exists(backup_path):
             logger.warning(f"[{ip}:{port}] Auto-Patch Skipped: Backup failed or missing.")
             return
        
        logger.info(f"[{ip}:{port}] Starting Auto-Patch (EvilPatcher)...")
        target['status'] = 'patching...'
        self.tm.notify_target_update(target)

        try:
            # 2. Prepare paths
            # backup_path is like "d:\...\tools\backups\ip_port\ezpwn"
            evil_patcher_dir = os.path.join(self.tools_folder, 'evilPatcher')
            evil_patcher_py = os.path.join(evil_patcher_dir, 'evilPatcher.py')
            sandbox_file = os.path.join(evil_patcher_dir, 'sandboxs', 'sandbox1.asm')
            
            patch_output_path = backup_path + ".patch"
            
            # Helper to convert win path to wsl path
            def to_wsl_path(win_path):
                # Drive letter d:\ -> /mnt/d/
                drive, rest = os.path.splitdrive(win_path)
                if drive:
                    drive_letter = drive[0].lower()
                    path = rest.replace('\\', '/')
                    return f"/mnt/{drive_letter}{path}"
                return win_path.replace('\\', '/')

            wsl_py = to_wsl_path(evil_patcher_py)
            wsl_input = to_wsl_path(backup_path)
            wsl_sandbox = to_wsl_path(sandbox_file)
            
            # 3. Execute Patch via WSL
            # python3 evilPatcher.py elfFile sandboxFile
            # Ensure paths are quoted to handle spaces if any (though typically minimal in these paths)
            cmd = f'wsl python3 "{wsl_py}" "{wsl_input}" "{wsl_sandbox}"'
            print(f"[{ip}:{port}] Executing WSL Patch Cmd: {cmd}", flush=True)
            
            # Run command synchronously
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                 print(f"[{ip}:{port}] Patching failed (WSL error): {result.stderr}", flush=True)
                 # Don't return, maybe check output file anyway? No, if it failed it failed.
                 return

            if not os.path.exists(patch_output_path):
                 logger.error(f"[{ip}:{port}] Patching failed: Output file not found ({patch_output_path})")
                 return
            
            logger.info(f"[{ip}:{port}] Patch generated successfully: {patch_output_path}")
            
            # 4. Upload & Deploy
            remote_pwn_path = target['detection']['evidence']['pwn'].split('\\n')[0]
            updated_filename = os.path.basename(remote_pwn_path)
            remote_tmp_patch = f"/tmp/{updated_filename}.patch"
            
            self.cm.upload(ip, int(port), patch_output_path, remote_tmp_patch)
            
            # Backup remote file to .bak (if not exists) and replace
            cmds = [
                f"chmod +x {remote_tmp_patch}",
                f"if [ ! -f {remote_pwn_path}.bak ]; then mv {remote_pwn_path} {remote_pwn_path}.bak; fi",
                f"cp {remote_tmp_patch} {remote_pwn_path}",
                f"chmod +x {remote_pwn_path}",
                f"rm {remote_tmp_patch}"
            ]
            
            full_deploy_cmd = " && ".join(cmds)
            self.cm.execute(ip, int(port), full_deploy_cmd)
            
            logger.info(f"[{ip}:{port}] Patch deployed successfully!")
            
            with self.tm.lock:
                target['pwn_patched'] = True
                self.tm.save_targets()

        except Exception as e:
            print(f"[{ip}:{port}] Auto-Patch Error: {e}", flush=True)
        
        target['status'] = 'connected'
        self.tm.notify_target_update(target)

    def _init_php_defense(self, ip, port):
        """Sequential initialization for PHP targets: AOI -> Immortal Killer -> PyGuard"""
        logger.info(f"[{ip}:{port}] Starting PHP Defense Initialization...")
        
        # 1. Deploy AOI (Safe deployment will handle timestamps)
        self.deploy_aoi_tools(ip, port)
        time.sleep(2)
        # 1.5 Deploy User Custom PHP Defense (ini_set)
        self.deploy_php_defense_script(ip, port)

        # 2. Deploy PyGuard (Python-based Monitor)
        if self.monitor_service:
            self.monitor_service.deploy_agent(ip, port)
        
        # 3. Create Snapshot & Scan Backdoor (Before starting Killer)
        # Ensure baseline is established including AOI tools
        print(f"[{ip}:{port}] Creating Security Snapshot...", flush=True)
        self.scanner.snapshot_files(ip, port)
        
        print(f"[{ip}:{port}] Starting Initial Backdoor Scan...", flush=True)
        self.scanner.scan_backdoor(ip, port)
        time.sleep(2)
        # 4. Start Immortal Shell Killer
        if self.immortal_killer:
            logger.info(f"[{ip}:{port}] Starting Immortal Shell Killer after Snapshot...")
            self.immortal_killer.start_monitoring(ip, port)

    def deploy_php_defense_script(self, ip, port):
        """Deploy user custom PHP defense script (.ini_set + preload)"""
        logger.info(f"[{ip}:{port}] Deploying custom PHP defense...")
        try:
            # Paths
            tools_include_php = os.path.join(self.tools_folder, 'include', '.ini_set.php')
            tools_preload_so = os.path.join(self.tools_folder, 'root-tmp', 'preload.so')
            tools_script = os.path.join(self.tools_folder, '.ini_set.sh')
            
            if not all(os.path.exists(p) for p in [tools_include_php, tools_preload_so, tools_script]):
                print(f"[{ip}:{port}] Custom PHP Defense Skipped: Tools missing.", flush=True)
                return

            # 1. Upload .ini_set.php -> /var/www/html/include/.ini_set.php
            remote_include_dir = "/var/www/html/include"
            self.cm.execute(ip, port, f"mkdir -p {remote_include_dir}")
            self.cm.upload(ip, port, tools_include_php, f"{remote_include_dir}/.ini_set.php")
            
            # 2. Upload preload.so -> /tmp/preload.so
            self.cm.upload(ip, port, tools_preload_so, "/tmp/preload.so")
            
            # 3. Upload .ini_set.sh -> /tmp/.ini_set.sh
            remote_script = "/tmp/.ini_set.sh"
            self.cm.upload(ip, port, tools_script, remote_script)
            self.cm.execute(ip, port, f"chmod +x {remote_script}")
            
            # 4. Execute script from webroot in background
            # cd /var/www/html && nohup /tmp/.ini_set.sh > /dev/null 2>&1 &
            cmd = f"cd /var/www/html && nohup {remote_script} > /dev/null 2>&1 &"
            self.cm.execute(ip, port, cmd)
            
            print(f"[{ip}:{port}] Custom PHP defense deployed successfully.", flush=True)
            
            # Wait for script to touch files
            time.sleep(2)
            
        except Exception as e:
            print(f"[{ip}:{port}] Custom PHP defense deploy error: {e}", flush=True)

    def deploy_aoi_tools(self, ip, port):
        target = self.tm.get_target(ip, port)
        if not target: return

        # Get Callback IP Priority: 1. Target Specific 2. Global Config 3. Auto-Detect
        local_ip = target.get('local_ip')
        if not local_ip:
            local_ip = self.tm.get_local_ip()
            
        if not local_ip:
            # Try to auto-detect from SSH session
            local_ip = self.cm.get_local_ip_for_target(ip, port)
            if local_ip:
                logger.info(f"[{ip}:{port}] AOI: Auto-detected Local IP: {local_ip}")
                with self.tm.lock:
                    target['detected_ip'] = local_ip
                    self.tm.notify_target_update(target)
            else:
                logger.warning(f"[{ip}:{port}] AOI Deploy Skipped: Local IP not set and autodetection failed.")
                return
        
        aoi_dir = os.path.join(self.tools_folder, 'aoi')
        tapeworm_path = os.path.join(aoi_dir, 'tapeworm.phar')
        roundworm_path = os.path.join(aoi_dir, 'roundworm')
        
        if not os.path.exists(tapeworm_path) or not os.path.exists(roundworm_path):
            print(f"[{ip}:{port}] AOI Deploy Skipped: Tools not found in {aoi_dir}", flush=True)
            return
        
        # --- Critical: Handling Immortal Shell Killer Conflict ---
        was_monitoring = False
        if self.immortal_killer and self.immortal_killer.is_monitoring(ip, port):
            print(f"[{ip}:{port}] Pausing Immortal Shell Killer for AOI deployment...", flush=True)
            self.immortal_killer.stop_monitoring(ip, port)
            was_monitoring = True
            
        try:
            
            # 2. Deploy AOI (Synchronous to ensure file mods complete before restore)
            print(f"[{ip}:{port}] Deploying AOI Tools...", flush=True)
            self.cm.upload(ip, port, tapeworm_path, '/tmp/tapeworm.phar')
            self.cm.upload(ip, port, roundworm_path, '/tmp/roundworm')
            self.cm.execute(ip, port, 'chmod +x /tmp/roundworm')
            
            ip1 = f"{local_ip}:8023"
            # Remove nohup and & to wait for completion
            tapeworm_cmd = f"cd /var/www/html && php /tmp/tapeworm.phar -d /var/www/html -s {ip1}"
            self.cm.execute(ip, port, tapeworm_cmd)
            
            ip2 = local_ip
            # Roundworm might be a long running process?? If so we should keep it bg but it modifies files?
            # Assuming roundworm is also a patcher/scanner. If it hangs, we might timeout.
            # Let's try synchronous with a timeout? Or just assume it's fast.
            # "Roundworm" usually implies a stronger WAF.
            # Let's keep Tapeworm sync (it definitely modifies files).
            # Let's keep Roundworm bg if it's a daemon, but if it modifies files launch it first?
            # Warning: If roundworm is a daemon, execute() will hang. 
            # Reverting Roundworm to BG if it's a watcher. But Tapeworm is the main patcher.
            roundworm_cmd = f"nohup /tmp/roundworm -d -s {ip2} -w /var/www/html > /dev/null 2>&1 &"
            self.cm.execute(ip, port, roundworm_cmd)
            
            # Wait a bit for any background tools to touch files
            
            # Wait a bit for any background tools to touch files
            # time.sleep(2) # Moved to post-restore for better snapshot timing
            
            with self.tm.lock:
                target['aoi_deployed'] = True
                print(f"[{ip}:{port}] AOI deploy Success!", flush=True)
                self.tm.notify_target_update(target)
                self.tm.save_targets()
                
            
        except Exception as e:
            print(f"[{ip}:{port}] AOI Deploy Error: {e}", flush=True)

        # 3.5 Update File Snapshot (Dynamic Baseline)
        # THIS IS CRITICAL: AOI modified files. We must accept this new state as the baseline
        # so Immortal Shell Killer doesn't kill them.
        # Wait for AOI (roundworm/tapeworm) to fully settle file modifications
        print(f"[{ip}:{port}] Waiting 5s for AOI to settle before snapshot...", flush=True)
        time.sleep(5)
        print(f"[{ip}:{port}] Updating File Snapshot after AOI deployment...", flush=True)
        self.scanner.snapshot_files(ip, port)

        # 4. Resume Immortal Shell Killer (If triggered manually and was running)
        if was_monitoring and self.immortal_killer:
             logger.info(f"[{ip}:{port}] Resuming Immortal Shell Killer...")
             self.immortal_killer.start_monitoring(ip, port)

    def setup_wwwdata_shell(self, ip, port):
        target = self.tm.get_target(ip, port)
        if not target: return
        
        # Ensure only filename is used for timestamp to verify unique shell name
        php_filename = f'.shell_{int(time.time())}.php'
        
        # --- 0. Enable SSH Login for www-data (for Xshell) ---
        try:
            # Set shell to /bin/bash (enable login)
            self.cm.execute(ip, port, "usermod -s /bin/bash www-data")
            
            # Set Password (WwwData@<LastIP>#<Port>)
            # simple deterministic password
            ip_suffix = ip.split('.')[-1]
            pw = f"WwwData@{ip_suffix}#{port}"
            # Use chpasswd
            self.cm.execute(ip, port, f"echo 'www-data:{pw}' | chpasswd")
            
            with self.tm.lock:
                target['wwwdata_password'] = pw
                self.tm.save_targets()
            
            logger.info(f"[{ip}:{port}] Enabled www-data SSH login. User: www-data, Pass: {pw}")
        except Exception as e:
            logger.error(f"[{ip}:{port}] Failed to enable www-data SSH: {e}")

        logger.info(f"[{ip}:{port}] Starting speedy www-data shell deployment...")
        php_content = "<?php system('cp /bin/bash /tmp/mujica;chmod u+s /tmp/mujica'); echo 'DONE';?>"
        b64_payload = base64.b64encode(php_content.encode()).decode()
        
        # Limit find depth to 4
        find_cmd = "find /var/www/html -maxdepth 4 -name '*.php' -type f 2>/dev/null | xargs -I{} dirname {} | sort -u"
        find_result = self.cm.execute(ip, port, find_cmd)
        
        php_dirs = []
        if find_result and find_result.strip():
            # Robust parsing
            for line in find_result.strip().splitlines():
                d = line.strip()
                if d and d.startswith('/') and d not in php_dirs:
                    php_dirs.append(d)
        
        # Sort by length (shallow dirs first)
        php_dirs.sort(key=len)

        if not php_dirs: 
            php_dirs = ['/var/www/html']
            print(f"[{ip}:{port}] No PHP dirs found, defaulting to /var/www/html", flush=True)
        else:
            # print(f"[{ip}:{port}] Found PHP dirs (shallow first): {php_dirs}", flush=True)
            pass
        
        ports_to_try = [80, 8080, 8888]
        success = False
        uploaded_paths = []
        import requests
        
        for web_dir in php_dirs:
            if success: break
            remote_path = f'{web_dir}/{php_filename}'
            
            # Try upload
            self.cm.execute(ip, port, f"echo {b64_payload} | base64 -d > {remote_path}")
            uploaded_paths.append(remote_path)
            
            # Skip verification as requested by user
            
            # Construct URLs: Try both full relative path and just filename (incase webroot is here)
            url_path = web_dir.replace('/var/www/html', '').lstrip('/')
            # Use list to ensure order: Deep path first, then shallow
            trigger_paths = []
            if url_path:
                trigger_paths.append(f"{url_path}/{php_filename}")
            trigger_paths.append(php_filename)
            
            # Loop over paths
            for trigger_file in trigger_paths:
                if success: break
                
                # Strategy 1: Controller-side Trigger (Fastest, Concurrent)
                for try_port in ports_to_try:
                    url = f"http://{ip}:{try_port}/{trigger_file}"
                    try:
                         # Very short timeout for local check
                         requests.get(url, timeout=0.2)
                    except: pass

                    # Check Success immediately after controller trigger
                    check = self.cm.execute(ip, port, "ls -la /tmp/mujica 2>/dev/null")
                    if check and 'mujica' in check and (('rws' in check) or ('s' in check.split()[0])):
                        logger.info(f"[{ip}:{port}] SUID shell created via Controller Request {url}")
                        success = True
                        break
                
                if success: break

                # Strategy 2: Remote Trigger (Fallback, SSH interaction)
                for try_port in ports_to_try:
                    url = f"http://localhost:{try_port}/{trigger_file}"
                    
                    # Try curl, wget, php with short timeouts
                    trigger_cmds = [
                        f"curl -s -m 1 -o /dev/null {url}",
                        f"wget -q -T 1 -O /dev/null {url}", 
                        f"php -r \"file_get_contents('{url}');\"" 
                    ]
                    
                    for cmd in trigger_cmds:
                        if cmd.startswith('php'):
                            cmd = f"timeout 1s {cmd}"
                        
                        self.cm.execute(ip, port, f"{cmd} > /dev/null 2>&1")
                
                time.sleep(0.5)
                check = self.cm.execute(ip, port, "ls -la /tmp/mujica 2>/dev/null")
                if check and 'mujica' in check and (('rws' in check) or ('s' in check.split()[0])):
                    # Let's run with a small timeout on SSH side using 'timeout' command if possible, 
                    # but simplest is just backgrounding it or relying on the command's own timeout.
                    # cmd already has -m 1 or -T 1.
                    
                    # For php, let's wrap in timeout 1s just in case
                    if cmd.startswith('php'):
                        cmd = f"timeout 1s {cmd}"
                    
                    self.cm.execute(ip, port, f"{cmd} > /dev/null 2>&1")
            
            time.sleep(0.5)
            check = self.cm.execute(ip, port, "ls -la /tmp/mujica 2>/dev/null")
            if check and 'mujica' in check and (('rws' in check) or ('s' in check.split()[0])):
                 print(f"[{ip}:{port}] SUID shell created via Remote Trigger", flush=True)
                 success = True
                 break

        # Cleanup
        for path in uploaded_paths: self.cm.execute(ip, port, f"rm -f {path}")

        logger.info(f"[{ip}:{port}] www-data shell {'success' if success else 'failed'}")
        
        with self.tm.lock:
            target['wwwdata_shell'] = success
            if success: target['wwwdata_strategy'] = 'suid'
            self.tm.notify_target_update(target)
            self.tm.save_targets()

    def execute_as_wwwdata(self, ip, port, cmd):
        target = self.tm.get_target(ip, port)
        if not target: return 'Error: 靶机未找到'
        if not target.get('wwwdata_shell'): return 'Error: www-data shell 未部署'

        strategy = target.get('wwwdata_strategy', 'sudo')
        if strategy == 'suid': wrapped_cmd = f'/tmp/mujica -p -c "{cmd}"'
        else: wrapped_cmd = f'sudo -u www-data bash -c "{cmd}"'
        return self.cm.execute(ip, int(port), wrapped_cmd)

    def _detect_php_ini(self, ip, port):
        target = self.tm.get_target(ip, port)
        if not target: return
        try:
            php_ini_info = {}
            ini_path_result = self.cm.execute(ip, port, "php -i 2>/dev/null | grep 'Loaded Configuration File' | awk -F'=> ' '{print $NF}'")
            ini_path = ini_path_result.strip() if ini_path_result else ''
            if not ini_path or ini_path == '(none)':
                find_result = self.cm.execute(ip, port, "find /etc -name 'php.ini' 2>/dev/null | head -n 1")
                ini_path = find_result.strip() if find_result else ''
            
            if not ini_path:
                php_ini_info['path'] = '未找到'
                php_ini_info['writable'] = False
            else:
                php_ini_info['path'] = ini_path
                perm_check = self.cm.execute(ip, port, f"test -w '{ini_path}' && echo WRITABLE || echo READONLY")
                php_ini_info['writable'] = 'WRITABLE' in (perm_check or '')
                
                configs_to_check = ['disable_functions', 'open_basedir', 'allow_url_include', 'display_errors', 'short_open_tag']
                config_values = {}
                for cfg in configs_to_check:
                    val = self.cm.execute(ip, port, f"php -i 2>/dev/null | grep -i '^{cfg}' | head -n 1")
                    if val and val.strip():
                        parts = val.strip().split('=>')
                        config_values[cfg] = parts[-1].strip() if len(parts) >= 2 else val.strip()
                    else:
                        config_values[cfg] = '未检测到'
                php_ini_info['configs'] = config_values

            restart_cmds = []
            for svc in ['apache2', 'nginx', 'php-fpm', 'php7.4-fpm', 'php8.0-fpm']:
                 check = self.cm.execute(ip, port, f"systemctl is-active {svc} 2>/dev/null")
                 if check and 'active' in check: restart_cmds.append(f"service {svc} restart")
            if not restart_cmds: restart_cmds = ['service apache2 restart', 'service php-fpm restart']
            php_ini_info['restart_cmds'] = restart_cmds

            with self.tm.lock:
                if 'detection' not in target: target['detection'] = {}
                target['detection']['php_ini'] = php_ini_info
                self.tm.notify_target_update(target)
                self.tm.save_targets()
        except Exception as e: print(f"php.ini detection error: {e}")

    def run_preload_tasks(self, ip, port, force_rerun=False):
        target = self.tm.get_target(ip, port)
        if not target: return
        if not force_rerun and target.get('preload_done'): return
        
        if self.preload_folder:
            for file_item in self.preload_config.get('files', []):
                local_path = os.path.join(self.preload_folder, file_item['filename'])
                if os.path.exists(local_path):
                    self.cm.upload(ip, port, local_path, file_item['remote_path'])
        
        for cmd in self.preload_config.get('commands', []):
            time.sleep(0.5)
            self.cm.execute(ip, port, cmd)
            
        with self.tm.lock:
            target['preload_done'] = True
            self.tm.save_targets()

    # Scheduled Tasks
    def add_scheduled_task(self, name, cmd, interval):
        self.scheduled_tasks[name] = {'cmd': cmd, 'interval': int(interval), 'last_run': 0, 'created_at': time.strftime('%Y-%m-%d %H:%M:%S')}
        self._start_scheduler()
        return True

    def remove_scheduled_task(self, name):
        if name in self.scheduled_tasks:
            del self.scheduled_tasks[name]
            return True
        return False

    def get_scheduled_tasks(self): return self.scheduled_tasks

    def _start_scheduler(self):
        if self._scheduler_running: return
        self._scheduler_running = True
        self._scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self._scheduler_thread.start()

    def _scheduler_loop(self):
        while self._scheduler_running:
            try:
                now = time.time()
                for name, task in list(self.scheduled_tasks.items()):
                    if now - task['last_run'] >= task['interval']:
                        self.cm.batch_execute(task['cmd'])
                        task['last_run'] = now
            except: pass
            time.sleep(5)

    def get_target_default_path(self, ip, port):
        target = self.tm.get_target(ip, port)
        if not target: return '/'
        
        detection = target.get('detection', {})
        types = detection.get('types', [])
        
        if 'php' in types:
            return '/var/www/html'
        elif 'pwn' in types:
            # Try to get directory of the binary
            if 'pwn' in detection.get('evidence', {}):
                 path = detection['evidence']['pwn'].split('\n')[0]
                 return path.rsplit('/', 1)[0] if '/' in path else '/home'
            return '/home'
        elif 'python' in types:
             return '/home'
             
        return '/'
