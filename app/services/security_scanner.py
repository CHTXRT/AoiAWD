import os
import re
import json
import time
import threading
import shlex
import logging

logger = logging.getLogger('SecurityScanner')

class SecurityScanner:
    def __init__(self, connection_manager, target_manager):
        self.cm = connection_manager
        self.tm = target_manager
        self.custom_php_rules = []
        self.custom_rules_file = None
        self.attack_manager = None
        
        # 后门特征正则 (Updated: 2026-02-14)
        self.BACKDOOR_PATTERNS = [
            (r'(?i)eval\s*\(\s*[\"\']?\s*base64_decode', 'PHP 加密马特征 (eval+b64)'),
            (r'(?i)eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)', 'PHP 一句话 (eval)'),
            (r'(?i)assert\s*\(\s*\$_(POST|GET|REQUEST)', 'PHP 一句话 (assert)'),
            (r'(?i)system\s*\(\s*\$_(POST|GET|REQUEST)', 'PHP 命令执行'),
            (r'(?i)shell_exec\s*\(\s*\$_(POST|GET|REQUEST)', 'PHP 命令执行'),
            (r'(?i)passthru\s*\(\s*\$_(POST|GET|REQUEST)', 'PHP 命令执行'),
            (r'(?i)\$_(GET|POST|REQUEST|COOKIE)\[.+\]\(', 'PHP 动态函数调用'),
            (r'(?i)call_user_func\s*\(\s*\$_(POST|GET|REQUEST)', 'PHP 回调后门'),
            (r'(?i)array_map\s*\(\s*[\'\"]assert', 'PHP array_map后门'),
            (r'(?i)ignore_user_abort\s*\(\s*true\s*\)', 'PHP 不死马特征 (ignore_user_abort)'),
            (r'(?i)set_time_limit\s*\(\s*0\s*\)', 'PHP 不死马特征 (set_time_limit)'),
            (r'(?i)file_put_contents\s*\(.*\.php', 'PHP 写 PHP 文件'),
            (r'(?i)__import__\s*\(\s*["\']os["\']\)', 'Python os 导入'),
            (r'(?i)exec\s*\(.*request\.(form|args|data)', 'Python exec 后门'),
            (r'(?i)eval\s*\(.*request\.(form|args|data)', 'Python eval 后门'),
            (r'(?i)os\.system', 'Python os.system 调用'),
            (r'(?i)subprocess\.call', 'Python subprocess 调用'),
        ]

    def init_app(self, app):
         self.custom_rules_file = os.path.join(app.config['DATA_DIR'], 'custom_php_rules.json')
         self.load_custom_rules()

    def set_attack_manager(self, attack_manager):
        self.attack_manager = attack_manager

    def load_custom_rules(self):
        if self.custom_rules_file and os.path.exists(self.custom_rules_file):
            try:
                with open(self.custom_rules_file, 'r', encoding='utf-8') as f:
                    self.custom_php_rules = json.load(f)
            except: self.custom_php_rules = []
        else: self.custom_php_rules = []

    def save_custom_rules(self):
        if self.custom_rules_file:
            try:
                with open(self.custom_rules_file, 'w', encoding='utf-8') as f:
                    json.dump(self.custom_php_rules, f, ensure_ascii=False, indent=2)
            except: pass

    # Wrapper methods for rules
    def get_custom_rules(self): return self.custom_php_rules
    def add_custom_rule(self, name, pattern, desc):
        rule = {'name': name, 'pattern': pattern, 'description': desc, 'enabled': True}
        self.custom_php_rules.append(rule)
        self.save_custom_rules()
        return rule
    def remove_custom_rule(self, index):
        if 0 <= index < len(self.custom_php_rules):
            self.custom_php_rules.pop(index)
            self.save_custom_rules()
            return True
        return False
    def toggle_custom_rule(self, index):
        if 0 <= index < len(self.custom_php_rules):
            self.custom_php_rules[index]['enabled'] = not self.custom_php_rules[index]['enabled']
            self.save_custom_rules()
            return self.custom_php_rules[index]
        return None

    def scan_php_vulns(self, ip, port):
        ip = ip.strip()
        port = int(port)
        target = self.tm.get_target(ip, port)
        if not target: return

        target['status'] = 'scanning...'
        self.tm.notify_target_update(target)

        builtin_patterns = [
            'system\\s*\\(', 'exec\\s*\\(', 'passthru\\s*\\(', 'shell_exec\\s*\\(',
            'popen\\s*\\(', 'proc_open\\s*\\(', 'pcntl_exec\\s*\\(',
            'eval\\s*\\(', 'assert\\s*\\(', 
            'create_function\\s*\\(', 'call_user_func\\s*\\(',
            'preg_replace\\s*\\(.*\\/e',
            '`.*`',
            'unserialize\\s*\\(',
            'base64_decode\\s*\\(.*\\$_',
            'file_put_contents\\s*\\(.*\\.php',
        ]
        custom_patterns = [r['pattern'] for r in self.custom_php_rules if r.get('enabled', True)]
        all_patterns = builtin_patterns + custom_patterns

        grep_expr_list = []
        for p in all_patterns:
             grep_p = p.replace('\\s*', '[[:space:]]*')
             grep_expr_list.append(grep_p)
        
        grep_expr = '|'.join(grep_expr_list)
        cmd = f"grep -rnEH '{grep_expr}' /var/www/html --include='*.php' | head -n 30"

        try:
            output = self.cm.execute(ip, port, cmd)
            processed_lines = []
            if output and output.strip():
                attacks_to_trigger = []
                for line in output.strip().splitlines():
                    parts = line.split(':', 2)
                    if len(parts) >= 3:
                        content = parts[2]
                        risk_tag = 'Unknown'
                        for p in all_patterns:
                            if re.search(p, content):
                                risk_tag = p.replace('\\s*', ' ').replace('\\(', '').replace('\\)', '').replace('.*', ' ').replace('\\/', '/')
                                break
                        processed_lines.append(f"{parts[0]}:{parts[1]}:{risk_tag}:{content}")
                        
                        # --- Auto Counter-Attack Logic (Vulnerability Scan) ---
                        # Check if this line looks like a one-liner webshell
                        # Regex for $_POST['pass'], $_REQUEST["pass"], or $_POST[pass]
                        # We only auto-attack if we can clearly identify a password in a typical eval($_POST[...]) context
                        pass_match = re.search(r'\$_(POST|REQUEST|GET)\[[\'"]?(\w+)[\'"]?\]', content)
                        if pass_match and ('eval' in content or 'assert' in content or 'system' in content):
                            shell_pass = pass_match.group(2)
                            filepath = parts[0]
                            
                            # EXCLUSION: Ignore hidden files (starting with .)
                            filename = os.path.basename(filepath)
                            if filename.startswith('.'):
                                logger.info(f"[{ip}:{port}] Ignoring hidden file for counter-attack: {filepath}")
                            else:
                                # Collect for later execution to don't block scan
                                attacks_to_trigger.append((ip, int(port), filepath, shell_pass))
                            
                    else:
                        processed_lines.append(line)
                
                final_output = '\n'.join(processed_lines)
                with self.tm.lock:
                    if 'detection' not in target: target['detection'] = {}
                    target['detection']['php_vulns'] = final_output
                    self.tm.save_targets()
                logger.info(f"[{ip}:{port}] PHP Scan found risks! (Processed {len(processed_lines)} lines)")

                # Launch attacks after saving scan results
                if hasattr(self, 'attack_manager') and self.attack_manager:
                    for atk in attacks_to_trigger:
                        logger.warning(f"[{atk[0]}:{atk[1]}] VULN SCAN: Found potential webshell in {atk[2]}. Password: '{atk[3]}'. Triggering counter-attack!")
                        threading.Thread(target=self.attack_manager.start_counter_attack_campaign, 
                                        args=atk).start()
                else:
                    if attacks_to_trigger:
                        logger.info(f"[{ip}:{port}] AttackManager not configured, skipping {len(attacks_to_trigger)} counter-attacks")

            else:
                 logger.info(f"[{ip}:{port}] PHP Scan found no risks")
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
        finally:
            with self.tm.lock:
                target['status'] = 'connected'
                self.tm.notify_target_update(target)
                self.tm.save_targets()

    def scan_python_vulns(self, ip, port):
        ip = ip.strip()
        port = int(port)
        target = self.tm.get_target(ip, port)
        if not target: return

        target['status'] = 'scanning...'
        self.tm.notify_target_update(target)
        
        patterns = {
            r'eval\s*\(': 'eval',
            r'exec\s*\(': 'exec',
            r'compile\s*\(': 'compile',
            r'os\.system\s*\(': 'os.system',
            r'os\.popen\s*\(': 'os.popen',
            r'subprocess\.\w+\s*\(': 'subprocess',
            r'commands\.\w+\s*\(': 'commands',
            r'pickle\.loads?\s*\(': 'pickle',
            r'yaml\.load\s*\(': 'yaml.load',
            r'__import__\s*\(': '__import__',
            r'importlib\.import': 'importlib',
            r'render_template_string\s*\(': 'SSTI:render_template_string',
            r'\.render\s*\([^)]*request': 'SSTI:render+request',
            r'\{\{.*config.*\}\}': 'SSTI:config_leak',
            r'\{\{.*self\.__.*\}\}': 'SSTI:class_access',
            r'\{\{.*\[\].__.*\}\}': 'SSTI:class_access',
            r'\{\{.*import.*\}\}': 'SSTI:import',
        }

        try:
             # Remote grep scan (Backup logic omitted for simplicity unless requested, focusing on core functionality)
             grep_patterns = [
                'eval\\s*\\(', 'exec\\s*\\(', 'compile\\s*\\(',
                'os\\.system\\s*\\(', 'os\\.popen\\s*\\(',
                'subprocess\\.', 'commands\\.',
                'pickle\\.loads', 'yaml\\.load\\s*\\(',
                '__import__\\s*\\(', 'importlib\\.import',
                'render_template_string\\s*\\(',
                '\\{\\{.*config.*\\}\\}',
             ]
             grep_expr = '|'.join(grep_patterns)
             cmd = f"grep -rnE '{grep_expr}' /home --include='*.py' --exclude-dir=upload --exclude-dir=uploads | head -n 50"
             output = self.cm.execute(ip, port, cmd)
             
             processed_lines = []
             if output and output.strip():
                for line in output.strip().split('\\n'):
                    parts = line.split(':', 2)
                    if len(parts) >= 3:
                        content = parts[2]
                        risk_tag = 'Unknown'
                        for pattern, tag in patterns.items():
                            if re.search(pattern, content):
                                risk_tag = tag
                                break
                        processed_lines.append(f"{parts[0]}:{parts[1]}:{risk_tag}:{content}")
                    else:
                        processed_lines.append(line)

             if processed_lines:
                final_output = '\\n'.join(processed_lines[:50])
                with self.tm.lock:
                    if 'detection' not in target: target['detection'] = {}
                    target['detection']['python_vulns'] = final_output
                    self.tm.save_targets()

             target['status'] = 'connected'
             self.tm.notify_target_update(target)
             self.tm.save_targets()
        except Exception as e:
            logger.error(f"Python scan error: {e}")

    def snapshot_files(self, ip, port):
        target = self.tm.get_target(ip, port)
        if not target: 
            logger.error(f"[{ip}:{port}] Snapshot failed: Target not found")
            return False, '靶机未找到'

        logger.info(f"[{ip}:{port}] Starting file snapshot...")
        snapshot = {}
        
        # Determine directories based on target type to avoid irrelevant scans
        detection = target.get('detection', {})
        types = detection.get('types', [])
        scan_dirs = []
        if 'php' in types:
            scan_dirs.append('/var/www/html')
        if 'python' in types:
            scan_dirs.append('/home')
        
        # Fallback if undetected or Pwn (usually home)
        if not scan_dirs:
            scan_dirs = ['/var/www/html', '/home']

        for scan_dir in scan_dirs:
            exclude = "-not -path '*/upload/*' -not -path '*/uploads/*'" if 'home' in scan_dir else ''
            # Optimized: Use xargs for speed and better compatibility
            # Use -print0 to handle filenames with spaces
            cmd = f"find {scan_dir} -type f {exclude} -print0 | xargs -0 md5sum 2>/dev/null"
            output = self.cm.execute(ip, int(port), cmd)
            
            if output and 'Error' not in output:
                lines = output.strip().split('\n')
                # DEBUG: If files are very few, maybe something is wrong (or it's a fresh container)
                if len(lines) < 5:
                     logger.warning(f"[{ip}:{port}] Snapshot WARN: Only {len(lines)} files found in {scan_dir}. Raw: {output[:200]}")
                
                for line in lines:
                    line = line.strip()
                    if not line: continue
                    # md5sum output: hash  filename
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        md5_hash, filepath = parts
                        snapshot[filepath] = md5_hash

        with self.tm.lock:
            target['file_snapshot'] = snapshot
            target['snapshot_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
            self.tm.notify_target_update(target)
            self.tm.save_targets()
        
        count = len(snapshot)
        logger.info(f"[{ip}:{port}] Snapshot completed. Tracked {count} files")
        return True, f'快照完成，共 {count} 个文件'

    def scan_backdoor(self, ip, port):
        target = self.tm.get_target(ip, port)
        if not target: 
             logger.error(f"[{ip}:{port}] Backdoor scan failed: Target not found")
             return {'error': '靶机未找到'}

        target['status'] = 'scanning backdoor...'
        self.tm.notify_target_update(target)

        logger.info(f"[{ip}:{port}] Starting backdoor scan...")
        results = {
            'new_files': [], 'modified_files': [], 'deleted_files': [], 'backdoors': [],
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        }

        baseline = target.get('file_snapshot', {})
        current_files = {}
        
        # Sync logic with snapshot_files
        detection = target.get('detection', {})
        types = detection.get('types', [])
        scan_dirs = []
        if 'php' in types:
            scan_dirs.append('/var/www/html')
        if 'python' in types:
            scan_dirs.append('/home')
        if not scan_dirs:
             scan_dirs = ['/var/www/html', '/home']

        for scan_dir in scan_dirs:
            exclude = "-not -path '*/upload/*' -not -path '*/uploads/*'" if 'home' in scan_dir else ''
            cmd = f"find {scan_dir} -type f {exclude} -exec md5sum {{}} \\; 2>/dev/null"
            output = self.cm.execute(ip, int(port), cmd)
            if output and 'Error' not in output:
                for line in output.strip().split('\\n'):
                    line = line.strip()
                    if not line: continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                         md5_hash, filepath = parts
                         current_files[filepath] = md5_hash

        if baseline:
            for filepath, md5_hash in current_files.items():
                if filepath not in baseline: results['new_files'].append(filepath)
                elif baseline[filepath] != md5_hash: results['modified_files'].append(filepath)
            for filepath in baseline:
                if filepath not in current_files: results['deleted_files'].append(filepath)

        suspect_files = results['new_files'] + results['modified_files']
        if not baseline:
             logger.info(f"[{ip}:{port}] No baseline found. Scanning all PHP/Python files")
             suspect_files = [f for f in current_files.keys() if f.endswith(('.php', '.py', '.phtml', '.php5'))]

        logger.info(f"[{ip}:{port}] Scanning content of {len(suspect_files)} suspect files using batch grep...")
        if suspect_files:
            # Batch scan suspect files using grep to find patterns
            # Limit to first 100 files to avoid command line length limits
            subset = suspect_files[:100]
            files_arg = " ".join([shlex.quote(f) for f in subset])
            
            # Re-use BACKDOOR_PATTERNS but convert to grep regex
            grep_expr_list = []
            for pattern, desc in self.BACKDOOR_PATTERNS:
                # Basic conversion of (?i) to grep -i and removing non-grep regex groups
                p = pattern.replace('(?i)', '')
                p = p.replace('\\s*', '[[:space:]]*')
                grep_expr_list.append(p)
            
            grep_expr = "|".join(grep_expr_list)
            cmd = f"grep -riEH '{grep_expr}' {files_arg} 2>/dev/null"
            grep_out = self.cm.execute(ip, int(port), cmd)
            
            if grep_out and 'Error' not in grep_out:
                found_map = {} # path -> [matches]
                for line in grep_out.strip().splitlines():
                    parts = line.split(':', 2)
                    if len(parts) >= 3:
                        filepath = parts[0]
                        line_content = parts[2]
                        matches = self._match_backdoor_patterns(line_content)
                        if matches:
                            if filepath not in found_map: found_map[filepath] = set()
                            found_map[filepath].update(matches)
                
                for filepath, matches in found_map.items():
                    results['backdoors'].append({
                        'file': filepath,
                        'matches': list(matches),
                        'is_new': filepath in results['new_files']
                    })

        with self.tm.lock:
            target['backdoor_scan'] = results
            target['status'] = 'connected'
            self.tm.notify_target_update(target)
            self.tm.save_targets()
        
        logger.info(f"[{ip}:{port}] Backdoor scan finished. Found {len(results['backdoors'])} backdoors")
        return results

    def _match_backdoor_patterns(self, content):
        matches = []
        for pattern, desc in self.BACKDOOR_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                matches.append(desc)
        return list(set(matches))
