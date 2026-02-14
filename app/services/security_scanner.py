import os
import re
import json
import time

class SecurityScanner:
    def __init__(self, ssh_manager):
        self.ssh = ssh_manager
        self.custom_php_rules = []
        self.custom_rules_file = None
        
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
        target = next((t for t in self.ssh.targets if t['ip'] == ip and t['port'] == port), None)
        if not target: return

        target['status'] = 'scanning...'
        self.ssh.notify_target_update(target)

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
            output = self.ssh.execute(ip, port, cmd)
            processed_lines = []
            if output and output.strip():
                for line in output.strip().split('\\n'):
                    parts = line.split(':', 2)
                    if len(parts) >= 3:
                        content = parts[2]
                        risk_tag = 'Unknown'
                        for p in all_patterns:
                            if re.search(p, content):
                                risk_tag = p.replace('\\s*', ' ').replace('\\(', '').replace('\\)', '').replace('.*', ' ').replace('\\/', '/')
                                break
                        processed_lines.append(f"{parts[0]}:{parts[1]}:{risk_tag}:{content}")
                    else:
                        processed_lines.append(line)
                
                final_output = '\\n'.join(processed_lines)
                with self.ssh.lock:
                    if 'detection' not in target: target['detection'] = {}
                    target['detection']['php_vulns'] = final_output
                    self.ssh.save_targets()
                print(f"[{ip}:{port}] PHP Scan found risks!")
            else:
                 pass # clean
            
            target['status'] = 'connected'
            self.ssh.notify_target_update(target)
            self.ssh.save_targets()
        except Exception as e:
            print(f"Scan error: {e}")

    def scan_python_vulns(self, ip, port):
        ip = ip.strip()
        port = int(port)
        target = next((t for t in self.ssh.targets if t['ip'] == ip and t['port'] == port), None)
        if not target: return

        target['status'] = 'scanning...'
        self.ssh.notify_target_update(target)
        
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
             output = self.ssh.execute(ip, port, cmd)
             
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
                with self.ssh.lock:
                    if 'detection' not in target: target['detection'] = {}
                    target['detection']['python_vulns'] = final_output
                    self.ssh.save_targets()

             target['status'] = 'connected'
             self.ssh.notify_target_update(target)
             self.ssh.save_targets()
        except Exception as e:
            print(f"Python scan error: {e}")

    def snapshot_files(self, ip, port):
        target = next((t for t in self.ssh.targets if t['ip'] == ip and t['port'] == int(port)), None)
        if not target: 
            print(f"[{ip}:{port}] Snapshot failed: Target not found")
            return False, '靶机未找到'

        print(f"[{ip}:{port}] Starting file snapshot...")
        snapshot = {}
        scan_dirs = ['/var/www/html', '/home']
        for scan_dir in scan_dirs:
            exclude = "-not -path '*/upload/*' -not -path '*/uploads/*'" if 'home' in scan_dir else ''
            cmd = f"find {scan_dir} -type f {exclude} -exec md5sum {{}} \\; 2>/dev/null"
            output = self.ssh.execute(ip, int(port), cmd)
            if output and 'Error' not in output:
                for line in output.strip().split('\\n'):
                    line = line.strip()
                    if not line: continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        md5_hash, filepath = parts
                        snapshot[filepath] = md5_hash

        with self.ssh.lock:
            target['file_snapshot'] = snapshot
            target['snapshot_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
            self.ssh.save_targets()
        
        count = len(snapshot)
        print(f"[{ip}:{port}] Snapshot completed. Tracked {count} files.")
        return True, f'快照完成，共 {count} 个文件'

    def scan_backdoor(self, ip, port):
        target = next((t for t in self.ssh.targets if t['ip'] == ip and t['port'] == int(port)), None)
        if not target: 
             print(f"[{ip}:{port}] Backdoor scan failed: Target not found")
             return {'error': '靶机未找到'}

        print(f"[{ip}:{port}] Starting backdoor scan...")
        results = {
            'new_files': [], 'modified_files': [], 'deleted_files': [], 'backdoors': [],
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        }

        baseline = target.get('file_snapshot', {})
        current_files = {}
        scan_dirs = ['/var/www/html', '/home']
        for scan_dir in scan_dirs:
            exclude = "-not -path '*/upload/*' -not -path '*/uploads/*'" if 'home' in scan_dir else ''
            cmd = f"find {scan_dir} -type f {exclude} -exec md5sum {{}} \\; 2>/dev/null"
            output = self.ssh.execute(ip, int(port), cmd)
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
             print(f"[{ip}:{port}] No baseline found. Scanning all PHP/Python files.")
             suspect_files = [f for f in current_files.keys() if f.endswith(('.php', '.py', '.phtml', '.php5'))]

        print(f"[{ip}:{port}] Scanning content of {len(suspect_files)} suspect files...")
        for filepath in suspect_files[:50]:
            if not filepath.endswith(('.php', '.py', '.phtml', '.pht', '.php5', '.inc')): continue
            cmd = f"cat '{filepath}' 2>/dev/null"
            content = self.ssh.execute(ip, int(port), cmd)
            if content and 'Error' not in content:
                matches = self._match_backdoor_patterns(content)
                if matches:
                    print(f"[{ip}:{port}] FOUND BACKDOOR in {filepath}: {matches}")
                    results['backdoors'].append({
                        'file': filepath,
                        'matches': matches,
                        'is_new': filepath in results['new_files'],
                    })

        with self.ssh.lock:
            target['backdoor_scan'] = results
            self.ssh.save_targets()
        
        print(f"[{ip}:{port}] Backdoor scan finished. Found {len(results['backdoors'])} backdoors.")
        return results

    def _match_backdoor_patterns(self, content):
        matches = []
        for pattern, desc in self.BACKDOOR_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                matches.append(desc)
        return list(set(matches))
