import os
import paramiko
import threading
import json
import stat
import time
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)

# 配置路径
# 修改为当前文件所在目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['KEYS_FOLDER'] = os.path.join(BASE_DIR, 'keys')
app.config['PRELOAD_FOLDER'] = os.path.join(BASE_DIR, 'preload')
app.config['CONFIG_FILE'] = os.path.join(BASE_DIR, 'preload_config.json')
app.config['TARGETS_FILE'] = os.path.join(BASE_DIR, 'targets.json')

# 确保目录存在
for folder in [app.config['UPLOAD_FOLDER'], app.config['KEYS_FOLDER'], app.config['PRELOAD_FOLDER']]:
    if not os.path.exists(folder):
        os.makedirs(folder)

class SSHController:
    def __init__(self):
        self.sessions = {}  # ip -> client
        self.targets = []   # List of dicts
        self.lock = threading.Lock()
        self.preload_config = self.load_preload_config()
        self.load_targets()

    def load_preload_config(self):
        if os.path.exists(app.config['CONFIG_FILE']):
            try:
                with open(app.config['CONFIG_FILE'], 'r') as f:
                    return json.load(f)
            except:
                pass
        return {'files': [], 'commands': []}

    def save_preload_config(self):
        with open(app.config['CONFIG_FILE'], 'w') as f:
            json.dump(self.preload_config, f, indent=4)

    def load_targets(self):
        """从文件加载靶机列表"""
        if os.path.exists(app.config['TARGETS_FILE']):
            try:
                with open(app.config['TARGETS_FILE'], 'r') as f:
                    loaded = json.load(f)
                    self.targets = []
                    if isinstance(loaded, list):
                        for t in loaded:
                            # 确保数据有效性
                            if not isinstance(t, dict) or 'ip' not in t:
                                continue
                            # 确保加载时去除空格
                            t['ip'] = str(t['ip']).strip()
                            t['status'] = 'disconnected'
                            self.targets.append(t)
                print(f"Loaded {len(self.targets)} targets from {app.config['TARGETS_FILE']}")
            except Exception as e:
                print(f"Error loading targets: {e}")
                self.targets = []

    def save_targets(self):
        """保存靶机列表到文件"""
        try:
            with open(app.config['TARGETS_FILE'], 'w') as f:
                # 保存时只保留配置信息，不保存状态
                targets_to_save = []
                for t in self.targets:
                    targets_to_save.append({
                        'ip': t['ip'],
                        'port': t['port'],
                        'user': t['user'],
                        'password': t.get('password'),
                        'key_path': t.get('key_path')
                    })
                json.dump(targets_to_save, f, indent=4)
            print(f"Targets saved successfully to {app.config['TARGETS_FILE']}")
        except Exception as e:
            print(f"Error saving targets: {e}")

    def add_target(self, ip, port=22, user='root', password=None, key_path=None):
        if not ip:
            return
        ip = ip.strip()
        with self.lock:
            for t in self.targets:
                if t['ip'] == ip:
                    return
            self.targets.append({
                'ip': ip,
                'port': int(port),
                'user': user,
                'password': password,
                'key_path': key_path,
                'status': 'disconnected'
            })
            self.save_targets()

    def remove_target(self, ip):
        """移除靶机"""
        if not ip:
            return False
        ip = ip.strip()
        print(f"Attempting to remove target: '{ip}'")
        with self.lock:
            self.disconnect(ip)
            
            original_len = len(self.targets)
            self.targets = [t for t in self.targets if t['ip'] != ip]
            
            if len(self.targets) < original_len:
                print(f"Target {ip} removed from memory list. Saving to file...")
                self.save_targets()
                return True
            else:
                print(f"Target {ip} not found in list. Available: {[t['ip'] for t in self.targets]}")
                return False

    def get_available_keys(self):
        keys = []
        if os.path.exists(app.config['KEYS_FOLDER']):
            for f in os.listdir(app.config['KEYS_FOLDER']):
                path = os.path.join(app.config['KEYS_FOLDER'], f)
                if os.path.isfile(path):
                    keys.append(path)
        return keys

    def connect(self, ip):
        ip = ip.strip()
        target = next((t for t in self.targets if t['ip'] == ip), None)
        if not target:
            return False, "Target not found"

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            connected = False
            # 1. 尝试指定密钥
            if target.get('key_path') and os.path.exists(target['key_path']):
                client.connect(ip, port=target['port'], username=target['user'], key_filename=target['key_path'], timeout=5)
                connected = True
            
            # 2. 尝试密码
            elif target.get('password'):
                client.connect(ip, port=target['port'], username=target['user'], password=target['password'], timeout=5)
                connected = True

            # 3. 尝试匹配目录下的所有密钥
            else:
                keys = self.get_available_keys()
                keys.sort(key=lambda k: 0 if ip in k else 1)
                for key in keys:
                    try:
                        client.connect(ip, port=target['port'], username=target['user'], key_filename=key, timeout=5)
                        target['key_path'] = key
                        connected = True
                        break
                    except:
                        continue
            
            if connected:
                self.sessions[ip] = client
                target['status'] = 'connected'
                self.save_targets() # 更新 key_path
                # 执行预设任务
                threading.Thread(target=self.run_preload_tasks, args=(ip,)).start()
                return True, "Connected successfully. Preload tasks started."
            
            return False, "Authentication failed"

        except Exception as e:
            target['status'] = 'error'
            return False, str(e)

    def disconnect(self, ip):
        """断开连接"""
        ip = ip.strip()
        target = next((t for t in self.targets if t['ip'] == ip), None)
        if ip in self.sessions:
            try:
                self.sessions[ip].close()
            except:
                pass
            del self.sessions[ip]
        
        if target:
            target['status'] = 'disconnected'
        return True, "Disconnected"

    def run_preload_tasks(self, ip):
        """执行预设的文件上传和命令"""
        print(f"[{ip}] Starting preload tasks...")
        
        # 1. 上传文件
        for file_item in self.preload_config.get('files', []):
            local_path = os.path.join(app.config['PRELOAD_FOLDER'], file_item['filename'])
            if os.path.exists(local_path):
                self.upload(ip, local_path, file_item['remote_path'])
                print(f"[{ip}] Uploaded {file_item['filename']}")

        # 2. 执行命令
        for cmd in self.preload_config.get('commands', []):
            time.sleep(0.5)
            output = self.execute(ip, cmd)
            print(f"[{ip}] Executed: {cmd}\nOutput: {output.strip()}")

    def execute(self, ip, cmd):
        ip = ip.strip()
        if ip not in self.sessions:
            return "Not connected"
        try:
            transport = self.sessions[ip].get_transport()
            if not transport or not transport.is_active():
                self.connect(ip)
            
            stdin, stdout, stderr = self.sessions[ip].exec_command(cmd, timeout=10)
            return stdout.read().decode() + stderr.read().decode()
        except Exception as e:
            return f"Error: {str(e)}"

    def upload(self, ip, local_path, remote_path):
        ip = ip.strip()
        if ip not in self.sessions:
            return False, "Not connected"
        try:
            sftp = self.sessions[ip].open_sftp()
            
            target_path = remote_path
            is_directory = False
            
            if target_path.endswith('/'):
                is_directory = True
            else:
                try:
                    attr = sftp.stat(target_path)
                    if stat.S_ISDIR(attr.st_mode):
                        is_directory = True
                except:
                    pass
            
            if is_directory:
                filename = os.path.basename(local_path)
                if not target_path.endswith('/'):
                    target_path += '/'
                target_path += filename
                
            sftp.put(local_path, target_path)
            sftp.close()
            return True, f"Success: {target_path}"
        except Exception as e:
            return False, str(e)

controller = SSHController()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWD Controller</title>
    <style>
        :root {
            --bg-color: #f4f6f8;
            --text-color: #2c3e50;
            --card-bg: #ffffff;
            --border-color: #dfe3e8;
            --primary-color: #3498db;
            --danger-color: #e74c3c;
            --success-color: #2ecc71;
            --warning-color: #f1c40f;
            --console-bg: #2d3436;
            --console-text: #f1f2f6;
            --shadow: 0 2px 4px rgba(0,0,0,0.05);
        }

        [data-theme="dark"] {
            --bg-color: #1a1a1a;
            --text-color: #ecf0f1;
            --card-bg: #2d2d2d;
            --border-color: #404040;
            --primary-color: #3498db;
            --danger-color: #e74c3c;
            --success-color: #2ecc71;
            --warning-color: #f1c40f;
            --console-bg: #000000;
            --console-text: #00ff00;
            --shadow: 0 2px 4px rgba(0,0,0,0.3);
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 0;
            transition: background-color 0.3s, color 0.3s;
        }

        .header {
            background-color: var(--card-bg);
            padding: 15px 30px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: var(--shadow);
        }

        .header h1 { margin: 0; font-size: 20px; font-weight: 600; }

        .container { padding: 20px; max-width: 1600px; margin: 0 auto; }

        .card {
            background-color: var(--card-bg);
            border-radius: 8px;
            border: 1px solid var(--border-color);
            margin-bottom: 20px;
            box-shadow: var(--shadow);
            overflow: hidden;
        }

        details { width: 100%; }
        summary {
            padding: 15px;
            cursor: pointer;
            font-weight: 600;
            background-color: rgba(0,0,0,0.02);
            border-bottom: 1px solid var(--border-color);
            outline: none;
            user-select: none;
        }
        summary:hover { background-color: rgba(0,0,0,0.04); }
        
        .card-content { padding: 20px; }

        /* Tables */
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid var(--border-color); }
        th { font-weight: 600; color: var(--text-color); opacity: 0.8; }
        
        /* Inputs & Buttons */
        input[type="text"], input[type="password"], input[type="file"] {
            padding: 8px 12px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background-color: var(--bg-color);
            color: var(--text-color);
            outline: none;
        }
        
        .btn {
            padding: 8px 16px;
            border-radius: 4px;
            border: none;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            transition: opacity 0.2s;
            color: white;
        }
        .btn:hover { opacity: 0.9; }
        .btn-primary { background-color: var(--primary-color); }
        .btn-danger { background-color: var(--danger-color); }
        .btn-warning { background-color: var(--warning-color); color: #333; }
        .btn-secondary { background-color: #95a5a6; }
        .btn-sm { padding: 4px 8px; font-size: 12px; }

        /* Tabs */
        .tabs-header {
            display: flex;
            background-color: var(--card-bg);
            border-bottom: 1px solid var(--border-color);
            overflow-x: auto;
        }
        .tab-btn {
            padding: 12px 20px;
            cursor: pointer;
            border-right: 1px solid var(--border-color);
            background: transparent;
            color: var(--text-color);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .tab-btn.active {
            background-color: var(--bg-color);
            border-bottom: 2px solid var(--primary-color);
            font-weight: 600;
        }
        .tab-btn:hover:not(.active) { background-color: rgba(0,0,0,0.02); }
        .close-tab { margin-left: 8px; opacity: 0.5; cursor: pointer; }
        .close-tab:hover { opacity: 1; color: var(--danger-color); }

        .tab-content { display: none; padding: 20px; background-color: var(--bg-color); height: 600px; flex-direction: column; }
        .tab-content.active { display: flex; }

        .console-output {
            flex-grow: 1;
            background-color: var(--console-bg);
            color: var(--console-text);
            font-family: 'Consolas', monospace;
            padding: 15px;
            border-radius: 4px;
            overflow-y: auto;
            margin-bottom: 15px;
            white-space: pre-wrap;
            font-size: 13px;
        }

        .console-input-area { display: flex; gap: 10px; margin-bottom: 10px; }
        .console-input { flex-grow: 1; font-family: monospace; }

        .flex-row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .spacer { flex-grow: 1; }

        /* Toast */
        #toast {
            visibility: hidden;
            min-width: 250px;
            background-color: #333;
            color: #fff;
            text-align: center;
            border-radius: 4px;
            padding: 12px;
            position: fixed;
            z-index: 1000;
            left: 50%;
            transform: translateX(-50%);
            bottom: 30px;
            font-size: 14px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        #toast.show { visibility: visible; animation: fadein 0.5s, fadeout 0.5s 2.5s; }
        
        @keyframes fadein { from {bottom: 0; opacity: 0;} to {bottom: 30px; opacity: 1;} }
        @keyframes fadeout { from {bottom: 30px; opacity: 1;} to {bottom: 0; opacity: 0;} }
    </style>
</head>
<body>

<div class="header">
    <h1>AWD Controller</h1>
    <div class="flex-row">
        <button class="btn btn-secondary" onclick="toggleTheme()">🌓 Theme</button>
    </div>
</div>

<div class="container">
    
    <!-- Config & Targets Section (Collapsible) -->
    <div class="card">
        <details open>
            <summary>⚙️ Configuration & Targets</summary>
            <div class="card-content">
                
                <!-- Preload Config -->
                <div style="margin-bottom: 30px;">
                    <h4 style="margin-top: 0;">Preload Tasks (Auto-run on Connect)</h4>
                    <div class="flex-row" style="margin-bottom: 10px;">
                        <input type="file" id="preload-file" style="width: 200px;">
                        <input type="text" id="preload-path" placeholder="Remote Path" style="width: 200px;">
                        <button class="btn btn-primary btn-sm" onclick="addPreloadFile()">Add File</button>
                        <div style="width: 20px;"></div>
                        <input type="text" id="preload-cmd" placeholder="Command" style="flex-grow: 1;">
                        <button class="btn btn-primary btn-sm" onclick="addPreloadCmd()">Add Cmd</button>
                    </div>
                    
                    <div style="max-height: 150px; overflow-y: auto; border: 1px solid var(--border-color); padding: 10px; border-radius: 4px;">
                        {% for f in preload.files %}
                        <div class="flex-row" style="margin-bottom: 5px; font-size: 12px;">
                            <span>📄 {{ f.filename }} &rarr; {{ f.remote_path }}</span>
                            <span class="spacer"></span>
                            <button class="btn btn-danger btn-sm" onclick="removePreload('file', {{ loop.index0 }})">×</button>
                        </div>
                        {% endfor %}
                        {% for cmd in preload.commands %}
                        <div class="flex-row" style="margin-bottom: 5px; font-size: 12px;">
                            <span>💻 {{ cmd }}</span>
                            <span class="spacer"></span>
                            <button class="btn btn-danger btn-sm" onclick="removePreload('cmd', {{ loop.index0 }})">×</button>
                        </div>
                        {% endfor %}
                    </div>
                </div>

                <hr style="border: 0; border-top: 1px solid var(--border-color); margin: 20px 0;">

                <!-- Add Target -->
                <form action="/add_target" method="post" class="flex-row" style="margin-bottom: 20px;">
                    <input type="text" name="ip" placeholder="IP Address" required>
                    <input type="text" name="port" placeholder="Port" value="22" style="width: 60px;">
                    <input type="text" name="user" placeholder="User" value="root" style="width: 80px;">
                    <input type="password" name="password" placeholder="Password">
                    <button type="submit" class="btn btn-primary">Add Target</button>
                </form>

                <!-- Target List -->
                <table>
                    <thead>
                        <tr>
                            <th>IP</th>
                            <th>User</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for t in targets %}
                        <tr>
                            <td>{{ t.ip }}</td>
                            <td>{{ t.user }}</td>
                            <td style="color: {{ 'var(--success-color)' if t.status == 'connected' else 'var(--text-color)' }}">
                                {{ t.status }}
                            </td>
                            <td>
                                {% if t.status == 'connected' %}
                                    <button class="btn btn-secondary btn-sm" onclick="disconnect('{{ t.ip }}')">Disconnect</button>
                                {% else %}
                                    <button class="btn btn-primary btn-sm" onclick="connect('{{ t.ip }}')">Connect</button>
                                {% endif %}
                                <button class="btn btn-success btn-sm" onclick="openConsoleTab('{{ t.ip }}')">Console</button>
                                <button class="btn btn-warning btn-sm" onclick="openXshell('{{ t.ip }}', '{{ t.port }}', '{{ t.user }}', '{{ t.password }}')">Xshell</button>
                                <button class="btn btn-danger btn-sm" onclick="removeTarget('{{ t.ip }}')">Del</button>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </details>
    </div>

    <!-- Multi-Tab Console Section -->
    <div class="card" id="console-section" style="display: none;">
        <div class="tabs-header" id="tabs-header">
            <!-- Tabs will be injected here -->
        </div>
        <div id="tabs-content-container">
            <!-- Tab contents will be injected here -->
        </div>
    </div>

</div>

<div id="toast"></div>

<script>
    // Theme Logic
    function toggleTheme() {
        const html = document.documentElement;
        const current = html.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', next);
        localStorage.setItem('theme', next);
    }
    
    // Init Theme
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);

    // Toast Logic
    function showToast(msg) {
        const t = document.getElementById('toast');
        t.innerText = msg;
        t.className = 'show';
        setTimeout(() => t.className = t.className.replace('show', ''), 3000);
    }

    // --- API Calls ---
    async function apiCall(url, data) {
        try {
            const res = await fetch(url, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            });
            return await res.json();
        } catch (e) {
            showToast("Error: " + e);
            return null;
        }
    }

    async function connect(ip) {
        showToast("Connecting to " + ip + "...");
        const data = await apiCall('/api/connect', {ip});
        if(data) {
            showToast(data.message);
            if(data.success) setTimeout(() => location.reload(), 500);
        }
    }

    async function disconnect(ip) {
        const data = await apiCall('/api/disconnect', {ip});
        if(data) {
            showToast(data.message);
            setTimeout(() => location.reload(), 500);
        }
    }

    async function removeTarget(ip) {
        if(!confirm('Remove target ' + ip + '?')) return;
        const data = await apiCall('/api/remove_target', {ip});
        if(data && data.status === 'ok') {
            showToast("Removed");
            setTimeout(() => location.reload(), 500);
        }
    }

    // --- Preload Logic ---
    async function addPreloadFile() {
        const fileInput = document.getElementById('preload-file');
        const pathInput = document.getElementById('preload-path');
        if(!fileInput.files[0] || !pathInput.value) return showToast("File and Path required");
        
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('remote_path', pathInput.value);
        
        try {
            const res = await fetch('/api/preload/add_file', {method: 'POST', body: formData});
            if(res.ok) location.reload();
        } catch(e) { showToast("Error uploading"); }
    }

    async function addPreloadCmd() {
        const cmd = document.getElementById('preload-cmd').value;
        if(!cmd) return;
        const data = await apiCall('/api/preload/add_cmd', {cmd});
        if(data && data.status === 'ok') location.reload();
    }

    async function removePreload(type, index) {
        if(!confirm('Remove?')) return;
        const data = await apiCall('/api/preload/remove', {type, index});
        if(data && data.status === 'ok') location.reload();
    }

    function openXshell(ip, port, user, password) {
        apiCall('/api/open_xshell', {ip, port, user, password}).then(d => {
            if(d) showToast(d.message);
        });
    }

    // --- Multi-Tab Console Logic ---
    const openTabs = new Set();
    let activeTabIp = null;

    function openConsoleTab(ip) {
        document.getElementById('console-section').style.display = 'block';
        
        if (openTabs.has(ip)) {
            activateTab(ip);
            return;
        }

        openTabs.add(ip);
        
        // Create Tab Button
        const header = document.getElementById('tabs-header');
        const btn = document.createElement('div');
        btn.className = 'tab-btn';
        btn.id = 'tab-btn-' + ip;
        btn.innerHTML = `<span>${ip}</span> <span class="close-tab" onclick="closeTab(event, '${ip}')">×</span>`;
        btn.onclick = () => activateTab(ip);
        header.appendChild(btn);

        // Create Tab Content
        const container = document.getElementById('tabs-content-container');
        const content = document.createElement('div');
        content.className = 'tab-content';
        content.id = 'tab-content-' + ip;
        content.innerHTML = `
            <div class="console-output" id="output-${ip}">Connecting to console... Ready.</div>
            <div class="console-input-area">
                <input type="text" class="console-input" id="input-${ip}" placeholder="Enter command..." onkeydown="if(event.key==='Enter') runConsoleCmd('${ip}')">
                <button class="btn btn-primary" onclick="runConsoleCmd('${ip}')">Run</button>
            </div>
            <div class="flex-row">
                <input type="file" id="file-${ip}" style="width: 200px;">
                <input type="text" id="path-${ip}" placeholder="Remote Path" style="width: 200px;">
                <button class="btn btn-secondary btn-sm" onclick="uploadConsoleFile('${ip}')">Upload</button>
            </div>
        `;
        container.appendChild(content);

        activateTab(ip);
    }

    function closeTab(e, ip) {
        e.stopPropagation();
        openTabs.delete(ip);
        document.getElementById('tab-btn-' + ip).remove();
        document.getElementById('tab-content-' + ip).remove();
        
        if (activeTabIp === ip) {
            activeTabIp = null;
            // Switch to another tab if exists
            if (openTabs.size > 0) {
                activateTab(openTabs.values().next().value);
            } else {
                document.getElementById('console-section').style.display = 'none';
            }
        }
    }

    function activateTab(ip) {
        activeTabIp = ip;
        
        // Update buttons
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.getElementById('tab-btn-' + ip).classList.add('active');

        // Update content
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        document.getElementById('tab-content-' + ip).classList.add('active');
    }

    async function runConsoleCmd(ip) {
        const input = document.getElementById('input-' + ip);
        const output = document.getElementById('output-' + ip);
        const cmd = input.value;
        if(!cmd) return;

        output.innerText += `\n> ${cmd}`;
        input.value = '';
        output.scrollTop = output.scrollHeight;

        const data = await apiCall('/api/execute', {ip, cmd});
        if(data) {
            output.innerText += `\n${data.output}`;
            output.scrollTop = output.scrollHeight;
        }
    }

    async function uploadConsoleFile(ip) {
        const fileInput = document.getElementById('file-' + ip);
        const pathInput = document.getElementById('path-' + ip);
        
        if(!fileInput.files[0] || !pathInput.value) return showToast("File and Path required");

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('ip', ip);
        formData.append('remote_path', pathInput.value);

        showToast("Uploading...");
        try {
            const res = await fetch('/api/upload', {method: 'POST', body: formData});
            const data = await res.json();
            showToast(data.message);
            if(data.success) {
                const output = document.getElementById('output-' + ip);
                output.innerText += `\n[System] Uploaded ${fileInput.files[0].name} to ${pathInput.value}`;
                output.scrollTop = output.scrollHeight;
            }
        } catch(e) { showToast("Upload failed"); }
    }

</script>
</body>
</html>
"""

@app.route('/')
def index():
    connected = sum(1 for t in controller.targets if t['status'] == 'connected')
    return render_template_string(HTML_TEMPLATE, 
                                targets=controller.targets,
                                connected_count=connected,
                                total_count=len(controller.targets),
                                preload=controller.preload_config)

@app.route('/add_target', methods=['POST'])
def add_target():
    controller.add_target(
        request.form['ip'],
        request.form.get('port', 22),
        request.form.get('user', 'root'),
        request.form.get('password'),
        None
    )
    return redirect(url_for('index'))

@app.route('/api/remove_target', methods=['POST'])
def remove_target():
    data = request.json
    success = controller.remove_target(data['ip'])
    if success:
        return jsonify({'status': 'ok'})
    else:
        return jsonify({'status': 'error', 'message': 'Target not found'}), 404

@app.route('/api/connect', methods=['POST'])
def api_connect():
    data = request.json
    success, msg = controller.connect(data['ip'])
    return jsonify({'success': success, 'message': msg})

@app.route('/api/disconnect', methods=['POST'])
def api_disconnect():
    data = request.json
    success, msg = controller.disconnect(data['ip'])
    return jsonify({'success': success, 'message': msg})

@app.route('/api/execute', methods=['POST'])
def api_execute():
    data = request.json
    output = controller.execute(data['ip'], data['cmd'])
    return jsonify({'output': output})

@app.route('/api/upload', methods=['POST'])
def api_upload():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'})
    
    file = request.files['file']
    ip = request.form['ip']
    remote_path = request.form['remote_path']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'})
        
    filename = secure_filename(file.filename)
    local_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(local_path)
    
    success, msg = controller.upload(ip, local_path, remote_path)
    return jsonify({'success': success, 'message': msg})

# 预设任务 API
@app.route('/api/preload/add_file', methods=['POST'])
def add_preload_file():
    file = request.files['file']
    remote_path = request.form['remote_path']
    
    filename = secure_filename(file.filename)
    local_path = os.path.join(app.config['PRELOAD_FOLDER'], filename)
    file.save(local_path)
    
    controller.preload_config['files'].append({
        'filename': filename,
        'remote_path': remote_path
    })
    controller.save_preload_config()
    return jsonify({'status': 'ok'})

@app.route('/api/preload/add_cmd', methods=['POST'])
def add_preload_cmd():
    cmd = request.json['cmd']
    controller.preload_config['commands'].append(cmd)
    controller.save_preload_config()
    return jsonify({'status': 'ok'})

@app.route('/api/preload/remove', methods=['POST'])
def remove_preload():
    data = request.json
    idx = data['index']
    if data['type'] == 'file':
        controller.preload_config['files'].pop(idx)
    elif data['type'] == 'cmd':
        controller.preload_config['commands'].pop(idx)
    
    controller.save_preload_config()
    return jsonify({'status': 'ok'})

@app.route('/api/open_xshell', methods=['POST'])
def open_xshell():
    import subprocess
    data = request.json
    ip = data.get('ip')
    port = data.get('port', 22)
    user = data.get('user', 'root')
    password = data.get('password', '')
    
    xshell_path = r"E:\xshell8\Xshell.exe" #不要修改
    if not os.path.exists(xshell_path):
        xshell_path = r"C:\Program Files\NetSarang\Xshell 7\Xshell.exe"
    
    if not os.path.exists(xshell_path):
        return jsonify({'success': False, 'message': 'Xshell executable not found. Please configure path.'})

    try:
        if password:
            cmd = f'"{xshell_path}" -url ssh://{user}:{password}@{ip}:{port}'
        else:
            cmd = f'"{xshell_path}" -url ssh://{user}@{ip}:{port}'
            
        subprocess.Popen(cmd, shell=True)
        return jsonify({'success': True, 'message': 'Xshell started'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    print("AWD 控制台启动中...")
    print(f"请访问: http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
