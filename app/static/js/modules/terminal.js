// --- Multi-Tab Console Logic ---
const openTabs = new Set();
let activeTabKey = null;
const consoleCwd = {};

// WebSocket 连接（如果 Socket.IO 可用）
let wsSocket = null;
try {
    wsSocket = io();
    wsSocket.on('connected', (data) => console.log('WebSocket:', data.message));
    wsSocket.on('ws_output', (data) => {
        const key = data.ip + ':' + data.port;
        const safeKey = key.replace(/[:.]/g, '-');
        const output = document.getElementById('output-' + safeKey);
        if (output) {
            output.innerText += `\n${data.output}`;
            output.scrollTop = output.scrollHeight;
        }
        // 更新 cwd 提示符
        if (data.cwd) {
            consoleCwd[key] = data.cwd;
            const input = document.getElementById('input-' + safeKey);
            if (input) input.placeholder = data.cwd + '$ ';
        }
    });
    wsSocket.on('ws_output_wd', (data) => {
        const key = 'wd-' + data.ip + ':' + data.port;
        const safeKey = key.replace(/[:.]/g, '-');
        const output = document.getElementById('wd-output-' + safeKey);
        if (output) {
            output.innerText += `\n${data.output}`;
            output.scrollTop = output.scrollHeight;
        }
    });

    // Target Status Update handled in app.js or here?
    // Let's keep WebSocket init here but the listener logic depends on UI.
    // The target_update listener updates the main table, which is more 'app' level.
    // We will move target_update listener to app.js to avoid circular deps if any.
} catch (e) {
    console.warn('WebSocket 不可用，回退到 HTTP 模式');
}

function openConsoleTab(ip, port) {
    document.getElementById('console-section').style.display = 'block';
    const key = ip + ':' + port;

    if (openTabs.has(key)) {
        activateTab(key);
        return;
    }

    openTabs.add(key);

    // Create Tab Button
    const header = document.getElementById('tabs-header');
    const btn = document.createElement('div');
    btn.className = 'tab-btn';
    btn.id = 'tab-btn-' + key.replace(/[:.]/g, '-');
    btn.innerHTML = `<span>${key}</span> <span class="close-tab" onclick="closeTab(event, '${ip}', '${port}')">×</span>`;
    btn.onclick = () => activateTab(key);
    header.appendChild(btn);

    // Create Tab Content
    const container = document.getElementById('tabs-content-container');
    const content = document.createElement('div');
    content.className = 'tab-content';
    content.id = 'tab-content-' + key.replace(/[:.]/g, '-');
    content.innerHTML = `
    <div class="console-output" id="output-${key.replace(/[:.]/g, '-')}">Connecting to console... Ready.</div>
    <div class="console-input-area">
        <input type="text" class="console-input" id="input-${key.replace(/[:.]/g, '-')}" aria-label="Console Input" placeholder="Enter command..." onkeydown="if(event.key==='Enter') runConsoleCmd('${ip}', '${port}')">
        <button class="btn btn-primary" onclick="runConsoleCmd('${ip}', '${port}')">Run</button>
        <button class="btn btn-secondary btn-sm" onclick="openFileManager('${ip}', '${port}')">📁 Files</button>
    </div>
    <div class="flex-row">
        <input type="file" id="file-${key.replace(/[:.]/g, '-')}" aria-label="Upload File" class="console-input" style="width: 151px;">
        <input type="text" id="path-${key.replace(/[:.]/g, '-')}" aria-label="Remote Path" placeholder="Remote Path" class="console-input" style="width: 150px;">
        <button class="btn btn-secondary btn-sm" onclick="uploadConsoleFile('${ip}', '${port}')">Upload</button>
    </div>
`;
    container.appendChild(content);

    activateTab(key);
}

function closeTab(e, ip, port) {
    e.stopPropagation();
    const key = ip + ':' + port;
    const safeKey = key.replace(/[:.]/g, '-');

    openTabs.delete(key);
    document.getElementById('tab-btn-' + safeKey).remove();
    document.getElementById('tab-content-' + safeKey).remove();

    if (activeTabKey === key) {
        activeTabKey = null;
        if (openTabs.size > 0) {
            activateTab(openTabs.values().next().value);
        } else {
            document.getElementById('console-section').style.display = 'none';
        }
    }
}

function activateTab(key) {
    activeTabKey = key;
    const safeKey = key.replace(/[:.]/g, '-');

    // Update buttons
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    const btn = document.getElementById('tab-btn-' + safeKey);
    if (btn) btn.classList.add('active');

    // Update content
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    const content = document.getElementById('tab-content-' + safeKey);
    if (content) content.classList.add('active');
}

async function runConsoleCmd(ip, port) {
    const key = ip + ':' + port;
    const safeKey = key.replace(/[:.]/g, '-');
    const input = document.getElementById('input-' + safeKey);
    const output = document.getElementById('output-' + safeKey);
    const cmd = input.value;
    if (!cmd) return;

    const cwd = consoleCwd[key] || '~';
    output.innerText += `\n${cwd}$ ${cmd}`;
    input.value = '';
    output.scrollTop = output.scrollHeight;

    // 优先使用 WebSocket
    if (wsSocket && wsSocket.connected) {
        wsSocket.emit('ws_execute', { ip, port: parseInt(port), cmd });
    } else {
        const data = await apiCall('/api/execute_console', { ip, port, cmd });
        if (data) {
            output.innerText += `\n${data.output}`;
            output.scrollTop = output.scrollHeight;
            if (data.cwd) {
                consoleCwd[key] = data.cwd;
                input.placeholder = data.cwd + '$ ';
            }
        }
    }
}

async function uploadConsoleFile(ip, port) {
    const key = ip + ':' + port;
    const safeKey = key.replace(/[:.]/g, '-');

    const fileInput = document.getElementById('file-' + safeKey);
    const pathInput = document.getElementById('path-' + safeKey);

    if (!fileInput.files[0] || !pathInput.value) return showToast("File and Path required");

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('ip', ip);
    formData.append('port', port);
    formData.append('remote_path', pathInput.value);

    showToast("Uploading...");
    try {
        const res = await fetch('/api/upload', { method: 'POST', body: formData });
        const data = await res.json();
        showToast(data.message);
        if (data.success) {
            const output = document.getElementById('output-' + safeKey);
            output.innerText += `\n[System] Uploaded ${fileInput.files[0].name} to ${pathInput.value}`;
            output.scrollTop = output.scrollHeight;
        }
    } catch (e) { showToast("Upload failed"); }
}

// --- www-data 权限终端 ---
function openWwwdataTab(ip, port) {
    const key = 'wd-' + ip + ':' + port;
    document.getElementById('console-section').style.display = 'block';

    if (openTabs.has(key)) {
        activateTab(key);
        return;
    }
    openTabs.add(key);

    const header = document.getElementById('tabs-header');

    const btn = document.createElement('div');
    btn.className = 'tab-btn';
    btn.id = 'tab-btn-' + key.replace(/[:.]/g, '-');
    btn.innerHTML = `<span onclick="activateTab('${key}')">\uD83D\uDD36 ${ip}:${port} (www-data)</span><span class="close-tab" onclick="closeWdTab(event, '${ip}', '${port}')">&times;</span>`;
    header.appendChild(btn);

    // Tab content
    const container = document.getElementById('tabs-content-container');
    const content = document.createElement('div');
    content.className = 'tab-content';
    content.id = 'tab-content-' + key.replace(/[:.]/g, '-');
    content.innerHTML = `
    <pre id="wd-output-${key.replace(/[:.]/g, '-')}" style="background: #000; color: var(--warning-color); padding:10px; max-height:300px; overflow-y:auto; border: 1px solid var(--border-color); border-radius:4px; margin-bottom:10px; font-family: var(--font-mono, monospace);">www-data@${ip}:${port}$ (SUID bash via /tmp/mujica)</pre>
    <div class="flex-row">
        <input type="text" id="wd-input-${key.replace(/[:.]/g, '-')}" placeholder="www-data$ 命令..." style="flex-grow:1;" onkeydown="if(event.key==='Enter') runWwwdataCmd('${ip}','${port}')" class="console-input">
        <button class="btn btn-warning" onclick="runWwwdataCmd('${ip}','${port}')">Run</button>
    </div>
    `;
    container.appendChild(content);
    activateTab(key);
}

function closeWdTab(e, ip, port) {
    e.stopPropagation();
    const key = 'wd-' + ip + ':' + port;
    const safeKey = key.replace(/[:.]/g, '-');
    openTabs.delete(key);
    document.getElementById('tab-btn-' + safeKey).remove();
    document.getElementById('tab-content-' + safeKey).remove();
    if (activeTabKey === key) {
        activeTabKey = null;
        if (openTabs.size > 0) {
            activateTab(openTabs.values().next().value);
        } else {
            document.getElementById('console-section').style.display = 'none';
        }
    }
}

async function runWwwdataCmd(ip, port) {
    const key = 'wd-' + ip + ':' + port;
    const safeKey = key.replace(/[:.]/g, '-');
    const input = document.getElementById('wd-input-' + safeKey);
    const output = document.getElementById('wd-output-' + safeKey);
    const cmd = input.value;
    if (!cmd) return;

    output.innerText += `\nwww-data$ ${cmd}`;
    input.value = '';
    output.scrollTop = output.scrollHeight;

    if (wsSocket && wsSocket.connected) {
        wsSocket.emit('ws_execute_wwwdata', { ip, port: parseInt(port), cmd });
    } else {
        const data = await apiCall('/api/execute_wwwdata', { ip, port, cmd });
        if (data) {
            output.innerText += `\n${data.output}`;
            output.scrollTop = output.scrollHeight;
        }
    }
}
