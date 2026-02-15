// ==================== 远程文件管理器 ====================

let fmIp = null, fmPort = null, fmCurrentPath = '/';

async function openFileManager(ip, port) {
    fmIp = ip;
    fmPort = port;
    
    // Default fallback
    fmCurrentPath = '/var/www/html';
    try {
        const res = await fetch(`/api/files/default_path?ip=${ip}&port=${port}`);
        const data = await res.json();
        if (data.path) fmCurrentPath = data.path;
    } catch (e) {
        console.error("Failed to fetch default path", e);
    }

    const key = 'fm-' + ip + ':' + port;

    document.getElementById('console-section').style.display = 'block';
    if (openTabs.has(key)) {
        activateTab(key);
        // Also update the path input if switching back, maybe? 
        // Or just load the *saved* path for that tab? 
        // If tab exists, we probably shouldn't reset path unless user re-opened it explicitly to reset?
        // But openFileManager is called when clicking "Files" button.
        // Let's reload the dir.
        fmLoadDir(ip, port, fmCurrentPath);
        return;
    }
    openTabs.add(key);

    const header = document.getElementById('tabs-header');
    const btn = document.createElement('div');
    btn.className = 'tab-btn';
    btn.id = 'tab-btn-' + key.replace(/[:.]/g, '-');
    btn.innerHTML = `<span onclick="activateTab('${key}')">📁 ${ip}:${port}</span><span class="close-tab" onclick="closeFmTab(event, '${ip}', '${port}')">&times;</span>`;
    header.appendChild(btn);

    const container = document.getElementById('tabs-content-container');
    const content = document.createElement('div');
    content.className = 'tab-content';
    content.id = 'tab-content-' + key.replace(/[:.]/g, '-');

    content.innerHTML = `
        <div class="flex-row" style="margin-bottom: 10px; background: var(--card-bg); padding: 5px; border-radius: 4px; border: 1px solid var(--border-color);">
            <button class="btn btn-secondary btn-sm" onclick="fmGoUp('${ip}','${port}')">⬆️ Up</button>
            <button class="btn btn-secondary btn-sm" onclick="fmReload('${ip}','${port}')">🔄 Refresh</button>
            <input type="text" id="fm-path-${key.replace(/[:.]/g, '-')}" value="${fmCurrentPath}" style="flex-grow:1; margin: 0 10px;" onkeydown="if(event.key==='Enter') fmNavigate('${ip}','${port}')">
            <button class="btn btn-primary btn-sm" onclick="fmNavigate('${ip}','${port}')">Go</button>
            <span class="spacer"></span>
            <button class="btn btn-primary btn-sm" onclick="document.getElementById('fm-upload-${key.replace(/[:.]/g, '-')}').click()">📤 Upload File</button>
            <input type="file" id="fm-upload-${key.replace(/[:.]/g, '-')}" style="display:none;" onchange="fmUploadFile(this, '${ip}', '${port}')">
        </div>
        
        <div class="flex-row" style="margin-bottom: 10px; font-family: monospace; font-size: 14px;">
            <strong>Path:</strong>
            <div id="fm-breadcrumbs-${key.replace(/[:.]/g, '-')}" style="flex-grow: 1; margin-left: 10px;"></div>
        </div>

        <div style="flex-grow: 1; overflow-y: auto; border: 1px solid var(--border-color); border-radius: 4px; background: var(--card-bg);">
            <table id="fm-table-${key.replace(/[:.]/g, '-')}" style="font-size: 13px;">
                <thead>
                    <tr style="background: rgba(0,0,0,0.02);">
                        <th style="width: 30px;">T</th>
                        <th>Name</th>
                        <th style="width: 80px;">Size</th>
                        <th style="width: 100px;">Perms</th>
                        <th style="width: 150px;">Date</th>
                        <th style="width: 120px;">Actions</th>
                    </tr>
                </thead>
                <tbody><tr><td colspan="6" style="text-align:center;">Loading...</td></tr></tbody>
            </table>
        </div>

        <!-- Simple Editor Modal -->
        <div id="fm-editor-modal-${key.replace(/[:.]/g, '-')}" style="display:none; position:fixed; top:0; left:0; right:0; bottom:0; background:rgba(0,0,0,0.5); z-index:9999; align-items:center; justify-content:center;">
            <div style="background:var(--card-bg); width:80%; height:80%; border-radius:8px; display:flex; flex-direction:column; padding:20px; box-shadow:0 4px 12px rgba(0,0,0,0.2);">
                <div class="flex-row" style="margin-bottom:10px;">
                    <h3 style="margin:0;" id="fm-editor-title-${key.replace(/[:.]/g, '-')}">Edit</h3>
                    <span class="spacer"></span>
                    <button class="btn btn-primary" onclick="fmSaveFile('${ip}','${port}')">💾 Save</button>
                    <button class="btn btn-secondary" onclick="document.getElementById('fm-editor-modal-${key.replace(/[:.]/g, '-')}').style.display='none'">Close</button>
                </div>
                <textarea id="fm-editor-area-${key.replace(/[:.]/g, '-')}" style="flex-grow:1; font-family:'Consolas',monospace; resize:none; padding:10px; border:1px solid var(--border-color);"></textarea>
            </div>
        </div>
    `;
    container.appendChild(content);
    activateTab(key);
    fmLoadDir(ip, port, fmCurrentPath);
}


function closeFmTab(e, ip, port) {
    e.stopPropagation();
    const key = 'fm-' + ip + ':' + port;
    const safeKey = key.replace(/[:.]/g, '-');
    openTabs.delete(key);
    document.getElementById('tab-btn-' + safeKey).remove();
    document.getElementById('tab-content-' + safeKey).remove();
    if (activeTabKey === key) {
        activeTabKey = null;
        if (openTabs.size > 0) activateTab(openTabs.values().next().value);
        else document.getElementById('console-section').style.display = 'none';
    }
}

async function fmLoadDir(ip, port, path) {
    const key = 'fm-' + ip + ':' + port;
    const safeKey = key.replace(/[:.]/g, '-');
    const tbody = document.querySelector(`#fm-table-${safeKey} tbody`);
    const breadcrumbs = document.getElementById('fm-breadcrumbs-' + safeKey);

    fmCurrentPath = path;

    // Update Breadcrumbs
    const parts = path.split('/').filter(p => p);
    let bcHtml = `<span onclick="fmLoadDir('${ip}','${port}','/')" style="cursor:pointer;color:var(--primary-color);">/</span>`;
    let currentP = '';
    parts.forEach((p, i) => {
        currentP += '/' + p;
        bcHtml += ` / <span onclick="fmLoadDir('${ip}','${port}','${currentP}')" style="cursor:pointer;color:var(--primary-color);">${p}</span>`;
    });
    breadcrumbs.innerHTML = bcHtml;

    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">Loading...</td></tr>';

    const data = await apiCall('/api/files/list', { ip, port: parseInt(port), path });
    if (data && data.error) {
        tbody.innerHTML = `<tr><td colspan="6" style="color:var(--danger-color);text-align:center;">${data.error}</td></tr>`;
        return;
    }
    if (!data || !data.files) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#999;">Empty directory</td></tr>';
        return;
    }

    let html = '';
    const sorted = data.files.sort((a, b) => (b.is_dir - a.is_dir) || a.name.localeCompare(b.name));

    for (const f of sorted) {
        const icon = f.is_dir ? '📂' : (f.is_link ? '🔗' : '📄');
        const fullPath = path.replace(/\/$/, '') + '/' + f.name;
        const size = f.is_dir ? '-' : (f.size < 1024 ? f.size + ' B' : (f.size / 1024).toFixed(1) + ' KB');
        const date = new Date(f.mtime * 1000).toLocaleString();

        let actions = '';
        if (!f.is_dir) {
            actions += `<button class="btn btn-sm btn-primary" onclick="fmOpenFile('${ip}','${port}','${fullPath}')" title="Edit">✏️</button> `;
            actions += `<button class="btn btn-sm btn-success" onclick="fmDownloadFile('${ip}','${port}','${fullPath}')" title="Download">⬇️</button> `;
        } else {
            actions += `<button class="btn btn-sm btn-secondary" onclick="fmLoadDir('${ip}','${port}','${fullPath}')" title="Open">📂</button> `;
        }
        actions += `<button class="btn btn-sm btn-danger" onclick="fmDeleteFile('${ip}','${port}','${fullPath}')" title="Delete">🗑️</button>`;

        const rowClick = f.is_dir ? `fmLoadDir('${ip}','${port}','${fullPath}')` : '';
        const rowStyle = f.is_dir ? 'cursor:pointer; font-weight:500;' : '';

        html += `
            <tr>
                <td onclick="${rowClick}" style="${rowStyle}">${icon}</td>
                <td onclick="${rowClick}" style="${rowStyle}">${f.name}</td>
                <td>${size}</td>
                <td style="font-family:monospace;font-size:12px;">${f.perms || '-'}</td>
                <td style="font-size:12px;color:#666;">${date}</td>
                <td>${actions}</td>
            </tr>
        `;
    }
    tbody.innerHTML = html;
}

function fmNavigate(ip, port) {
    const key = 'fm-' + ip + ':' + port;
    const safeKey = key.replace(/[:.]/g, '-');
    const path = document.getElementById('fm-path-' + safeKey).value;
    fmLoadDir(ip, port, path);
}

function fmGoUp(ip, port) {
    const parent = fmCurrentPath.split('/').slice(0, -1).join('/') || '/';
    fmLoadDir(ip, port, parent);
}

function fmReload(ip, port) {
    fmLoadDir(ip, port, fmCurrentPath);
}

let currentEditPath = '';
function quickEditFile(ip, port, path) {
    openFileManager(ip, port);
    fmOpenFile(ip, port, path);
}

async function fmOpenFile(ip, port, path) {
    const key = 'fm-' + ip + ':' + port;
    const safeKey = key.replace(/[:.]/g, '-');
    currentEditPath = path;

    document.getElementById(`fm-editor-modal-${safeKey}`).style.display = 'flex';
    document.getElementById(`fm-editor-title-${safeKey}`).innerText = 'Editing: ' + path;
    const textarea = document.getElementById(`fm-editor-area-${safeKey}`);
    textarea.value = 'Loading...';

    const data = await apiCall('/api/files/read', { ip, port: parseInt(port), path });
    if (data && data.content !== undefined) {
        textarea.value = data.content;
    } else {
        textarea.value = 'Error reading file: ' + (data ? data.error : 'Unknown');
    }
}

async function fmSaveFile(ip, port) {
    const key = 'fm-' + ip + ':' + port;
    const safeKey = key.replace(/[:.]/g, '-');
    const content = document.getElementById(`fm-editor-area-${safeKey}`).value;

    showToast("Saving...");
    const data = await apiCall('/api/files/write', { ip, port: parseInt(port), path: currentEditPath, content });
    if (data && data.success) {
        showToast("Saved successfully");
        document.getElementById(`fm-editor-modal-${safeKey}`).style.display = 'none';
        fmReload(ip, port);
    } else {
        showToast("Error: " + (data ? data.message : 'Unknown'));
    }
}

async function fmDeleteFile(ip, port, path) {
    if (!confirm(`Delete ${path}?`)) return;
    const data = await apiCall('/api/files/delete', { ip, port: parseInt(port), path });
    if (data && data.success) {
        showToast("Deleted");
        fmReload(ip, port);
    } else {
        showToast("Error: " + (data ? data.message : 'Unknown'));
    }
}

function fmDownloadFile(ip, port, path) {
    window.location.href = `/api/files/download?ip=${ip}&port=${port}&path=${encodeURIComponent(path)}`;
}

async function fmUploadFile(input, ip, port) {
    if (input.files.length === 0) return;
    const file = input.files[0];
    const formData = new FormData();
    formData.append('file', file);
    formData.append('ip', ip);
    formData.append('port', port);
    formData.append('path', fmCurrentPath);

    showToast("Uploading " + file.name + "...");
    try {
        const res = await fetch('/api/files/upload', {
            method: 'POST',
            body: formData
        });
        const data = await res.json();
        if (data.success) {
            showToast("Upload success");
            fmReload(ip, port);
        } else {
            showToast("Upload failed: " + data.error);
        }
    } catch (e) {
        showToast("Upload error: " + e);
    }
    input.value = ''; // clear
}
