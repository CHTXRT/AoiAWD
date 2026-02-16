// --- Defense Module (Preload, Scheduled Tasks, AOI) ---

// --- Preload Logic ---
async function addPreloadFile() {
    const fileInput = document.getElementById('preload-file');
    const pathInput = document.getElementById('preload-path');
    if (!fileInput.files[0] || !pathInput.value) return showToast("File and Path required");

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('remote_path', pathInput.value);

    try {
        const res = await fetch('/api/preload/add_file', { method: 'POST', body: formData });
        if (res.ok) location.reload();
    } catch (e) { showToast("Error uploading"); }
}

async function addPreloadCmd() {
    const cmd = document.getElementById('preload-cmd').value;
    if (!cmd) return;
    const data = await apiCall('/api/preload/add_cmd', { cmd });
    if (data && data.status === 'ok') location.reload();
}

async function removePreload(type, index) {
    index = parseInt(index);
    if (!confirm('Remove?')) return;
    const data = await apiCall('/api/preload/remove', { type, index });
    if (data && data.status === 'ok') location.reload();
}

async function rerunPreload(ip, port) {
    if (!confirm('Rerun preload tasks for ' + ip + ':' + port + '?')) return;
    showToast("Queueing preload tasks...");
    const data = await apiCall('/api/rerun_preload', { ip, port });
    if (data) showToast(data.message);
}

// --- Schedule Tasks ---
async function loadScheduledTasks() {
    try {
        const res = await fetch('/api/scheduled_tasks');
        const data = await res.json();
        const container = document.getElementById('scheduled-tasks-list');
        const tasks = data.tasks || {};
        const entries = Object.entries(tasks);
        if (entries.length === 0) {
            container.innerHTML = '<span style="color: #999;">暂无定时任务</span>';
            return;
        }
        container.innerHTML = entries.map(([name, task]) => `
            <div class="flex-row" style="margin-bottom: 5px;">
                <span>⏰ <strong>${name}</strong> → ${task.cmd} (每 ${task.interval}s)</span>
                <span class="spacer"></span>
                <button class="btn btn-danger btn-sm" onclick="removeScheduledTask('${name}')">×</button>
            </div>
        `).join('');
    } catch (e) {
        console.error('加载定时任务失败', e);
    }
}

async function addScheduledTask() {
    const name = document.getElementById('task-name').value;
    const cmd = document.getElementById('task-cmd').value;
    const interval = parseInt(document.getElementById('task-interval').value) || 300;
    if (!name || !cmd) return showToast('请填写任务名称和命令');
    const data = await apiCall('/api/scheduled_task/add', { name, cmd, interval });
    if (data) {
        showToast(data.message || '已添加');
        document.getElementById('task-name').value = '';
        document.getElementById('task-cmd').value = '';
        loadScheduledTasks();
    }
}

async function removeScheduledTask(name) {
    if (!confirm('移除定时任务 "' + name + '"?')) return;
    const data = await apiCall('/api/scheduled_task/remove', { name });
    if (data) {
        showToast(data.message || '已移除');
        loadScheduledTasks();
    }
}

// --- AOI Tools ---
async function saveLocalIp() {
    const ip = document.getElementById('local-ip-input').value.trim();
    const status = document.getElementById('local-ip-status');
    const data = await apiCall('/api/local_ip', { ip });
    if (data && data.status === 'ok') {
        status.innerHTML = '<span style="color:var(--success-color);">✅ 已保存</span>';
        showToast('本机 IP 已保存: ' + ip);
        setTimeout(() => status.innerHTML = '', 3000);
    }
}

async function deployAoi(ip, port) {
    if (!confirm('部署 AOI 工具到 ' + ip + ':' + port + '?')) return;
    showToast('AOI 部署已启动...');
    await apiCall('/api/deploy_aoi', { ip, port });
}

// --- Backups & Scans ---
async function rerunBackup(ip, port) {
    if (!confirm('重新备份 ' + ip + ':' + port + '?')) return;
    showToast("备份任务已启动...");
    const data = await apiCall('/api/rerun_backup', { ip, port });
    if (data) showToast(data.message);
}

async function snapshotFiles(ip, port) {
    if (!confirm('为 ' + ip + ':' + port + ' 建立文件快照基线？\n这将记录当前所有文件的 MD5，用于后续对比。')) return;
    showToast('正在建立快照...');
    const data = await apiCall('/api/snapshot', { ip, port });
    if (data) showToast(data.message);
}

async function scanBackdoor(ip, port) {
    showToast('正在扫描后门...');
    const data = await apiCall('/api/scan_backdoor', { ip, port });
    if (data) {
        showToast(data.message);
    }
}

async function restoreBackup(ip, port) {
    if (!confirm('⚠️ 确定要还原 ' + ip + ':' + port + ' 的备份吗？\n此操作将覆盖靶机上的当前文件！')) return;
    showToast('正在还原备份...');
    const data = await apiCall('/api/restore_backup', { ip, port });
    if (data) showToast(data.message);
}

// --- Persistent Killers UI ---
async function loadActiveKillers() {
    const tbody = document.getElementById('active-killers-tbody');
    if (!tbody) return;

    try {
        const res = await fetch('/api/defense/immortal/killers');
        const data = await res.json();
        const killers = data.killers || [];

        if (killers.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px; color:#999;">暂无正在运行的查杀任务</td></tr>';
            return;
        }

        tbody.innerHTML = killers.map(k => `
            <tr>
                <td style="padding:8px; border-bottom:1px solid var(--border-color);">${k.ip}:${k.port}</td>
                <td style="padding:8px; border-bottom:1px solid var(--border-color); font-family:monospace; color:#e74c3c;">${k.file}</td>
                <td style="padding:8px; border-bottom:1px solid var(--border-color);">
                    <span class="badge" style="background:var(--success-color); animation: pulse-red 2s infinite;">RUNNING</span>
                </td>
                <td style="padding:8px; border-bottom:1px solid var(--border-color);">
                    <button class="btn btn-sm btn-danger" onclick="togglePersistentKill('${k.ip}', '${k.port}', '${k.file.replace(/\\/g, '\\\\')}', this)">🛑 停止</button>
                </td>
            </tr>
        `).join('');

    } catch (e) {
        console.error('加载查杀列表失败', e);
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px; color:var(--danger-color);">加载失败</td></tr>';
    }
}

// Auto load on init if function exists
document.addEventListener('DOMContentLoaded', () => {
    if (typeof loadActiveKillers === 'function') loadActiveKillers();
});

// --- Monitor Logic (PyGuard/ShellGuard) ---
// const monitorSocket = io(); // Already have socket from app.js or global? 
// In defense.js we might need to use the global socket or init a new one.
// Let's assume 'socket' is available from app.js or init one. 
// However, in module based JS, scope is tricky.
// Let's us `io()` again or checking if a global socket exists.
// Based on index.html, socket.io.min.js is included.

var monitorSocket = io();
var monitorAlertCount = 0;

monitorSocket.on('monitor_log', function (log) {
    addMonitorRow(log, false);
});

monitorSocket.on('monitor_alert', function (log) {
    monitorAlertCount++;
    const badge = document.getElementById('alert-count');
    if (badge) badge.innerText = monitorAlertCount + " Alerts";
    addMonitorRow(log, true);

    // Optional: Toast notification
    if (typeof showToast !== 'undefined') {
        showToast(`🚨 Security Alert [${log.ip}]: ${log.message}`);
    }
});

function addMonitorRow(log, isAlert) {
    const tbody = document.getElementById('monitor-logs-body');
    if (!tbody) return;

    const time = log.time;
    const ip = log.ip;
    const type = log.type ? log.type.toUpperCase() : "UNKNOWN";
    let details = "";

    // Safety check for details
    if (!log.details) log.details = {};

    if (log.type === 'file') {
        details = `<span style="color:#aaa;">${log.details.event || ''}</span> : <span style="color:#fff;">${log.details.path || ''}</span>`;
        if (log.details.content) {
            // Create a collapsible details id
            const detailId = 'detail-' + Math.random().toString(36).substr(2, 9);
            details += ` <a href="javascript:void(0)" onclick="document.getElementById('${detailId}').style.display = document.getElementById('${detailId}').style.display === 'none' ? 'block' : 'none'" style="color:#00afff">[View Content]</a>`;
            details += `<pre id="${detailId}" style="display:none; margin-top:5px; border:1px solid #444; padding:5px; color:#ccc; white-space:pre-wrap;">${escapeHtml(log.details.content)}</pre>`;
        }
    } else if (log.type === 'process') {
        details = `PID:<span style="color:#e74c3c;">${log.details.pid}</span> CMD:<span style="color:#f39c12;">${log.details.cmd}</span>`;
    } else {
        details = JSON.stringify(log.details);
    }

    if (isAlert) {
        details = `<span class="text-danger font-weight-bold" style="background:rgba(231,76,60,0.1); padding:2px;">⚠️ ${log.message}</span> <br> ${details}`;
    }

    const row = document.createElement('tr');
    if (isAlert) row.classList.add('table-danger');

    row.innerHTML = `
        <td style="color:#888;">${time}</td>
        <td>${ip}</td>
        <td><span class="badge ${log.type === 'file' ? 'badge-info' : 'badge-warning'}">${type}</span></td>
        <td class="text-break" style="word-break:break-all;">${details}</td>
    `;

    // Prepend to top
    if (tbody.firstChild) {
        tbody.insertBefore(row, tbody.firstChild);
    } else {
        tbody.appendChild(row);
    }

    // Limit rows to 100
    if (tbody.children.length > 100) {
        tbody.removeChild(tbody.lastChild);
    }
}

function clearMonitorLogs() {
    const tbody = document.getElementById('monitor-logs-body');
    if (tbody) tbody.innerHTML = '';
    monitorAlertCount = 0;
    const badge = document.getElementById('alert-count');
    if (badge) badge.innerText = "0 Alerts";
}

function escapeHtml(text) {
    if (!text) return text;
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
