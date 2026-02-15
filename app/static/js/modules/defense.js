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
