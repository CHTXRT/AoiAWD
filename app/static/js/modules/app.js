// --- App Initializer & Main Logic ---

// Switch View Logic
function switchView(viewName, navItem) {
    // Update Nav
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    navItem.classList.add('active');

    // Update View
    document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
    const target = document.getElementById('view-' + viewName);
    if (target) target.classList.add('active');

    // Logic hooks
    if (viewName === 'attacks') {
        loadAttackConfig();
        startAttackPoll();
    } else {
        stopAttackPoll();
    }
}

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

// Toggle Detail Row
function toggleRow(ip, port) {
    const safeIp = ip.replace(/\./g, '-');
    const rowId = 'detail-' + safeIp + '-' + port;
    const iconId = 'icon-' + safeIp + '-' + port;

    const row = document.getElementById(rowId);
    const icon = document.getElementById(iconId);

    if (row.style.display === 'none') {
        row.style.display = 'table-row';
        icon.style.transform = 'rotate(90deg)';
    } else {
        row.style.display = 'none';
        icon.style.transform = 'rotate(0deg)';
    }
}

// Global WebSocket Listeners for UI Updates (outside of Terminal)
// Ideally, wsSocket should be a shared global socket.
if (typeof wsSocket === 'undefined') {
    // If not defined by terminal.js, create one.
    // Or check if 'socket' from defense.js can be reused (but scope is tricky).
    // Let's create a global one.
    window.wsSocket = io();
}

if (typeof wsSocket !== 'undefined' && wsSocket) {
    wsSocket.on('target_update', (data) => {
        console.log('Received target_update:', data);
        const target = data.target;

        if (!target || !target.ip || !target.port) return;

        const safeIp = target.ip.replace(/\./g, '-');
        const rowId = 'target-' + safeIp + '-' + target.port;
        const detailRowId = 'detail-' + safeIp + '-' + target.port;

        const existingRow = document.getElementById(rowId);
        const existingDetail = document.getElementById(detailRowId);
        const tbody = document.querySelector('#view-dashboard table tbody');

        if (data.action === 'remove') {
            if (existingRow) existingRow.remove();
            if (existingDetail) existingDetail.remove();
            return;
        }

        // For update or add
        if (data.html_main) {
            // Update Main Row
            const tempMain = document.createElement('tbody');
            tempMain.innerHTML = data.html_main;
            const newMainRow = tempMain.firstElementChild;

            if (existingRow) {
                existingRow.replaceWith(newMainRow);
            } else {
                tbody.appendChild(newMainRow);
            }
        }

        if (data.html_detail) {
            // Update Detail Row
            const tempDetail = document.createElement('tbody');
            tempDetail.innerHTML = data.html_detail;
            const newDetailRow = tempDetail.firstElementChild;

            if (existingDetail) {
                // Preserve display state
                newDetailRow.style.display = existingDetail.style.display;
                existingDetail.replaceWith(newDetailRow);
            } else {
                // If new row added, detail row comes after main row
                const currentMain = document.getElementById('target-' + safeIp + '-' + target.port);
                if (currentMain) {
                    currentMain.after(newDetailRow);
                }
            }
        }

        // Re-sync icon state if detail is open
        const newDetail = document.getElementById(detailRowId);
        const newIcon = document.getElementById('icon-' + safeIp + '-' + target.port);
        if (newDetail && newDetail.style.display !== 'none' && newIcon) {
            newIcon.style.transform = 'rotate(90deg)';
        }
    });

    wsSocket.on('immortal_alert', (data) => {
        console.log('Received ALERT:', data);
        addAlert(data);
    });
}

// Alert Logic
let alertCount = 0;
const alertSound = new Audio("data:audio/wav;base64,UklGRl9vT19XQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YU..."); // Placeholder sound? 
// Let's use a simple beep or just assume browser might block it without interaction. 
// Using a very short beep base64 for simplicity or just console log if sound fails.
// Since I cannot easily generate a valid wav base64 here without tools, let's skip the actual base64 string content and handle the logic. 
// I will use a dummy empty src for now, user can add file later or I can try to generate a beep via Context if needed, but a simple console log is safer for now.

function playAlertSound() {
    if (!document.getElementById('alert-sound-toggle').checked) return;
    try {
        // Simple Beep using AudioContext
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = ctx.createOscillator();
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(880, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(110, ctx.currentTime + 0.5);
        const gain = ctx.createGain();
        gain.gain.setValueAtTime(0.5, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.5);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start();
        osc.stop(0.5);
    } catch (e) { console.error("Sound error", e); }
}

function initAlerts(targets) {
    const list = document.getElementById('alerts-list');
    if (!list) return;

    // Clear initial empty msg if we have targets
    if (targets.length > 0) {
        const empty = list.querySelector('.empty-msg');
        if (empty) empty.remove();
    }

    targets.forEach(t => {
        // Only for PHP targets? User said "php targets placeholder". 
        // Let's check detection types if available, otherwise just do all connected/active ones.
        // Simplified: Create for all targets to be safe, or check data.
        if (t.detection && t.detection.types && t.detection.types.includes('php')) {
            createAlertCard(t.ip, t.port, t.name);
        }
    });
}

function createAlertCard(ip, port, name) {
    const list = document.getElementById('alerts-list');
    const safeIp = ip.replace(/\./g, '-');
    const cardId = `alert-card-${safeIp}-${port}`;

    if (document.getElementById(cardId)) return document.getElementById(cardId);

    const card = document.createElement('div');
    card.id = cardId;
    card.className = 'card';
    card.style.cssText = `border-left: 4px solid #ccc; margin-bottom: 15px; transition: all 0.3s;`;

    // Default collapsed (no alerts yet)
    // We use a custom 'collapsed' class or just display none on body
    const title = name ? `${ip}:${port} (${name})` : `${ip}:${port}`;

    card.innerHTML = `
        <div class="card-header" onclick="toggleAlertCard('${cardId}')" style="cursor:pointer; padding:10px 15px; background:rgba(0,0,0,0.03); border-bottom:1px solid transparent; display:flex; justify-content:space-between; align-items:center;">
             <div style="display:flex; align-items:center; gap:10px;">
                <span id="icon-${cardId}" style="transition:transform 0.2s;">▶</span>
                <strong>${title}</strong>
             </div>
             <div>
                <span class="badge" id="badge-${cardId}" style="background:#95a5a6; color:white; font-size:11px;">Safe</span>
             </div>
        </div>
        <div class="card-content" style="padding:0; display:none;">
            <table style="width:100%; font-size:13px;">
                <thead style="background:rgba(0,0,0,0.02); color:#666;">
                    <tr>
                        <th style="padding:8px; text-align:left;">Time</th>
                        <th style="padding:8px; text-align:left;">File</th>
                        <th style="padding:8px; text-align:left;">Action</th>
                    </tr>
                </thead>
                <tbody class="alert-rows"></tbody>
            </table>
        </div>
    `;
    list.appendChild(card); // Append to end naturally
    return card;
}

function toggleAlertCard(cardId) {
    const card = document.getElementById(cardId);
    if (!card) return;
    const content = card.querySelector('.card-content');
    const icon = document.getElementById(`icon-${cardId}`);

    if (content.style.display === 'none') {
        content.style.display = 'block';
        icon.style.transform = 'rotate(90deg)';
        card.querySelector('.card-header').style.borderBottom = '1px solid var(--border-color)';
    } else {
        content.style.display = 'none';
        icon.style.transform = 'rotate(0deg)';
        card.querySelector('.card-header').style.borderBottom = '1px solid transparent';
    }
}

function addAlert(data, silent = false) {
    const list = document.getElementById('alerts-list');
    const empty = list.querySelector('.empty-msg');
    if (empty) empty.remove();

    // Find or Create Card
    let card = createAlertCard(data.ip, data.port, data.target_name);

    // Update Style for Alert State
    card.style.borderLeftColor = '#e74c3c';
    const badge = card.querySelector(`#badge-${card.id}`);
    badge.style.background = '#e74c3c';
    badge.innerText = 'Immortal Shell';

    const header = card.querySelector('.card-header');
    header.style.background = 'rgba(231,76,60,0.1)';

    // Add row
    const tbody = card.querySelector('.alert-rows');
    const row = document.createElement('tr');
    // Check if persistent kill is active for this file (need to check backend or store state)
    // For now, default button state.
    row.style.animation = "fadeIn 0.5s";
    row.innerHTML = `
        <td style="padding:8px; border-bottom:1px solid var(--border-color); color:#999;">${data.time}</td>
        <td style="padding:8px; border-bottom:1px solid var(--border-color); font-family:monospace; color:#f39c12;">${data.file}</td>
        <td style="padding:8px; border-bottom:1px solid var(--border-color); color:#2ecc71; display:flex; align-items:center; gap:5px; flex-wrap:wrap;">
            <span>${data.action}</span>
            <div style="display:flex; gap:4px;">
                ${data.quarantine_path ?
            `<button class="btn btn-sm btn-warning" onclick="restoreFile('${data.ip}', '${data.port}', '${data.file.replace(/\\/g, '\\\\')}', '${data.quarantine_path.replace(/\\/g, '\\\\')}', this)" title="还原隔离文件并信任">🛡️ 还原</button>` :
            `<button class="btn btn-sm btn-secondary" onclick="trustFile('${data.ip}', '${data.port}', '${data.file.replace(/\\/g, '\\\\')}', this)" title="加入白名单，防止误杀">🛡️ 信任</button>`
        }
                
                <button class="btn btn-sm btn-info" style="background:#3498db; border:none;" onclick="viewFileContent('${data.ip}', '${data.port}', '${data.file.replace(/\\/g, '\\\\')}')" title="审计文件内容">👁️ 审计</button>
                
                <button id="btn-kill-${data.ip.replace(/\./g, '-')}-${data.port}-${hex_md5(data.file)}" class="btn btn-sm btn-danger" style="background:#e74c3c; border:none;" onclick="togglePersistentKill('${data.ip}', '${data.port}', '${data.file.replace(/\\/g, '\\\\')}', this)" title="启动毫秒级持续查杀">⚡ 持续查杀</button>
            </div>
        </td>
    `;
    tbody.insertBefore(row, tbody.firstChild);

    // Auto expand if collapsed (only if not silent load?)
    // Maybe keep collapsed on load to avoid clutter
    const content = card.querySelector('.card-content');
    if (!silent && content.style.display === 'none') {
        toggleAlertCard(card.id);
    }

    // Move to top of list if not already
    list.prepend(card);

    // Update Global Badge
    alertCount++;
    const navBadge = document.getElementById('nav-alert-badge');
    navBadge.innerText = alertCount;
    navBadge.style.display = 'inline-block';

    if (!silent) {
        playAlertSound();
        showToast(`🚨 ALERT: Immortal Shell on ${data.ip} `, 'error');
    }
}

function clearAlerts() {
    document.getElementById('alerts-list').innerHTML = '<div class="empty-msg" style="text-align:center; padding:40px; color:#666;">✅ 暂无安全告警</div>';
    alertCount = 0;
    document.getElementById('nav-alert-badge').style.display = 'none';
}

async function loadAlerts() {
    try {
        const res = await fetch('/api/defense/immortal/alerts');
        const data = await res.json();
        if (data && data.alerts) {
            // Reverse so newest is first? addAlert prepends, so if list is chronological (oldest first), we iterate normal.
            // If backend list is chronological (append), we should iterate in order. addAlert uses list.prepend, so last added will be top.
            // So iterating persistent list (old -> new) means Newest will be at top. Correct.
            data.alerts.forEach(alert => {
                // We use addAlert but without sound/toast for initial load?
                // Or maybe we want to just populate quietly.
                addAlert(alert, true); // true = silent mode
            });
        }
    } catch (e) { console.error("Error loading alerts", e); }
}

async function trustFile(ip, port, file, btn) {
    if (!confirm(`确定要信任文件 ${file} 吗？\n信任后，不死马查杀将忽略对该文件的检查。`)) return;
    performTrust(ip, port, file, btn);
}

async function performTrust(ip, port, file, btn) {
    try {
        const res = await fetch('/api/defense/whitelist/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, port, file })
        });
        const data = await res.json();
        if (data.status === 'ok') {
            showToast(data.message);
            if (btn) {
                btn.innerText = '✅ 已信任';
                btn.disabled = true;
                btn.classList.remove('btn-secondary');
                btn.closest('tr').style.opacity = '0.6';
            }
        } else {
            showToast('操作失败', 'error');
        }
    } catch (e) { console.error(e); showToast('请求错误', 'error'); }
}

async function restoreFile(ip, port, file, quarantine_path, btn) {
    if (!confirm(`确定要还原并信任 ${file} 吗？\n这将覆盖当前文件，并将其加入白名单。`)) return;

    try {
        const res = await fetch('/api/defense/quarantine/restore', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, port, file, quarantine_path })
        });
        const data = await res.json();
        if (data.status === 'ok') {
            showToast('已还原并加入白名单');
            if (btn) {
                btn.innerText = '✅ 已还原';
                btn.disabled = true;
                btn.classList.remove('btn-warning');
                btn.closest('tr').style.opacity = '0.6';
            }
        } else {
            showToast('还原失败: ' + data.message, 'error');
        }
    } catch (e) { console.error(e); showToast('请求错误', 'error'); }
}

async function toggleMaintenance(ip, port, checkbox) {
    const enabled = checkbox.checked;
    await apiCall('/api/target/maintenance', { ip, port, enabled });
    showToast(enabled ? '维护模式已开启 (暂停查杀)' : '维护模式已关闭 (恢复查杀)');
}

// --- Persistent Killer Logic ---
async function viewFileContent(ip, port, path) {
    try {
        const res = await fetch('/api/files/read', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, port, path })
        });
        const data = await res.json();

        // Use a simple modal
        const modalId = 'file-viewer-modal';
        let modal = document.getElementById(modalId);
        if (!modal) {
            modal = document.createElement('div');
            modal.id = modalId;
            modal.style.cssText = `position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.5); z-index:1000; display:flex; align-items:center; justify-content:center;`;
            modal.innerHTML = `
                <div style="background:var(--card-bg); width:80%; height:80%; border-radius:8px; display:flex; flex-direction:column; box-shadow:0 10px 30px rgba(0,0,0,0.5); border:1px solid var(--border-color);">
                    <div style="padding:15px; border-bottom:1px solid var(--border-color); display:flex; justify-content:space-between; align-items:center;">
                        <h3 style="margin:0; font-size:16px;">📂 文件审计: <span id="viewer-filename"></span></h3>
                        <button onclick="document.getElementById('${modalId}').style.display='none'" style="background:none; border:none; color:var(--text-color); font-size:20px; cursor:pointer;">&times;</button>
                    </div>
                    <div style="flex:1; overflow:auto; padding:0; background:#1e1e1e;">
                        <pre style="margin:0; padding:15px; font-family:'Consolas',monospace; color:#d4d4d4; font-size:12px; white-space:pre-wrap; word-break:break-all;" id="viewer-content"></pre>
                    </div>
                    <div style="padding:15px; border-top:1px solid var(--border-color); display:flex; justify-content:flex-end; gap:10px;">
                        <button class="btn btn-secondary" onclick="document.getElementById('${modalId}').style.display='none'">关闭</button>
                        <button class="btn btn-danger" id="viewer-kill-btn">⚡ 启动持续查杀</button>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
        }

        document.getElementById('viewer-filename').innerText = path;
        document.getElementById('viewer-content').innerText = data.content || data.error || '[Empty]';

        const killBtn = document.getElementById('viewer-kill-btn');
        killBtn.onclick = () => {
            modal.style.display = 'none';
            togglePersistentKill(ip, port, path, null);
        };

        modal.style.display = 'flex';

    } catch (e) { showToast('读取文件失败: ' + e, 'error'); }
}

async function togglePersistentKill(ip, port, file, btn) {
    // If called from modal, btn is null. We should find the button in alert card if possible, 
    // but file path might be from anywhere.
    // Let's use MD5 of file path to find button if passed

    const confirmMsg = btn && btn.innerText.includes('停止') ?
        `确定要停止对 ${file} 的持续查杀吗？` :
        `⚠️ 高危操作：确定要对 ${file} 启动持续查杀吗？\n\n系统将生成驻留脚本，毫秒级轮询删除该文件并建立文件夹占位。`;

    if (!confirm(confirmMsg)) return;

    const action = (btn && btn.innerText.includes('停止')) ? 'stop' : 'start';

    try {
        const res = await fetch('/api/defense/immortal/kill_persist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, port, file, action })
        });
        const data = await res.json();

        if (data.status === 'ok') {
            showToast(action === 'start' ? '⚡ 持续查杀已启动' : '🛑 持续查杀已停止');

            // Try to update button state globally (could be multiple buttons for same file)
            // But we need hex_md5 which I need to ensure is available or implement simple one.
            // app.js doesn't have md5 lib by default. 
            // I will implement a simple hash or just rely on reloading/checking status.

            if (btn) {
                if (action === 'start') {
                    btn.innerText = '🛑 停止查杀';
                    btn.classList.add('pulse-red'); // Need css
                } else {
                    btn.innerText = '⚡ 持续查杀';
                    btn.classList.remove('pulse-red');
                }
            }
        } else {
            showToast('操作失败: ' + data.message, 'error');
        }
    } catch (e) { console.error(e); showToast('请求异常', 'error'); }
}

// Simple MD5 impl or similar for ID generation? 
// Actually I can just use a simple string hash for ID if needed, or rely on passing button reference.
// The button ID I added above used hex_md5. I need to add that library or use a simple replacement.
// Let's add a simple hash function.

function hex_md5(s) {
    // Placeholder: just a simple hash to avoid requiring full md5 lib
    // Used for generating valid IDs for buttons
    var h = 0, l = s.length, i = 0;
    if (l > 0)
        while (i < l)
            h = (h << 5) - h + s.charCodeAt(i++) | 0;
    return "h" + h; // Prepend char to ensure valid ID
}

// Initialization
document.addEventListener('DOMContentLoaded', () => {
    loadScheduledTasks();
    loadAlerts(); // Load persisted alerts
    if (typeof loadCustomRules === 'function') loadCustomRules();
    if (typeof loadKeys === 'function') loadKeys(); // Load keys initially
});
