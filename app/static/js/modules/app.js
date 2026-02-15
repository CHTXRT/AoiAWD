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

function addAlert(data) {
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
    row.style.animation = "fadeIn 0.5s";
    row.innerHTML = `
        <td style="padding:8px; border-bottom:1px solid var(--border-color); color:#999;">${data.time}</td>
        <td style="padding:8px; border-bottom:1px solid var(--border-color); font-family:monospace; color:#f39c12;">${data.file}</td>
        <td style="padding:8px; border-bottom:1px solid var(--border-color); color:#2ecc71;">${data.action}</td>
    `;
    tbody.insertBefore(row, tbody.firstChild);

    // Auto expand if collapsed
    const content = card.querySelector('.card-content');
    if (content.style.display === 'none') {
        toggleAlertCard(card.id);
    }

    // Move to top of list if not already
    list.prepend(card);

    // Update Global Badge
    alertCount++;
    const navBadge = document.getElementById('nav-alert-badge');
    navBadge.innerText = alertCount;
    navBadge.style.display = 'inline-block';

    playAlertSound();
    showToast(`🚨 ALERT: Immortal Shell on ${data.ip}`, 'error');
}

function clearAlerts() {
    document.getElementById('alerts-list').innerHTML = '<div class="empty-msg" style="text-align:center; padding:40px; color:#666;">✅ 暂无安全告警</div>';
    alertCount = 0;
    document.getElementById('nav-alert-badge').style.display = 'none';
}

// Initialization
document.addEventListener('DOMContentLoaded', () => {
    loadScheduledTasks();
    if (typeof loadCustomRules === 'function') loadCustomRules();
    if (typeof loadKeys === 'function') loadKeys(); // Load keys initially
});
