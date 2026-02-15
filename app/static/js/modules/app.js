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
}

// Initialization
document.addEventListener('DOMContentLoaded', () => {
    loadScheduledTasks();
    if (typeof loadCustomRules === 'function') loadCustomRules();
    if (typeof loadKeys === 'function') loadKeys(); // Load keys initially
});
