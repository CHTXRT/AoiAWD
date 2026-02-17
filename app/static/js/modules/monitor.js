// Monitor Module
console.log("Monitor Module Loaded");

function initMonitor() {
    // Check if socket exists
    if (typeof wsSocket !== 'undefined') {
        console.log("Monitor Module: Socket found, listening for monitor_log");
        wsSocket.on('monitor_log', (data) => {
            // console.log("Monitor Log received", data);
            addMonitorLog(data);
        });
    } else {
        console.warn("Monitor Module: wsSocket not defined yet");
        // Retry shortly? app.js defines it.
        setTimeout(initMonitor, 1000);
    }
}

function addMonitorLog(log) {
    const tbody = document.getElementById('monitor-logs-body');
    if (!tbody) return;

    // Remove empty msg
    const empty = tbody.querySelector('td[colspan]');
    if (empty) tbody.innerHTML = '';

    const row = document.createElement('tr');
    row.style.animation = "fadeIn 0.3s";

    // Mapping
    const time = log.time || new Date().toLocaleTimeString();
    const ip = log.ip;
    let eventType = log.type;
    let path = '-';
    let detailsStr = '';

    if (log.type === 'file') {
        eventType = log.details.event || 'FILE';
        path = log.details.path || '';
        // detailsStr = JSON.stringify(log.details);
    } else if (log.type === 'process') {
        eventType = 'PROCESS';
        // path = log.details.cmd || '';
        path = `PID: ${log.details.pid}`;
        detailsStr = log.details.cmd || '';
    } else if (log.type === 'heartbeat') {
        return; // Filter heartbeats if they leak through
    }

    if (!detailsStr && log.details) {
        // Create a cleaner detail string
        const cloned = { ...log.details };
        delete cloned.path;
        delete cloned.event;
        delete cloned.cmd;
        delete cloned.pid;
        delete cloned.time;
        if (Object.keys(cloned).length > 0) detailsStr = JSON.stringify(cloned);
    }

    // Color code events
    let color = 'var(--text-color)';
    if (eventType.includes('DELETE')) color = '#e74c3c';
    else if (eventType.includes('CREATE')) color = '#2ecc71';
    else if (eventType.includes('MODIFY')) color = '#f39c12';

    row.innerHTML = `
        <td style="padding:8px; border-bottom:1px solid var(--border-color); color: var(--text-muted); font-size:12px; white-space:nowrap;">${time}</td>
        <td style="padding:8px; border-bottom:1px solid var(--border-color); font-size:12px;">${ip}</td>
        <td style="padding:8px; border-bottom:1px solid var(--border-color); color:${color}; font-weight:bold; font-size:12px;">${eventType}</td>
        <td style="padding:8px; border-bottom:1px solid var(--border-color); font-family:var(--font-mono, monospace); font-size:12px; word-break:break-all;">${path}</td>
        <td style="padding:8px; border-bottom:1px solid var(--border-color); color: var(--text-muted); font-size:11px; word-break:break-all;">${detailsStr.substring(0, 100)}</td>
    `;

    tbody.insertBefore(row, tbody.firstChild);

    // Limit rows
    if (tbody.children.length > 200) {
        tbody.lastChild.remove();
    }
}

function clearMonitorLogs() {
    const tbody = document.getElementById('monitor-logs-body');
    if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="empty-placeholder">等待日志...</td></tr>';
}

// Auto init
document.addEventListener('DOMContentLoaded', initMonitor);
