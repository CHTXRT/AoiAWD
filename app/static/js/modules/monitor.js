// Monitor Module
console.log("Monitor Module Loaded");

// Agent 状态管理
const agentStatuses = {};

function initMonitor() {
    // Check if socket exists
    if (typeof wsSocket !== 'undefined') {
        console.log("Monitor Module: Socket found, listening for monitor_log");
        
        // 监听文件监控日志
        wsSocket.on('monitor_log', (data) => {
            console.log('[Monitor] Received monitor_log:', data);
            addMonitorLog(data);
        });
        
        // 监听 Agent 心跳状态
        wsSocket.on('agent_heartbeat', (data) => {
            updateAgentStatus(data);
        });
        
    } else {
        console.warn("Monitor Module: wsSocket not defined yet");
        setTimeout(initMonitor, 1000);
    }
}

// 更新 Agent 状态（用于呼吸灯）
function updateAgentStatus(data) {
    const key = `${data.ip}:${data.port}`;
    agentStatuses[key] = {
        status: data.status,
        lastHeartbeat: data.timestamp,
        isOnline: data.status === 'online'
    };
    
    // 更新 UI 上的呼吸灯
    updateAgentStatusIndicator(data.ip, data.port, data.status);
}

// 更新 Agent 状态指示器（呼吸灯）
function updateAgentStatusIndicator(ip, port, status) {
    const safeIp = ip.replace(/\./g, '-');
    const rowId = `target-${safeIp}-${port}`;
    const row = document.getElementById(rowId);
    
    if (row) {
        const indicators = row.querySelectorAll('.agent-status-indicator');
        indicators.forEach(ind => {
            ind.className = 'agent-status-indicator ' + (status === 'online' ? 'online' : 'offline');
            ind.title = `Agent ${status} - Last update: ${new Date().toLocaleTimeString()}`;
        });
    }
}

// 获取 Agent 状态
function getAgentStatus(ip, port) {
    return agentStatuses[`${ip}:${port}`] || { status: 'unknown', isOnline: false };
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
    } else if (log.type === 'process') {
        eventType = 'PROCESS';
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

// 定期刷新 Agent 状态（每 10 秒）
async function refreshAgentStatuses() {
    try {
        const response = await fetch('/api/agent/all_status');
        const data = await response.json();
        if (data.agents) {
            Object.entries(data.agents).forEach(([key, status]) => {
                const [ip, port] = key.split(':');
                const health = status.health || {};
                updateAgentStatusIndicator(ip, parseInt(port), health.is_alive ? 'online' : 'offline');
            });
        }
    } catch (e) {
        console.error('Failed to refresh agent statuses:', e);
    }
}

// 启动定期刷新
setInterval(refreshAgentStatuses, 10000);

// Auto init
document.addEventListener('DOMContentLoaded', () => {
    initMonitor();
    refreshAgentStatuses(); // 初始加载
});
