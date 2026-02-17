// --- Attack Module Logic ---
let attackPollInterval = null;

function loadAttackConfig() {
    fetch('/api/attack/config')
        .then(r => r.json())
        .then(data => {
            const tplInput = document.getElementById('attack-template');
            const excInput = document.getElementById('attack-excluded');
            if (tplInput) tplInput.value = data.template || '';
            if (excInput) excInput.value = data.excluded_ips || '';
            renderAttackWall(data.targets);
        });
}

function saveAttackConfig() {
    const template = document.getElementById('attack-template').value;
    const excluded = document.getElementById('attack-excluded').value;
    fetch('/api/attack/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ template, excluded_ips: excluded })
    })
        .then(r => r.json())
        .then(data => {
            showToast('配置已保存');
            loadAttackConfig();
        });
}

function startAttackPoll() {
    if (attackPollInterval) clearInterval(attackPollInterval);
    loadAttackConfig(); // initial
    attackPollInterval = setInterval(() => {
        fetch('/api/attack/status').then(r => r.json()).then(data => renderAttackWall(data.targets));
    }, 3000);
}

function stopAttackPoll() {
    if (attackPollInterval) clearInterval(attackPollInterval);
}

// FIX: In-place DOM update to preserve state
function renderAttackWall(targetsData) {
    const wall = document.getElementById('attack-wall');
    if (!wall) return;

    if (!targetsData || Object.keys(targetsData).length === 0) {
        if (!wall.querySelector('.empty-msg')) {
            wall.innerHTML = '<div class="empty-msg empty-placeholder" style="grid-column: 1/-1;">无活跃目标</div>';
        }
        // Remove cards if any exist
        wall.querySelectorAll('.target-card').forEach(c => c.remove());
        return;
    }

    const emptyMsg = wall.querySelector('.empty-msg');
    if (emptyMsg) emptyMsg.remove();

    const currentIps = new Set(Object.keys(targetsData));

    for (const [ip, info] of Object.entries(targetsData)) {
        const safeIp = ip.replace(/\./g, '_');
        const cardId = `card-${safeIp}`;
        let card = document.getElementById(cardId);

        let statusClass = 'status-waiting';
        let statusDotClass = '';

        if (info.status === 'success' || info.status === 'confirmed') {
            statusClass = 'status-success';
            statusDotClass = 'status-dot-success';
        } else if (info.status === 'failed') {
            statusClass = 'status-failed';
            statusDotClass = 'status-dot-failed';
        } else if (info.status === 'uncertain') {
            statusClass = 'status-uncertain';
            statusDotClass = 'status-dot-uncertain';
        }

        if (card) {
            // Update Existing: Surgical updates for status and content
            card.className = `card target-card status-${statusClass}-border`;

            const badge = card.querySelector('.attack-status-badge');
            if (badge) {
                badge.className = `attack-status-badge status-${statusClass}`;
                badge.innerHTML = `<span class="status-dot status-dot-${statusClass}"></span> ${info.status}`;
            }

            const infoValues = card.querySelectorAll('.info-val');
            if (infoValues.length >= 3) {
                const safeText = (txt) => txt || 'None';
                if (infoValues[0].innerText !== safeText(info.last_msg)) infoValues[0].innerText = safeText(info.last_msg);
                if (infoValues[1].innerText !== (info.password || 'N/A')) infoValues[1].innerText = info.password || 'N/A';
                if (infoValues[2].innerText !== (info.shell_uri || 'N/A')) infoValues[2].innerText = info.shell_uri || 'N/A';
            }

            const actionDiv = card.querySelector('.action-div');
            const shouldShow = (info.status !== 'waiting' && info.status !== 'failed');
            if (shouldShow && !actionDiv) {
                card.querySelector('.card-content').insertAdjacentHTML('beforeend', getActionHtml(ip, info.port));
            }
        } else {
            // Create New Cyberpunk Card
            card = document.createElement('div');
            card.id = cardId;
            card.className = `card target-card status-${statusClass}-border`;
            card.setAttribute('data-ip', ip);
            card.style.padding = '0';

            const details = document.createElement('details');
            details.style.width = '100%';

            const summary = document.createElement('summary');
            summary.innerHTML = `
                <div class="attack-card-header">
                    <span class="attack-card-ip">${ip}</span>
                    <div class="attack-status-badge status-${statusClass}">
                        <span class="status-dot status-dot-${statusClass}"></span> ${info.status}
                    </div>
                </div>
                <div class="attack-card-port" style="position:absolute; bottom:5px; right:15px; font-size:9px; color: var(--text-muted); font-family:'Share Tech Mono';">PORT_NODE: ${info.port || '80'}</div>
            `;

            const content = document.createElement('div');
            content.className = 'card-content attack-card-details';

            content.innerHTML = `
                <div class="info-item"><span class="info-label">LOG_STREAM:</span> <span class="info-val">${info.last_msg || 'NO_DATA'}</span></div>
                <div class="info-item"><span class="info-label">AUTH_KEY:</span> <code class="info-val" style="user-select:all; color:var(--neon-yellow);">${info.password || 'N/A'}</code></div>
                <div class="info-item"><span class="info-label">REMOTE_URI:</span> <code class="info-val" style="user-select:all; font-size:10px;">${info.shell_uri || 'N/A'}</code></div>
            `;
            if (info.status !== 'waiting' && info.status !== 'failed') {
                content.insertAdjacentHTML('beforeend', getActionHtml(ip, info.port));
            }

            details.appendChild(summary);
            details.appendChild(content);
            card.appendChild(details);
            wall.appendChild(card);
        }
    }

    // Remove Stale
    document.querySelectorAll('.target-card').forEach(card => {
        const ip = card.getAttribute('data-ip');
        if (ip && !currentIps.has(ip)) card.remove();
    });
}

function getActionHtml(ip, port) {
    return `
        <div class="action-div action-panel">
            <div class="flag-box">
                <div style="display:flex; justify-content:space-between; align-items:center; width:100%;">
                    <span class="info-label" style="margin:0;">ACCESS_FLAG:</span>
                    <button class="btn btn-cyber btn-sm neon-pink" 
                        onclick="attackGetFlag('${ip}', ${port || 80}, this)">EXTRACT</button>
                </div>
                <div class="flag-output"></div>
            </div>
            <div class="cmd-box">
                <input type="text" class="cmd-input form-control form-control-sm" placeholder="COMMAND_INPUT..." onkeydown="if(event.key==='Enter') attackExecCmd('${ip}', ${port || 80}, this.nextElementSibling)">
                <button class="btn btn-cyber btn-sm neon-blue" 
                    onclick="attackExecCmd('${ip}', ${port || 80}, this)">EXECUTE</button>
            </div>
            <pre class="cmd-output" style="padding:12px; margin-top:15px; display:none; max-height:180px; overflow:auto;"></pre>
        </div>
    `;
}

// --- Attack Actions ---
function attackGetFlag(ip, port, btn) {
    const parent = btn.closest('.flag-box');
    const outputDiv = parent.querySelector('.flag-output');

    outputDiv.innerText = 'EXTRACTING...';
    outputDiv.classList.add('extracting');
    btn.disabled = true;

    fetch('/api/attack/get_flag', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, port })
    })
        .then(r => r.json())
        .then(data => {
            btn.disabled = false;
            outputDiv.classList.remove('extracting');

            if (data.success) {
                outputDiv.innerText = data.output;
                // Add success visual feedback
                outputDiv.style.borderColor = 'var(--success-color)';
                outputDiv.style.color = 'var(--success-color)';
                setTimeout(() => {
                    outputDiv.style.borderColor = '';
                    outputDiv.style.color = '';
                }, 2000);
            } else {
                outputDiv.innerText = 'ERR: ' + data.output;
                // Add error visual feedback
                outputDiv.style.borderColor = 'var(--danger-color)';
                outputDiv.style.color = 'var(--danger-color)';
            }
        })
        .catch(err => {
            btn.disabled = false;
            outputDiv.classList.remove('extracting');
            outputDiv.innerText = 'ERR: ' + err;
        });
}

function attackExecCmd(ip, port, btn) {
    const input = btn.previousElementSibling;
    const pre = btn.parentElement.nextElementSibling;
    const cmd = input.value;

    if (!cmd) return;

    pre.style.display = 'block';
    pre.innerText = 'Executing...';

    fetch('/api/attack/execute_cmd', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, port, cmd })
    })
        .then(r => r.json())
        .then(data => {
            pre.innerText = data.output;
        });
}
