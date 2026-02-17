// --- SSH Connection & Target Logic ---

async function connect(ip, port) {
    console.log(`[SSH] Connect called for ${ip}:${port}`);
    console.trace();  // 打印调用栈
    showToast("Connecting to " + ip + ":" + port + "...");
    const data = await apiCall('/api/connect', { ip, port });
    if (data) {
        showToast(data.message);
        if (data.success) {
            // Update happens via WebSocket
        } else {
            setTimeout(() => location.reload(), 500); // Fallback
        }
    }
}

async function disconnect(ip, port) {
    const data = await apiCall('/api/disconnect', { ip, port });
    if (data) {
        showToast(data.message);
    }
}

async function removeTarget(ip, port) {
    if (!confirm('Remove target ' + ip + ':' + port + '?')) return;
    const data = await apiCall('/api/remove_target', { ip, port });
    if (data && data.status === 'ok') {
        showToast("Removed");
    }
}

async function updatePassword(ip, port) {
    const password = prompt("Enter new password for " + ip + ":" + port + ":");
    if (password === null) return;
    showToast("Updating password...");
    const data = await apiCall('/api/update_password', { ip, port, password });
    if (data) {
        showToast(data.message);
    }
}

async function connectAll() {
    console.log('[SSH] ConnectAll called');
    console.trace();  // 打印调用栈
    if (!confirm('确定要连接所有靶机吗？')) return;
    showToast('正在连接所有靶机...');
    const data = await apiCall('/api/connect_all', {});
    if (data) {
        showToast(data.message);
    }
}

async function disconnectAll() {
    if (!confirm('确定要断开所有靶机吗？')) return;
    const data = await apiCall('/api/disconnect_all', {});
    if (data) {
        showToast('已断开所有连接');
    }
}

async function batchExecutePrompt() {
    const cmd = prompt('在所有已连接靶机上执行命令:');
    if (!cmd) return;
    showToast('正在批量执行...');
    const data = await apiCall('/api/batch_execute', { cmd });
    if (data && data.results) {
        let msg = '批量执行结果:\n';
        for (const [key, output] of Object.entries(data.results)) {
            msg += `\n[${key}]\n${output}\n`;
        }
        alert(msg);
    }
}

async function checkConnections() {
    showToast('正在检查连接...');
    const data = await apiCall('/api/check_connections', {});
    if (data && data.results) {
        let dead = data.results.filter(r => !r.alive);
        if (dead.length === 0) {
            showToast('所有连接正常 ✅');
        } else {
            showToast(`${dead.length} 个连接已断开`);
        }
    }
}

function openXshell(ip, port) {
    // Check if we are running locally (on the server machine)
    const isLocal = ['localhost', '127.0.0.1'].includes(window.location.hostname);

    if (isLocal) {
        // Server-side launch
        apiCall('/api/open_xshell', { ip, port }).then(d => {
            if (d) showToast(d.message);
        });
    } else {
        // Client-side: Copy SSH Command (No Password for Security)
        // We do not have the password in frontend anymore.
        // Just copy the user@ip:port part. Default user is root if not known, but we don't have user either?
        // Wait, template passes user? No, we removed user param too from onclick in template? 
        // Let's check template again. target_main_row passed: openXshell('{{ t.ip }}', '{{ t.port }}')
        // So we only have IP and Port.
        // We can assume 'root' or just copy ip:port

        const sshCmd = `ssh root@${ip} -p ${port}`;
        navigator.clipboard.writeText(sshCmd).then(() => {
            showToast('连接命令已复制 (不含密码): ' + sshCmd);
        }).catch(err => {
            showToast('复制失败: ' + sshCmd);
            prompt('请手动复制连接命令 (需自行输入密码):', sshCmd);
        });
    }
}

function openXshellWwwData(ip, port) {
    // Server-side launch only (mostly) or just copy command?
    // The previous logic for WwwData was server launch via api.
    apiCall('/api/open_xshell_wwwdata', { ip, port }).then(d => {
        if (d) showToast(d.message);
    });
}
