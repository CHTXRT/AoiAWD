// ==================== SSH Key Management ====================

async function loadKeys() {
    try {
        const res = await fetch('/api/keys');
        const data = await res.json();
        const tbody = document.getElementById('keys-table-body');
        if (!tbody) return;

        if (data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-placeholder">暂无密钥文件</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(k => {
            const sizeKB = (k.size / 1024).toFixed(2) + ' KB';
            const usedList = Array.isArray(k.used_by) ? k.used_by : [];
            const usedByCount = usedList.length;

            let usedByHtml = '<span style="color: var(--text-muted);">未使用</span>';
            if (usedByCount > 0) {
                const listItems = usedList.map(t => `<li>${t}</li>`).join('');
                usedByHtml = `
                    <details>
                        <summary style="padding:2px; background:transparent; border:none; cursor:pointer; color:var(--primary-color); outline:none; font-size:11px;">
                           🔗 ${usedByCount} 个靶机
                        </summary>
                        <ul style="margin:5px 0 5px 15px; padding:0; font-size:11px; color:var(--text-color);">
                            ${listItems}
                        </ul>
                    </details>
                `;
            }

            return `
                <tr>
                    <td>${k.name}</td>
                    <td>${sizeKB}</td>
                    <td>${usedByHtml}</td>
                    <td>
                        <button class="btn btn-danger btn-sm" onclick="deleteKey('${k.name}')">🗑️</button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        const tbody = document.getElementById('keys-table-body');
        if (tbody) tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:red;">加载失败: ${e.message}</td></tr>`;
    }
}

async function uploadKeys() {
    const inputFiles = document.getElementById('key-upload-input');
    const inputFolder = document.getElementById('key-upload-folder');

    let totalFiles = 0;
    if (inputFiles) totalFiles += inputFiles.files.length;
    if (inputFolder) totalFiles += inputFolder.files.length;

    if (totalFiles === 0) return showToast('请选择文件或文件夹');

    const formData = new FormData();
    if (inputFiles) {
        for (let i = 0; i < inputFiles.files.length; i++) {
            formData.append('files[]', inputFiles.files[i]);
        }
    }
    if (inputFolder) {
        for (let i = 0; i < inputFolder.files.length; i++) {
            formData.append('files[]', inputFolder.files[i]);
        }
    }

    showToast('正在上传...');
    try {
        const res = await fetch('/api/keys/upload', {
            method: 'POST',
            body: formData
        });
        const data = await res.json();

        if (res.ok) {
            showToast(`成功上传 ${data.uploaded.length} 个文件`);
            if (inputFiles) inputFiles.value = '';
            if (inputFolder) inputFolder.value = '';
            loadKeys();
        } else {
            showToast('上传失败: ' + (data.error || 'Unknown error'));
        }
    } catch (e) {
        showToast('上传出错: ' + e.message);
    }
}

async function deleteKey(filename) {
    if (!confirm(`确定要删除密钥文件 "${filename}" 吗？`)) return;
    showToast('正在删除...');
    const data = await apiCall('/api/keys/delete', { filename });
    if (data && data.status === 'ok') {
        showToast('已删除');
        loadKeys();
    } else if (data && data.error) {
        showToast('删除失败: ' + data.error);
    }
}
