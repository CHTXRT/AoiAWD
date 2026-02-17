// ==================== 自定义 PHP 规则管理 ====================

async function loadCustomRules() {
    try {
        const res = await fetch('/api/rules');
        const data = await res.json();
        const list = document.getElementById('custom-rules-list');
        if (!data.rules || data.rules.length === 0) {
            list.innerHTML = '<div style="color: var(--text-muted);">暂无自定义规则。内置规则已包含常见 PHP 危险函数。</div>';
            return;
        }
        list.innerHTML = data.rules.map((r, i) => `
            <div style="display:flex; justify-content:space-between; align-items:center; padding:4px 0; border-bottom:1px solid var(--border-color);">
                <span style="${r.enabled ? '' : 'opacity:0.5; text-decoration:line-through;'}">
                    <strong>${r.name}</strong> — <code>${r.pattern}</code>
                    ${r.description ? '<span style="color: var(--text-muted);">' + r.description + '</span>' : ''}
                </span>
                <span>
                    <button class="btn btn-sm" onclick="toggleCustomRule(${i})" style="font-size:10px;">${r.enabled ? '⏸️' : '▶️'}</button>
                    <button class="btn btn-sm" onclick="removeCustomRule(${i})" style="font-size:10px; color:#e74c3c;">🗑️</button>
                </span>
            </div>
        `).join('');
    } catch (e) { console.error('加载规则失败', e); }
}

async function addCustomRule() {
    const name = document.getElementById('rule-name').value;
    const pattern = document.getElementById('rule-pattern').value;
    const desc = document.getElementById('rule-desc').value;
    if (!name || !pattern) return showToast('名称和正则表达式不能为空');
    const data = await apiCall('/api/rules/add', { name, pattern, description: desc });
    if (data) {
        showToast('规则已添加');
        document.getElementById('rule-name').value = '';
        document.getElementById('rule-pattern').value = '';
        document.getElementById('rule-desc').value = '';
        loadCustomRules();
    }
}

async function removeCustomRule(index) {
    if (!confirm('删除此规则?')) return;
    const data = await apiCall('/api/rules/remove', { index });
    if (data) { showToast('规则已删除'); loadCustomRules(); }
}

async function toggleCustomRule(index) {
    const data = await apiCall('/api/rules/toggle', { index });
    if (data) { showToast(data.rule.enabled ? '规则已启用' : '规则已禁用'); loadCustomRules(); }
}
