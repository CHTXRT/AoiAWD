// Toast Logic
function showToast(msg) {
    const t = document.getElementById('toast');
    if (!t) return;
    t.innerText = msg;
    t.className = 'show';
    setTimeout(() => t.className = t.className.replace('show', ''), 3000);
}

// API Call Wrapper
async function apiCall(url, data) {
    try {
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        return await res.json();
    } catch (e) {
        showToast("Error: " + e);
        return null;
    }
}
