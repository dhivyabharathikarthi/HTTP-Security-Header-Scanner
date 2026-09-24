/**
 * HTTP Security Header Scanner - SOC Dashboard Frontend
 */

let currentScanData = null;
let currentFilter = 'all';

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scan-form');
    const targetInput = document.getElementById('target-url');
    const scanBtn = document.getElementById('btn-scan');
    const scanError = document.getElementById('scan-error');
    const btnHistory = document.getElementById('btn-view-history');
    const historyModal = document.getElementById('history-modal');
    const btnCloseHistory = document.getElementById('btn-close-history');
    const btnExportJson = document.getElementById('btn-export-json');
    const btnCopySummary = document.getElementById('btn-copy-summary');

    // Quick sample clicks
    document.querySelectorAll('.sample-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            targetInput.value = btn.dataset.url;
            form.dispatchEvent(new Event('submit'));
        });
    });

    // Form submit
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = targetInput.value.trim();
        if (!url) return;

        showLoading(true);
        hideError();

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || 'Scan request failed.');
            }

            currentScanData = data;
            renderScanDashboard(data);
        } catch (err) {
            showError(err.message || 'Failed to complete security scan.');
        } finally {
            showLoading(false);
        }
    });

    // Filter pills
    document.querySelectorAll('.filter-pills .pill').forEach(pill => {
        pill.addEventListener('click', () => {
            document.querySelectorAll('.filter-pills .pill').forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            currentFilter = pill.dataset.filter;
            if (currentScanData) {
                renderFindings(currentScanData.findings);
            }
        });
    });

    // Export JSON
    btnExportJson.addEventListener('click', () => {
        if (!currentScanData) return;
        const blob = new Blob([JSON.stringify(currentScanData, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `security_scan_${currentScanData.id ? currentScanData.id.slice(0, 8) : 'export'}.json`;
        a.click();
        URL.revokeObjectURL(a.href);
    });

    // Copy Summary
    btnCopySummary.addEventListener('click', () => {
        if (!currentScanData) return;
        const passCount = currentScanData.findings.filter(f => f.status === 'PASS').length;
        const warnCount = currentScanData.findings.filter(f => f.status === 'WARN').length;
        const text = `[HTTP Security Header Scan Summary]\nTarget: ${currentScanData.target}\nScore: ${currentScanData.score} / ${currentScanData.max_score} (${currentScanData.score_percentage}%)\nStatus: ${currentScanData.status_code} | HTTPS: ${currentScanData.is_https ? 'Yes' : 'No'}\nPassed: ${passCount} | Warnings: ${warnCount}\nGenerated at: ${currentScanData.timestamp}`;
        navigator.clipboard.writeText(text).then(() => {
            alert('Summary copied to clipboard!');
        }).catch(() => {
            console.log(text);
        });
    });

    // History Modal
    btnHistory.addEventListener('click', loadHistory);
    btnCloseHistory.addEventListener('click', () => {
        historyModal.style.display = 'none';
    });
    window.addEventListener('click', (e) => {
        if (e.target === historyModal) {
            historyModal.style.display = 'none';
        }
    });
});

function showLoading(isLoading) {
    const btn = document.getElementById('btn-scan');
    const text = btn.querySelector('.btn-text');
    const spinner = btn.querySelector('.spinner');
    if (isLoading) {
        btn.disabled = true;
        text.textContent = 'Scanning...';
    } else {
        btn.disabled = false;
        text.textContent = '⚡ Scan Target';
    }
}

function showError(msg) {
    const errBox = document.getElementById('scan-error');
    errBox.textContent = `⚠️ ${msg}`;
    errBox.style.display = 'block';
}

function hideError() {
    const errBox = document.getElementById('scan-error');
    errBox.style.display = 'none';
}

function renderScanDashboard(data) {
    document.getElementById('scan-dashboard').style.display = 'block';

    // Target meta
    document.getElementById('meta-target').textContent = data.target;
    document.getElementById('meta-final').textContent = data.final_url;
    document.getElementById('meta-status').textContent = data.status_code;
    document.getElementById('meta-https').textContent = data.is_https ? '✓ Enabled (TLS)' : '✕ Insecure (HTTP)';
    document.getElementById('meta-https').style.color = data.is_https ? 'var(--accent-green)' : 'var(--accent-red)';
    document.getElementById('meta-redirects').textContent = data.redirect_count;

    // Score
    document.getElementById('score-text').textContent = `${data.score} / ${data.max_score}`;
    document.getElementById('score-percentage').textContent = `${data.score_percentage}%`;
    document.getElementById('score-bar').style.width = `${data.score_percentage}%`;

    // Redirect section
    const redirectSection = document.getElementById('redirect-section');
    const chainContainer = document.getElementById('redirect-chain-flow');
    chainContainer.innerHTML = '';
    if (data.redirect_chain && data.redirect_chain.length > 1) {
        redirectSection.style.display = 'block';
        data.redirect_chain.forEach((hop, idx) => {
            const stepEl = document.createElement('div');
            stepEl.className = 'redirect-step';
            stepEl.innerHTML = `<strong>Step ${hop.step}:</strong> [${hop.status_code}] ${escapeHtml(hop.url)}`;
            chainContainer.appendChild(stepEl);
            if (idx < data.redirect_chain.length - 1) {
                const arrow = document.createElement('div');
                arrow.className = 'redirect-arrow';
                arrow.textContent = '↓';
                chainContainer.appendChild(arrow);
            }
        });
    } else {
        redirectSection.style.display = 'none';
    }

    // Findings
    renderFindings(data.findings);

    // Cookies
    renderCookies(data.cookies);

    // Raw Headers
    const rawPre = document.getElementById('raw-headers-block');
    rawPre.textContent = JSON.stringify(data.raw_headers || {}, null, 2);

    // Scroll to dashboard smoothly
    document.getElementById('scan-dashboard').scrollIntoView({ behavior: 'smooth' });
}

function renderFindings(findings) {
    const container = document.getElementById('headers-list');
    container.innerHTML = '';

    const filtered = (findings || []).filter(f => {
        if (currentFilter === 'all') return true;
        return f.status === currentFilter;
    });

    if (filtered.length === 0) {
        container.innerHTML = '<p style="color: var(--text-muted); padding: 1rem;">No findings match the selected filter.</p>';
        return;
    }

    filtered.forEach(item => {
        const div = document.createElement('div');
        const statusClass = item.status === 'PASS' ? 'pass' : 'warn';
        div.className = `finding-item ${statusClass}`;

        const badgeClass = item.status === 'PASS' ? 'badge-pass' : 'badge-warn';
        const icon = item.status === 'PASS' ? '✓' : '⚠';

        div.innerHTML = `
            <div class="finding-header">
                <div class="finding-title">
                    <span>${icon}</span>
                    <span>${escapeHtml(item.header)}</span>
                </div>
                <span class="badge ${badgeClass}">${item.status} (+${item.score_contribution}/${item.max_score_contribution} pts)</span>
            </div>
            ${item.value ? `<div class="finding-val"><code>${escapeHtml(item.value)}</code></div>` : '<div class="finding-val" style="color: #f87171;"><em>Header not configured</em></div>'}
            <div class="finding-msg">${escapeHtml(item.message)}</div>
            ${item.recommendation ? `<div class="finding-rec"><strong>Recommendation:</strong> ${escapeHtml(item.recommendation)}</div>` : ''}
        `;
        container.appendChild(div);
    });
}

function renderCookies(cookies) {
    const tbody = document.getElementById('cookie-table-body');
    tbody.innerHTML = '';

    if (!cookies || cookies.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 1.5rem;">No Set-Cookie headers observed in response.</td></tr>';
        return;
    }

    cookies.forEach(c => {
        const tr = document.createElement('tr');
        const secureFlag = c.secure ? '<span style="color: var(--accent-green)">✓ Yes</span>' : '<span style="color: var(--accent-red)">✕ No</span>';
        const httpOnlyFlag = c.httponly ? '<span style="color: var(--accent-green)">✓ Yes</span>' : '<span style="color: var(--accent-yellow)">✕ No</span>';
        const sameSiteText = c.samesite || 'Omitted';
        const notesHtml = (c.notes || []).map(n => `<div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 2px;">• ${escapeHtml(n)}</div>`).join('');

        tr.innerHTML = `
            <td><strong><code>${escapeHtml(c.name)}</code></strong></td>
            <td>${secureFlag}</td>
            <td>${httpOnlyFlag}</td>
            <td><code>${escapeHtml(sameSiteText)}</code></td>
            <td><small>${escapeHtml(c.path || '/')} | ${escapeHtml(c.domain || 'host')}</small></td>
            <td>${notesHtml}</td>
        `;
        tbody.appendChild(tr);
    });
}

async function loadHistory() {
    const modal = document.getElementById('history-modal');
    const tbody = document.getElementById('history-table-body');
    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">Loading past scans...</td></tr>';
    modal.style.display = 'flex';

    try {
        const res = await fetch('/api/scans');
        const items = await res.json();
        tbody.innerHTML = '';

        if (!items || items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-dim);">No previous scans recorded yet.</td></tr>';
            return;
        }

        items.forEach(item => {
            const tr = document.createElement('tr');
            const dateStr = item.timestamp ? new Date(item.timestamp).toLocaleString() : '-';
            tr.innerHTML = `
                <td><small>${dateStr}</small></td>
                <td><strong>${escapeHtml(item.original_url)}</strong></td>
                <td><span class="badge badge-info">${item.status_code}</span></td>
                <td>${item.is_https ? '<span style="color: var(--accent-green)">HTTPS</span>' : '<span style="color: var(--accent-red)">HTTP</span>'}</td>
                <td><strong>${item.score} / ${item.max_score}</strong></td>
                <td><button class="btn btn-sm btn-outline load-past-btn" data-id="${item.id}">View</button></td>
            `;
            tbody.appendChild(tr);
        });

        document.querySelectorAll('.load-past-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const scanId = btn.dataset.id;
                try {
                    const detailRes = await fetch(`/api/scans/${scanId}`);
                    const detailData = await detailRes.json();
                    currentScanData = detailData;
                    renderScanDashboard(detailData);
                    modal.style.display = 'none';
                } catch (e) {
                    alert('Failed to load past scan details.');
                }
            });
        });
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" style="color: var(--accent-red); text-align: center;">Error loading history: ${err.message}</td></tr>`;
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
