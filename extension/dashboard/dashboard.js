// Titus Secret Vault - Dashboard Script

// State
let allFindings = [];
let filteredFindings = [];
let currentSort = { field: 'timestamp', direction: 'desc' };
let expandedRows = new Set();

// Escape HTML (copied from popup.js)
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
}

// Decode base64 string to plaintext (copied from popup.js)
function decodeBase64(str) {
    if (typeof str !== 'string') return str;
    try {
        // Check if it looks like base64 (only contains valid base64 chars)
        if (/^[A-Za-z0-9+/=]+$/.test(str) && str.length > 10) {
            const decoded = atob(str);
            // Verify it's printable ASCII (not binary garbage)
            if (/^[\x20-\x7E\n\r\t]+$/.test(decoded)) {
                return decoded;
            }
        }
    } catch (e) {
        // Not valid base64, return original
    }
    return str;
}

// Extract secret from finding
function extractSecret(finding) {
    const secret = finding.secret || finding.Snippet?.Matching || 'N/A';
    let secretDisplay;
    if (typeof secret === 'string') {
        secretDisplay = decodeBase64(secret);
    } else if (Array.isArray(secret)) {
        secretDisplay = String.fromCharCode(...secret);
    } else {
        secretDisplay = String(secret);
    }
    return secretDisplay;
}

// Truncate text with ellipsis
function truncate(text, maxLength = 50) {
    if (!text || text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3) + '...';
}

// Format URL for display
function formatUrl(url, maxLength = 60) {
    try {
        const urlObj = new URL(url);
        let display = urlObj.hostname + urlObj.pathname;
        if (display.length > maxLength) {
            display = display.substring(0, maxLength - 3) + '...';
        }
        return display;
    } catch {
        return truncate(url, maxLength);
    }
}

// Format time ago (copied from popup.js)
function formatTimeAgo(timestamp) {
    const seconds = Math.floor((Date.now() - timestamp) / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    return `${Math.floor(minutes / 60)}h ago`;
}

// Update stats
async function updateStats() {
    const stats = await chrome.runtime.sendMessage({ action: 'getStats' });
    document.getElementById('total-count').textContent = `${stats.totalFindings} finding${stats.totalFindings !== 1 ? 's' : ''}`;
    document.getElementById('site-count').textContent = `${stats.uniqueSites} site${stats.uniqueSites !== 1 ? 's' : ''}`;

    // Count unique rule types
    const uniqueRules = new Set(allFindings.map(f => f.ruleName || f.RuleName));
    document.getElementById('rule-count').textContent = `${uniqueRules.size} rule type${uniqueRules.size !== 1 ? 's' : ''}`;
}

// Update queue status display (copied from popup.js)
async function updateQueueStatus() {
    try {
        const status = await chrome.runtime.sendMessage({ action: 'getQueueStatus' });
        const container = document.getElementById('queue-status');
        const countEl = document.getElementById('queue-count');
        const detailsEl = document.getElementById('queue-details');

        if (!status.wasmReady) {
            container.classList.remove('hidden');
            countEl.textContent = '⚠️';
            detailsEl.innerHTML = '<div class="queue-item queue-loading">Initializing WASM scanner...</div>';
            return;
        }

        if (status.queueLength === 0 && !status.isProcessing) {
            container.classList.add('hidden');
            return;
        }

        container.classList.remove('hidden');
        countEl.textContent = status.queueLength;

        let html = '';

        // Show currently scanning item with progress
        if (status.isProcessing && status.progress) {
            const p = status.progress;
            const progressText = `${p.processedItems}/${p.totalItems} items`;
            const findingsText = p.findings > 0 ? ` • ${p.findings} found` : '';
            html += `
                <div class="queue-item queue-active">
                    <span class="queue-item-icon">🔍</span>
                    <span class="queue-item-url">${escapeHtml(formatUrl(p.url))}</span>
                    <span class="queue-item-status">${progressText}${findingsText}</span>
                </div>
                <div class="queue-progress-bar">
                    <div class="queue-progress-fill" style="width: ${Math.round(p.processedItems / p.totalItems * 100)}%"></div>
                </div>
            `;
        } else if (status.isProcessing && status.currentlyScanning) {
            html += `
                <div class="queue-item queue-active">
                    <span class="queue-item-icon">🔍</span>
                    <span class="queue-item-url">${escapeHtml(formatUrl(status.currentlyScanning))}</span>
                    <span class="queue-item-status">Starting...</span>
                </div>
            `;
        }

        // Show queued items
        if (status.queue && status.queue.length > 0) {
            const queuedItems = status.isProcessing ? status.queue.slice(1) : status.queue;

            queuedItems.forEach((item, index) => {
                html += `
                    <div class="queue-item queue-pending">
                        <span class="queue-item-icon">${index + 1}</span>
                        <span class="queue-item-url">${escapeHtml(formatUrl(item.url))}</span>
                        <span class="queue-item-meta">${item.itemCount} items • ${formatTimeAgo(item.queuedAt)}</span>
                    </div>
                `;
            });
        }

        if (!html) {
            html = '<div class="queue-item queue-empty">Queue empty</div>';
        }

        detailsEl.innerHTML = html;
    } catch (err) {
        console.error('Failed to update queue status:', err);
    }
}

// Load all findings
async function loadFindings() {
    allFindings = await chrome.runtime.sendMessage({ action: 'getAllFindings' });
    applyFilters();
    updateStats();
    populateRuleFilter();
}

// Populate rule type filter dropdown
function populateRuleFilter() {
    const select = document.getElementById('rule-filter');
    const uniqueRules = new Set(allFindings.map(f => f.ruleName || f.RuleName));

    // Clear existing options except "All Rules"
    select.innerHTML = '<option value="">All Rules</option>';

    // Add rule options sorted alphabetically
    Array.from(uniqueRules)
        .sort()
        .forEach(rule => {
            const option = document.createElement('option');
            option.value = rule;
            option.textContent = rule;
            select.appendChild(option);
        });
}

// Apply filters
function applyFilters() {
    const ruleFilter = document.getElementById('rule-filter').value;
    const searchFilter = document.getElementById('search-filter').value.toLowerCase();

    filteredFindings = allFindings.filter(finding => {
        // Rule filter
        if (ruleFilter) {
            const ruleName = finding.ruleName || finding.RuleName || '';
            if (ruleName !== ruleFilter) return false;
        }

        // Search filter
        if (searchFilter) {
            const secret = extractSecret(finding).toLowerCase();
            const url = (finding.url || '').toLowerCase();
            const source = (finding.source || '').toLowerCase();

            if (!secret.includes(searchFilter) &&
                !url.includes(searchFilter) &&
                !source.includes(searchFilter)) {
                return false;
            }
        }

        return true;
    });

    sortFindings();
    renderTable();
}

// Sort findings
function sortFindings() {
    filteredFindings.sort((a, b) => {
        let aVal, bVal;

        switch (currentSort.field) {
            case 'rule':
                aVal = a.ruleName || a.RuleName || '';
                bVal = b.ruleName || b.RuleName || '';
                break;
            case 'secret':
                aVal = extractSecret(a);
                bVal = extractSecret(b);
                break;
            case 'source':
                aVal = a.source || '';
                bVal = b.source || '';
                break;
            case 'url':
                aVal = a.url || '';
                bVal = b.url || '';
                break;
            case 'timestamp':
                aVal = new Date(a.timestamp).getTime();
                bVal = new Date(b.timestamp).getTime();
                break;
            default:
                return 0;
        }

        if (typeof aVal === 'string') {
            aVal = aVal.toLowerCase();
            bVal = bVal.toLowerCase();
        }

        const comparison = aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
        return currentSort.direction === 'asc' ? comparison : -comparison;
    });
}

// Render table
function renderTable() {
    const tbody = document.getElementById('findings-tbody');
    tbody.innerHTML = '';

    if (filteredFindings.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-state-row">
                <td colspan="6">
                    <div class="empty-state">No secrets found matching filters</div>
                </td>
            </tr>
        `;
        return;
    }

    filteredFindings.forEach((finding, index) => {
        const row = createTableRow(finding, index);
        tbody.appendChild(row);

        // Re-add detail row if it was expanded
        if (expandedRows.has(index)) {
            const detailRow = createDetailRow(finding, index);
            tbody.appendChild(detailRow);
        }
    });
}

// Create table row
function createTableRow(finding, index) {
    const tr = document.createElement('tr');
    tr.className = 'finding-row';
    tr.dataset.index = index;

    const secret = extractSecret(finding);
    const ruleName = finding.ruleName || finding.RuleName || 'Unknown';
    const source = finding.source || 'Unknown';
    const url = finding.url || 'Unknown';
    const timestamp = new Date(finding.timestamp).toLocaleString();

    tr.innerHTML = `
        <td>${escapeHtml(ruleName)}</td>
        <td class="secret-cell" title="${escapeHtml(secret)}">${escapeHtml(truncate(secret, 40))}</td>
        <td>${escapeHtml(truncate(source, 30))}</td>
        <td title="${escapeHtml(url)}">${escapeHtml(formatUrl(url))}</td>
        <td>${timestamp}</td>
        <td>
            <button class="btn btn-small expand-btn" data-index="${index}">
                ${expandedRows.has(index) ? '▲' : '▼'} Details
            </button>
        </td>
    `;

    // Click handler for expand button
    const expandBtn = tr.querySelector('.expand-btn');
    expandBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleDetailRow(index);
    });

    return tr;
}

// Create detail row
function createDetailRow(finding, index) {
    const template = document.getElementById('detail-row-template');
    const detailRow = template.content.cloneNode(true).querySelector('.detail-row');
    detailRow.dataset.index = index;

    const secret = extractSecret(finding);
    const ruleName = finding.ruleName || finding.RuleName || 'Unknown';
    const source = finding.source || 'Unknown';
    const url = finding.url || 'Unknown';
    const timestamp = new Date(finding.timestamp).toLocaleString();

    // Populate detail content
    detailRow.querySelector('.detail-secret').textContent = secret;
    detailRow.querySelector('.detail-rule').textContent = ruleName;
    detailRow.querySelector('.detail-source').textContent = source;
    detailRow.querySelector('.detail-url').textContent = url;
    detailRow.querySelector('.detail-timestamp').textContent = timestamp;

    // Show location if available
    if (finding.location?.Source?.Start?.Line) {
        const locationEl = detailRow.querySelector('.detail-location');
        locationEl.style.display = 'block';
        locationEl.querySelector('.detail-location-text').textContent =
            `Line ${finding.location.Source.Start.Line}`;
    }

    // Copy button handler
    const copyBtn = detailRow.querySelector('.copy-detail-btn');
    copyBtn.addEventListener('click', async () => {
        await navigator.clipboard.writeText(secret);

        // Visual feedback
        const originalText = copyBtn.textContent;
        copyBtn.textContent = '✓ Copied!';
        copyBtn.classList.add('copied');
        setTimeout(() => {
            copyBtn.textContent = originalText;
            copyBtn.classList.remove('copied');
        }, 1500);
    });

    return detailRow;
}

// Toggle detail row
function toggleDetailRow(index) {
    const tbody = document.getElementById('findings-tbody');
    const existingDetailRow = tbody.querySelector(`.detail-row[data-index="${index}"]`);

    if (existingDetailRow) {
        // Collapse
        existingDetailRow.remove();
        expandedRows.delete(index);
    } else {
        // Expand
        const finding = filteredFindings[index];
        const detailRow = createDetailRow(finding, index);

        // Find the finding row and insert after it
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const findingRow = rows.find(row => row.dataset.index === String(index));

        if (findingRow) {
            findingRow.after(detailRow);
            expandedRows.add(index);
        }
    }

    // Update button text
    const btn = tbody.querySelector(`.finding-row[data-index="${index}"] .expand-btn`);
    if (btn) {
        btn.textContent = expandedRows.has(index) ? '▲ Details' : '▼ Details';
    }
}

// Setup table sorting
function setupSorting() {
    const headers = document.querySelectorAll('.sortable');
    headers.forEach(header => {
        header.addEventListener('click', () => {
            const field = header.dataset.sort;

            // Toggle direction if clicking same field
            if (currentSort.field === field) {
                currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
            } else {
                currentSort.field = field;
                currentSort.direction = 'asc';
            }

            // Update UI
            headers.forEach(h => {
                h.classList.remove('active', 'asc', 'desc');
                h.querySelector('.sort-indicator').textContent = '';
            });
            header.classList.add('active', currentSort.direction);
            header.querySelector('.sort-indicator').textContent =
                currentSort.direction === 'asc' ? '▲' : '▼';

            // Re-sort and render
            sortFindings();
            renderTable();
        });
    });
}

// Export functionality
async function exportFindings() {
    const json = await chrome.runtime.sendMessage({ action: 'exportFindings' });

    // Create download
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `titus-findings-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

// Clear functionality
async function clearFindings() {
    if (confirm('Are you sure you want to clear all findings? This cannot be undone.')) {
        await chrome.runtime.sendMessage({ action: 'clearFindings' });
        loadFindings();
    }
}

// Queue status polling interval
let queuePollInterval = null;

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
    // Load initial data
    await Promise.all([
        loadFindings(),
        updateQueueStatus()
    ]);

    // Setup event listeners
    setupSorting();

    document.getElementById('rule-filter').addEventListener('change', applyFilters);
    document.getElementById('search-filter').addEventListener('input', applyFilters);
    document.getElementById('clear-filters').addEventListener('click', () => {
        document.getElementById('rule-filter').value = '';
        document.getElementById('search-filter').value = '';
        applyFilters();
    });

    document.getElementById('export-btn').addEventListener('click', exportFindings);
    document.getElementById('clear-btn').addEventListener('click', clearFindings);

    // Start polling queue status every second
    queuePollInterval = setInterval(updateQueueStatus, 1000);
});

// Clean up interval when page closes
window.addEventListener('unload', () => {
    if (queuePollInterval) {
        clearInterval(queuePollInterval);
    }
});
