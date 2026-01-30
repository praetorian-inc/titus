// Titus Secret Vault - Popup Script

// Escape HTML
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
}

// Update stats
async function updateStats() {
    const stats = await chrome.runtime.sendMessage({ action: 'getStats' });
    document.getElementById('total-count').textContent = stats.totalFindings;
    document.getElementById('site-count').textContent = stats.uniqueSites;
}

// Format URL for display (truncate)
function formatUrl(url, maxLength = 40) {
    try {
        const urlObj = new URL(url);
        let display = urlObj.hostname + urlObj.pathname;
        if (display.length > maxLength) {
            display = display.substring(0, maxLength - 3) + '...';
        }
        return display;
    } catch {
        return url.substring(0, maxLength);
    }
}

// Format time ago
function formatTimeAgo(timestamp) {
    const seconds = Math.floor((Date.now() - timestamp) / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    return `${Math.floor(minutes / 60)}h ago`;
}

// Update queue status display
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
            // Skip first item if it's currently being scanned
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

// Open dashboard
function openDashboard() {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/dashboard.html') });
}

// Load and apply toast style preference
async function loadStylePreference() {
    const result = await chrome.storage.local.get(['toastStyle']);
    const style = result.toastStyle || 'modern';
    updateStyleToggle(style);
}

// Update style toggle buttons UI
function updateStyleToggle(style) {
    const modernBtn = document.getElementById('style-modern');
    const classicBtn = document.getElementById('style-classic');

    if (style === 'modern') {
        modernBtn.classList.add('active');
        classicBtn.classList.remove('active');
    } else {
        modernBtn.classList.remove('active');
        classicBtn.classList.add('active');
    }
}

// Save toast style preference
async function setStylePreference(style) {
    await chrome.storage.local.set({ toastStyle: style });
    updateStyleToggle(style);
}

// Queue status polling interval
let queuePollInterval = null;

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
    // Load initial data
    await Promise.all([
        updateStats(),
        updateQueueStatus(),
        loadStylePreference()
    ]);

    // Start polling queue status every second
    queuePollInterval = setInterval(updateQueueStatus, 1000);

    // Button handlers
    document.getElementById('open-dashboard').addEventListener('click', openDashboard);

    // Style toggle handlers
    document.getElementById('style-modern').addEventListener('click', () => setStylePreference('modern'));
    document.getElementById('style-classic').addEventListener('click', () => setStylePreference('classic'));
});

// Clean up interval when popup closes
window.addEventListener('unload', () => {
    if (queuePollInterval) {
        clearInterval(queuePollInterval);
    }
});
