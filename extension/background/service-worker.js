// Titus Browser Extension - Background Service Worker
// Manages WASM lifecycle, scan queue, and handles requests

// Import dependencies using importScripts (classic script mode)
importScripts('../storage/db.js');
importScripts('../lib/wasm_exec.js');
importScripts('../lib/titus.js');

// WASM state
let wasmReady = false;
let scannerHandle = null;
let wasmInitializing = false;

// Scan queue
const scanQueue = [];
let isProcessingQueue = false;
let currentScanProgress = null; // Track progress within current scan

console.log('[Titus] Service worker started');

// On install, immediately activate
chrome.runtime.onInstalled.addListener((details) => {
    console.log('[Titus] Extension installed/updated:', details.reason);
    // Inject content scripts into all existing tabs
    injectIntoExistingTabs();
});

// On startup (browser restart), also inject
chrome.runtime.onStartup.addListener(() => {
    console.log('[Titus] Browser started');
    injectIntoExistingTabs();
});

// Inject content scripts into all existing tabs
async function injectIntoExistingTabs() {
    try {
        const tabs = await chrome.tabs.query({});
        for (const tab of tabs) {
            // Skip chrome://, edge://, about:, etc.
            if (!tab.url || !tab.url.startsWith('http')) continue;

            try {
                // Inject CSS first
                await chrome.scripting.insertCSS({
                    target: { tabId: tab.id },
                    files: ['content/toast.css']
                });
                // Then inject JS
                await chrome.scripting.executeScript({
                    target: { tabId: tab.id },
                    files: ['content/content.js']
                });
                console.log(`[Titus] Injected into existing tab: ${tab.url}`);
            } catch (e) {
                // Ignore errors for tabs we can't inject into (e.g., chrome:// pages)
                console.log(`[Titus] Could not inject into ${tab.url}: ${e.message}`);
            }
        }
    } catch (e) {
        console.error('[Titus] Error injecting into existing tabs:', e);
    }
}

// Initialize WASM
async function ensureWASMReady() {
    if (wasmReady && scannerHandle !== null) {
        return true;
    }

    if (wasmInitializing) {
        // Wait for initialization to complete
        while (wasmInitializing) {
            await new Promise(r => setTimeout(r, 100));
        }
        return wasmReady;
    }

    wasmInitializing = true;

    try {
        console.log('[Titus] Initializing WASM...');
        const wasmUrl = chrome.runtime.getURL('lib/titus.wasm');
        await TitusInit(wasmUrl);

        // Use builtin rules embedded in WASM (from pkg/rule/rules/*.yml)
        console.log('[Titus] Creating scanner with builtin rules...');
        const result = TitusNewScanner('builtin');
        if (result.error) {
            throw new Error(result.error);
        }
        scannerHandle = result.handle;
        wasmReady = true;

        console.log('[Titus] WASM initialized successfully with builtin rules');
        return true;
    } catch (err) {
        console.error('[Titus] WASM initialization failed:', err);
        wasmReady = false;
        scannerHandle = null;
        return false;
    } finally {
        wasmInitializing = false;
    }
}

// Add to scan queue
function queueScan(tabId, url, content) {
    console.log(`[Titus] Queuing scan for ${url} (${content.length} items)`);

    // Remove any existing queue entry for this URL (replace with newer content)
    const existingIndex = scanQueue.findIndex(item => item.url === url);
    if (existingIndex >= 0) {
        scanQueue.splice(existingIndex, 1);
    }

    scanQueue.push({
        tabId,
        url,
        content,
        queuedAt: Date.now()
    });

    // Update badge to show queued
    chrome.action.setBadgeText({ text: '...', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#666', tabId });

    // Start processing if not already
    processQueue();
}

// Process scan queue
async function processQueue() {
    if (isProcessingQueue) return;
    if (scanQueue.length === 0) return;

    isProcessingQueue = true;
    console.log(`[Titus] Processing queue (${scanQueue.length} items)`);

    try {
        // Ensure WASM is ready
        if (!await ensureWASMReady()) {
            console.error('[Titus] Cannot process queue - WASM not available');
            isProcessingQueue = false;
            return;
        }

        while (scanQueue.length > 0) {
            const item = scanQueue.shift();
            await processScanItem(item);
        }
    } catch (err) {
        console.error('[Titus] Queue processing error:', err);
    } finally {
        isProcessingQueue = false;
    }
}

// Process a single scan item
async function processScanItem(item) {
    const { tabId, url, content } = item;
    console.log(`[Titus] Scanning ${url} (${content.length} items)...`);

    const startTime = Date.now();
    let totalFindings = 0;

    // Initialize progress tracking
    currentScanProgress = {
        url,
        totalItems: content.length,
        processedItems: 0,
        currentBatch: 0,
        totalBatches: Math.ceil(content.length / 10),
        findings: 0
    };

    try {
        // Process in batches to avoid blocking
        const batchSize = 10;
        for (let i = 0; i < content.length; i += batchSize) {
            const batch = content.slice(i, i + batchSize);

            // Update progress
            currentScanProgress.currentBatch = Math.floor(i / batchSize) + 1;
            currentScanProgress.processedItems = Math.min(i + batchSize, content.length);

            const resultsJson = TitusScanBatch(scannerHandle, JSON.stringify(batch));
            const results = JSON.parse(resultsJson);

            if (results.error) {
                console.error(`[Titus] Batch scan error: ${results.error}`);
                continue;
            }

            if (results.total > 0) {
                totalFindings += results.total;
                currentScanProgress.findings = totalFindings;
                await storeFindings(url, results);
            }

            // Small yield to prevent blocking
            await new Promise(r => setTimeout(r, 0));
        }

        const elapsed = Date.now() - startTime;
        console.log(`[Titus] Scan complete for ${url}: ${totalFindings} findings in ${elapsed}ms`);

        // Update badge
        if (totalFindings > 0) {
            chrome.action.setBadgeText({ text: String(totalFindings), tabId });
            chrome.action.setBadgeBackgroundColor({ color: '#107C10', tabId }); // Xbox green
        } else {
            chrome.action.setBadgeText({ text: '✓', tabId });
            chrome.action.setBadgeBackgroundColor({ color: '#333', tabId });
            // Clear the checkmark after 2 seconds
            setTimeout(() => {
                chrome.action.setBadgeText({ text: '', tabId }).catch(() => {});
            }, 2000);
        }

        // Notify the ACTIVE tab (not the scanned tab) so user sees notification wherever they are
        try {
            const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (activeTab?.id) {
                chrome.tabs.sendMessage(activeTab.id, {
                    action: 'scanComplete',
                    url,
                    total: totalFindings,
                    scannedTabId: tabId
                }).catch(() => {}); // Ignore if tab can't receive messages
            }
        } catch (e) {
            // Tab query may fail
        }

    } catch (err) {
        console.error(`[Titus] Scan error for ${url}:`, err);
        chrome.action.setBadgeText({ text: '!', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#c00', tabId });
    } finally {
        // Clear progress tracking
        currentScanProgress = null;
    }
}

// Message handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const tab = sender.tab;

    switch (message.action) {
        case 'queueScan':
            // Queue the scan and respond immediately
            if (tab && message.content) {
                queueScan(tab.id, tab.url, message.content);
                sendResponse({ queued: true, position: scanQueue.length });
            } else {
                sendResponse({ error: 'Missing tab or content' });
            }
            return false; // Synchronous response

        case 'getQueueStatus':
            // Include detailed queue info for the popup
            const queueInfo = scanQueue.map(item => ({
                url: item.url,
                itemCount: item.content.length,
                queuedAt: item.queuedAt
            }));
            sendResponse({
                queueLength: scanQueue.length,
                isProcessing: isProcessingQueue,
                wasmReady,
                queue: queueInfo,
                currentlyScanning: isProcessingQueue && currentScanProgress ? currentScanProgress.url : null,
                progress: currentScanProgress // Include detailed progress info
            });
            return false;

        case 'getFindings':
            getFindings(message.url).then(sendResponse);
            return true;

        case 'getAllFindings':
            getAllFindings().then(sendResponse);
            return true;

        case 'clearFindings':
            clearFindings().then(() => sendResponse({ success: true }));
            return true;

        case 'exportFindings':
            exportFindings().then(sendResponse);
            return true;

        case 'getStats':
            getStats().then(sendResponse);
            return true;

        case 'openPopup':
            chrome.action.openPopup?.() || console.log('[Titus] Popup requested');
            sendResponse({ success: true });
            return false;

        default:
            sendResponse({ error: 'Unknown action' });
            return false;
    }
});

// Clear badge when tab is updated/navigated
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'loading') {
        chrome.action.setBadgeText({ text: '', tabId });
    }
});

// Initialize WASM on startup (don't wait)
ensureWASMReady();
