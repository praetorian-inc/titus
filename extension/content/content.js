// Titus Browser Extension - Content Script
// Collects page content and triggers WASM scanning

(function() {
    'use strict';

    // Prevent multiple injections
    if (window.__titusScanned) return;
    window.__titusScanned = true;

    console.log('[Titus] Content script loaded on:', window.location.href);

    // Fetch external script content
    async function fetchExternalScript(url) {
        try {
            const response = await fetch(url, {
                mode: 'cors',
                credentials: 'omit'
            });
            if (response.ok) {
                return await response.text();
            }
        } catch (e) {
            // CORS or network error - try without CORS
            try {
                const response = await fetch(url);
                if (response.ok) {
                    return await response.text();
                }
            } catch (e2) {
                console.log(`[Titus] Could not fetch ${url}: ${e2.message}`);
            }
        }
        return null;
    }

    // Collect page content for scanning
    async function collectContent() {
        const items = [];

        // Inline scripts
        document.querySelectorAll('script:not([src])').forEach((script, i) => {
            const content = script.textContent?.trim();
            if (content && content.length > 0) {
                items.push({
                    source: `script:inline:${i}`,
                    content,
                    metadata: { type: 'javascript', inline: 'true', index: String(i) }
                });
            }
        });

        console.log(`[Titus] Found ${items.length} inline scripts`);

        // External scripts - fetch their content
        const externalScripts = document.querySelectorAll('script[src]');
        console.log(`[Titus] Found ${externalScripts.length} external scripts to fetch`);

        for (const script of externalScripts) {
            const src = script.src;
            if (!src) continue;

            // Skip chrome-extension:// URLs and data: URLs
            if (src.startsWith('chrome-extension://') || src.startsWith('data:')) continue;

            const content = await fetchExternalScript(src);
            if (content && content.length > 0) {
                items.push({
                    source: `script:external:${src}`,
                    content,
                    metadata: { type: 'javascript', url: src }
                });
                console.log(`[Titus] Fetched external script: ${src.substring(0, 80)}...`);
            }
        }

        // Inline styles
        document.querySelectorAll('style').forEach((style, i) => {
            const content = style.textContent?.trim();
            if (content && content.length > 0) {
                items.push({
                    source: `style:inline:${i}`,
                    content,
                    metadata: { type: 'css', inline: 'true', index: String(i) }
                });
            }
        });

        // External stylesheets
        const externalStyles = document.querySelectorAll('link[rel="stylesheet"]');
        for (const link of externalStyles) {
            const href = link.href;
            if (!href || href.startsWith('chrome-extension://')) continue;

            try {
                const response = await fetch(href);
                if (response.ok) {
                    const content = await response.text();
                    if (content && content.length > 0) {
                        items.push({
                            source: `style:external:${href}`,
                            content,
                            metadata: { type: 'css', url: href }
                        });
                    }
                }
            } catch (e) {
                // Ignore fetch errors
            }
        }

        // LocalStorage
        try {
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                const value = localStorage.getItem(key);
                if (value) {
                    items.push({
                        source: `storage:local:${key}`,
                        content: value,
                        metadata: { type: 'storage', storageType: 'localStorage', key }
                    });
                }
            }
        } catch (e) {
            // Storage access may be restricted
        }

        // SessionStorage
        try {
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                const value = sessionStorage.getItem(key);
                if (value) {
                    items.push({
                        source: `storage:session:${key}`,
                        content: value,
                        metadata: { type: 'storage', storageType: 'sessionStorage', key }
                    });
                }
            }
        } catch (e) {
            // Storage access may be restricted
        }

        // HTML attributes that might contain secrets (data-*, config attributes)
        document.querySelectorAll('[data-api-key], [data-token], [data-secret], [data-config]').forEach((el, i) => {
            const attrs = ['data-api-key', 'data-token', 'data-secret', 'data-config'];
            attrs.forEach(attr => {
                const value = el.getAttribute(attr);
                if (value) {
                    items.push({
                        source: `attr:${attr}:${i}`,
                        content: value,
                        metadata: { type: 'attribute', attribute: attr }
                    });
                }
            });
        });

        // Meta tags (sometimes contain config/API info)
        document.querySelectorAll('meta[name], meta[property]').forEach((meta, i) => {
            const name = meta.getAttribute('name') || meta.getAttribute('property');
            const content = meta.getAttribute('content');
            if (content && content.length > 10) {  // Skip very short values
                items.push({
                    source: `meta:${name}:${i}`,
                    content,
                    metadata: { type: 'meta', name }
                });
            }
        });

        // Also scan the full HTML for any secrets that might be in comments or elsewhere
        const fullHtml = document.documentElement.outerHTML;
        if (fullHtml && fullHtml.length > 0) {
            items.push({
                source: 'html:full',
                content: fullHtml,
                metadata: { type: 'html' }
            });
        }

        return items;
    }

    // Escape HTML for safe display
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    }

    // Format URL for display
    function formatUrlShort(url) {
        try {
            const urlObj = new URL(url);
            let display = urlObj.hostname + urlObj.pathname;
            if (display.length > 35) {
                display = display.substring(0, 32) + '...';
            }
            return display;
        } catch {
            return url.substring(0, 35);
        }
    }

    // Toast queue for showing multiple toasts
    let toastQueue = [];
    let isShowingToasts = false;
    let toastCounter = 0;
    let toastStyle = 'modern'; // 'modern' (Xbox One) or 'classic' (Xbox 360)

    // Load toast style preference
    chrome.storage.local.get(['toastStyle'], (result) => {
        toastStyle = result.toastStyle || 'modern';
    });

    // Decode base64 string to plaintext (Go encodes []byte as base64 in JSON)
    function decodeBase64(str) {
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

    // Convert byte array or base64 string to plaintext
    function byteArrayToString(value) {
        if (typeof value === 'string') {
            return decodeBase64(value);
        }
        if (Array.isArray(value)) {
            try {
                return String.fromCharCode(...value);
            } catch (e) {
                return value.map(b => String.fromCharCode(b)).join('');
            }
        }
        return null;
    }

    // Extract secret value from a match (handles both WASM results and DB findings)
    function extractSecretValue(match) {
        // Try direct secret field first (from DB findings)
        if (match.secret) {
            return byteArrayToString(match.secret) || match.secret;
        }
        // Try Groups (captured groups from regex - WASM results)
        if (match.Groups && match.Groups.length > 0) {
            const converted = byteArrayToString(match.Groups[0]);
            if (converted) return converted;
        }
        // Try Snippet.Matching (WASM results) - strip HTML tags as snippet may contain HTML context
        if (match.Snippet?.Matching) {
            let converted = byteArrayToString(match.Snippet.Matching);
            if (converted) {
                // Strip HTML tags that may be included from full page scan
                return converted.replace(/<[^>]*>/g, '').trim();
            }
        }
        return null;
    }

    // Show multiple achievement toasts for each finding
    function showAchievementToasts(results) {
        // Check if this is from a different page
        const isDifferentPage = results.scannedUrl && results.scannedUrl !== window.location.href;
        const sourceUrl = isDifferentPage ? results.scannedUrl : null;

        // Collect all individual findings
        const findings = [];

        if (results.results) {
            for (const result of results.results) {
                if (result.matches) {
                    for (const match of result.matches) {
                        const secretValue = extractSecretValue(match);
                        if (secretValue) {
                            findings.push({
                                ruleName: match.RuleName || match.ruleName || 'Secret',
                                ruleId: match.RuleID || match.ruleId || '',
                                secret: secretValue,
                                source: result.Source || result.source || '',
                                sourceUrl
                            });
                        }
                    }
                }
            }
        }

        // Also handle flat findings array (from getFindings)
        if (Array.isArray(results) || (results.length !== undefined && !results.results)) {
            const arr = Array.isArray(results) ? results : [];
            for (const finding of arr) {
                const secretValue = extractSecretValue(finding) || finding.secret;
                if (secretValue) {
                    findings.push({
                        ruleName: finding.RuleName || finding.ruleName || 'Secret',
                        ruleId: finding.RuleID || finding.ruleId || '',
                        secret: secretValue,
                        source: finding.source || '',
                        sourceUrl
                    });
                }
            }
        }

        if (findings.length === 0) return;

        // Queue all findings for display
        toastQueue.push(...findings);
        processToastQueue();
    }

    // Process toast queue - show toasts with stagger
    function processToastQueue() {
        if (isShowingToasts || toastQueue.length === 0) return;
        isShowingToasts = true;

        // Show up to 5 toasts at once, staggered
        const toShow = toastQueue.splice(0, 5);
        const remainingCount = toastQueue.length;

        toShow.forEach((finding, index) => {
            setTimeout(() => {
                showSingleToast(finding, index, remainingCount > 0 && index === toShow.length - 1 ? remainingCount : 0);
            }, index * 300); // Stagger by 300ms
        });

        // After all toasts shown, check for more
        setTimeout(() => {
            isShowingToasts = false;
            if (toastQueue.length > 0) {
                setTimeout(processToastQueue, 1000);
            }
        }, toShow.length * 300 + 100);
    }

    // Show a single toast
    function showSingleToast(finding, stackIndex = 0, moreCount = 0) {
        const toastId = `titus-toast-${++toastCounter}`;
        const isClassic = toastStyle === 'classic';

        const sourceInfo = finding.sourceUrl ? escapeHtml(formatUrlShort(finding.sourceUrl)) : '';
        const moreInfo = moreCount > 0 ? `+${moreCount} more...` : '';

        // Create toast
        const toast = document.createElement('div');
        toast.id = toastId;
        toast.className = isClassic ? 'titus-toast titus-classic' : 'titus-toast';

        // Stack offset - bottom for modern, top for classic
        if (isClassic) {
            toast.style.top = `${20 + (stackIndex * 160)}px`;
        } else {
            toast.style.bottom = `${20 + (stackIndex * 140)}px`;
        }

        if (isClassic) {
            // Xbox 360 Classic Layout
            toast.innerHTML = `
                <button class="titus-toast-close">×</button>
                <div class="titus-toast-content">
                    <div class="titus-toast-banner">
                        <div class="titus-toast-banner-icon"></div>
                        <span class="titus-toast-title">Secret Unlocked</span>
                    </div>
                    <div class="titus-toast-body">
                        <div class="titus-toast-rule">${escapeHtml(finding.ruleName)}</div>
                        <div class="titus-toast-secret">${escapeHtml(finding.secret)}</div>
                        ${sourceInfo ? `<div class="titus-toast-source">${sourceInfo}</div>` : ''}
                        <div class="titus-toast-gamerscore">+50 pts</div>
                        ${moreInfo ? `<div class="titus-toast-more">${moreInfo}</div>` : ''}
                    </div>
                </div>
            `;
        } else {
            // Xbox One Modern Layout
            toast.innerHTML = `
                <div class="titus-toast-content">
                    <div class="titus-toast-icon-container">
                        <span class="titus-toast-icon">🔓</span>
                    </div>
                    <div class="titus-toast-text">
                        <div class="titus-toast-header">
                            <span class="titus-toast-title">Achievement Unlocked</span>
                            <button class="titus-toast-close">×</button>
                        </div>
                        <div class="titus-toast-rule">${escapeHtml(finding.ruleName)}</div>
                        <div class="titus-toast-secret">${escapeHtml(finding.secret)}</div>
                        ${sourceInfo ? `<div class="titus-toast-source">${sourceInfo}</div>` : ''}
                        <div class="titus-toast-gamerscore">+50 Gamerscore</div>
                        ${moreInfo ? `<div class="titus-toast-more">${moreInfo}</div>` : ''}
                    </div>
                </div>
            `;
        }

        // Close button handler
        const closeBtn = toast.querySelector('.titus-toast-close');
        closeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            dismissToast(toast);
        });

        // Click to open dashboard
        toast.addEventListener('click', () => {
            chrome.runtime.sendMessage({ action: 'openPopup' });
        });

        document.body.appendChild(toast);

        // Auto-dismiss after 8 seconds
        setTimeout(() => dismissToast(toast), 8000);
    }

    // Legacy function for backwards compatibility
    function showAchievementToast(results) {
        showAchievementToasts(results);
    }

    function dismissToast(toast) {
        if (!toast || !toast.parentNode) return;
        toast.classList.add('titus-toast-exit');
        setTimeout(() => toast.remove(), 300);
    }

    // Scan page - queues content for async scanning
    async function scanPage() {
        console.log('[Titus] Starting page content collection...');

        const content = await collectContent();

        if (content.length === 0) {
            console.log('[Titus] No content to scan');
            return;
        }

        console.log(`[Titus] Collected ${content.length} items, queuing for scan...`);

        // Fire and forget - queue the scan and don't wait for results
        // The service worker will process the queue asynchronously
        chrome.runtime.sendMessage({
            action: 'queueScan',
            content
        }).then(response => {
            if (response?.queued) {
                console.log(`[Titus] Scan queued successfully (position: ${response.position})`);
            } else if (response?.error) {
                console.error('[Titus] Queue error:', response.error);
            }
        }).catch(err => {
            console.error('[Titus] Communication error:', err);
        });
    }

    // Listen for scan completion messages from service worker
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.action === 'scanComplete') {
            console.log(`[Titus] Scan complete for ${message.url}: ${message.total} findings`);

            if (message.total > 0) {
                // Fetch the findings to show toast
                chrome.runtime.sendMessage({ action: 'getFindings', url: message.url })
                    .then(findings => {
                        if (findings && findings.length > 0) {
                            showAchievementToast({
                                total: message.total,
                                results: findings.map(f => ({ matches: [f] })),
                                scannedUrl: message.url  // Pass the scanned URL for display
                            });
                        }
                    });
            }
        }
        return false;
    });

    // Run scan after DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            // Small delay to let dynamic content load
            setTimeout(scanPage, 500);
        });
    } else {
        // DOM already loaded
        setTimeout(scanPage, 500);
    }
})();
