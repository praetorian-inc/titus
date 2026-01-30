/**
 * Titus WASM JavaScript Wrapper
 *
 * Provides content collectors and high-level page scanning for browser-based secret detection.
 *
 * Usage:
 *   1. Include wasm_exec.js (from Go distribution)
 *   2. Include this file
 *   3. Call TitusInit() to load the WASM module
 *   4. Create a scanner with TitusNewScanner("builtin")
 *   5. Call TitusScanPage(scanner) to scan all page content
 */

// Global state
let titusReady = false;
let titusGo = null;

/**
 * Initialize the Titus WASM module.
 * @param {string} wasmPath - Path to titus.wasm file (default: 'titus.wasm')
 * @returns {Promise<void>}
 */
async function TitusInit(wasmPath = 'titus.wasm') {
    if (titusReady) return;

    titusGo = new Go();
    const result = await WebAssembly.instantiateStreaming(
        fetch(wasmPath),
        titusGo.importObject
    );
    titusGo.run(result.instance);
    titusReady = true;
}

/**
 * Check if Titus WASM module is ready.
 * @returns {boolean}
 */
function TitusIsReady() {
    return titusReady;
}

// ============================================================
// Content Collectors
// ============================================================

/**
 * Collect inline script content from the page.
 * @returns {Array<{source: string, content: string, metadata: object}>}
 */
function collectInlineScripts() {
    const items = [];
    const scripts = document.querySelectorAll('script:not([src])');

    scripts.forEach((script, index) => {
        const content = script.textContent || '';
        if (content.trim().length > 0) {
            items.push({
                source: `script:inline:${index}`,
                content: content,
                metadata: {
                    type: 'javascript',
                    inline: 'true',
                    index: String(index)
                }
            });
        }
    });

    return items;
}

/**
 * Collect external script content from the page.
 * Fetches script content from URLs.
 * @returns {Promise<Array<{source: string, content: string, metadata: object}>>}
 */
async function collectExternalScripts() {
    const items = [];
    const scripts = document.querySelectorAll('script[src]');

    for (const script of scripts) {
        const src = script.src;
        try {
            // Only fetch same-origin or CORS-enabled scripts
            const response = await fetch(src, { mode: 'cors' });
            if (response.ok) {
                const content = await response.text();
                items.push({
                    source: `script:external:${src}`,
                    content: content,
                    metadata: {
                        type: 'javascript',
                        url: src
                    }
                });
            }
        } catch (e) {
            // Skip scripts that can't be fetched (CORS, network errors)
            console.debug(`Titus: Could not fetch script ${src}: ${e.message}`);
        }
    }

    return items;
}

/**
 * Collect stylesheet content from the page.
 * @returns {Promise<Array<{source: string, content: string, metadata: object}>>}
 */
async function collectStylesheets() {
    const items = [];

    // Inline styles
    const inlineStyles = document.querySelectorAll('style');
    inlineStyles.forEach((style, index) => {
        const content = style.textContent || '';
        if (content.trim().length > 0) {
            items.push({
                source: `style:inline:${index}`,
                content: content,
                metadata: {
                    type: 'css',
                    inline: 'true'
                }
            });
        }
    });

    // External stylesheets
    const links = document.querySelectorAll('link[rel="stylesheet"]');
    for (const link of links) {
        const href = link.href;
        try {
            const response = await fetch(href, { mode: 'cors' });
            if (response.ok) {
                const content = await response.text();
                items.push({
                    source: `style:external:${href}`,
                    content: content,
                    metadata: {
                        type: 'css',
                        url: href
                    }
                });
            }
        } catch (e) {
            console.debug(`Titus: Could not fetch stylesheet ${href}: ${e.message}`);
        }
    }

    return items;
}

/**
 * Collect localStorage and sessionStorage content.
 * @returns {Array<{source: string, content: string, metadata: object}>}
 */
function collectLocalStorage() {
    const items = [];

    // localStorage
    try {
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            const value = localStorage.getItem(key);
            if (value) {
                items.push({
                    source: `storage:local:${key}`,
                    content: value,
                    metadata: {
                        type: 'storage',
                        storageType: 'localStorage',
                        key: key
                    }
                });
            }
        }
    } catch (e) {
        console.debug(`Titus: Could not access localStorage: ${e.message}`);
    }

    // sessionStorage
    try {
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            const value = sessionStorage.getItem(key);
            if (value) {
                items.push({
                    source: `storage:session:${key}`,
                    content: value,
                    metadata: {
                        type: 'storage',
                        storageType: 'sessionStorage',
                        key: key
                    }
                });
            }
        }
    } catch (e) {
        console.debug(`Titus: Could not access sessionStorage: ${e.message}`);
    }

    return items;
}

// ============================================================
// Network Response Capture (Optional)
// ============================================================

let capturedResponses = [];
let networkCaptureEnabled = false;

/**
 * Enable network response capture.
 * Must be called before page loads to capture all responses.
 * Intercepts fetch and XMLHttpRequest.
 */
function enableNetworkCapture() {
    if (networkCaptureEnabled) return;
    networkCaptureEnabled = true;

    // Intercept fetch
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        const response = await originalFetch.apply(this, args);
        const url = typeof args[0] === 'string' ? args[0] : args[0].url;

        try {
            const clone = response.clone();
            const contentType = clone.headers.get('content-type') || '';

            // Only capture text-based responses
            if (contentType.includes('text') ||
                contentType.includes('json') ||
                contentType.includes('javascript') ||
                contentType.includes('xml')) {
                const text = await clone.text();
                capturedResponses.push({
                    source: `network:fetch:${url}`,
                    content: text,
                    metadata: {
                        type: 'network',
                        method: 'fetch',
                        url: url,
                        contentType: contentType
                    }
                });
            }
        } catch (e) {
            console.debug(`Titus: Could not capture fetch response: ${e.message}`);
        }

        return response;
    };

    // Intercept XMLHttpRequest
    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        this._titusUrl = url;
        this._titusMethod = method;
        return originalXHROpen.apply(this, [method, url, ...rest]);
    };

    XMLHttpRequest.prototype.send = function(...args) {
        this.addEventListener('load', function() {
            try {
                const contentType = this.getResponseHeader('content-type') || '';
                if (contentType.includes('text') ||
                    contentType.includes('json') ||
                    contentType.includes('javascript') ||
                    contentType.includes('xml')) {
                    capturedResponses.push({
                        source: `network:xhr:${this._titusUrl}`,
                        content: this.responseText,
                        metadata: {
                            type: 'network',
                            method: 'xhr',
                            url: this._titusUrl,
                            contentType: contentType
                        }
                    });
                }
            } catch (e) {
                console.debug(`Titus: Could not capture XHR response: ${e.message}`);
            }
        });
        return originalXHRSend.apply(this, args);
    };
}

/**
 * Get captured network responses.
 * @returns {Array<{source: string, content: string, metadata: object}>}
 */
function collectNetworkResponses() {
    return [...capturedResponses];
}

/**
 * Clear captured network responses.
 */
function clearNetworkResponses() {
    capturedResponses = [];
}

// ============================================================
// High-Level API
// ============================================================

/**
 * Scan all page content for secrets.
 *
 * @param {number} scannerHandle - Handle from TitusNewScanner()
 * @param {object} options - Scan options
 * @param {boolean} options.inlineScripts - Scan inline scripts (default: true)
 * @param {boolean} options.externalScripts - Scan external scripts (default: true)
 * @param {boolean} options.stylesheets - Scan stylesheets (default: true)
 * @param {boolean} options.storage - Scan localStorage/sessionStorage (default: true)
 * @param {boolean} options.network - Include captured network responses (default: true)
 * @returns {Promise<object>} Scan results
 */
async function TitusScanPage(scannerHandle, options = {}) {
    const opts = {
        inlineScripts: true,
        externalScripts: true,
        stylesheets: true,
        storage: true,
        network: true,
        ...options
    };

    if (!titusReady) {
        throw new Error('Titus WASM module not initialized. Call TitusInit() first.');
    }

    // Collect content
    const items = [];

    if (opts.inlineScripts) {
        items.push(...collectInlineScripts());
    }

    if (opts.externalScripts) {
        items.push(...await collectExternalScripts());
    }

    if (opts.stylesheets) {
        items.push(...await collectStylesheets());
    }

    if (opts.storage) {
        items.push(...collectLocalStorage());
    }

    if (opts.network && networkCaptureEnabled) {
        items.push(...collectNetworkResponses());
    }

    if (items.length === 0) {
        return {
            results: [],
            total: 0,
            itemsScanned: 0
        };
    }

    // Scan using WASM
    const itemsJSON = JSON.stringify(items);
    const resultStr = TitusScanBatch(scannerHandle, itemsJSON);

    // Parse result
    let result;
    if (typeof resultStr === 'string') {
        result = JSON.parse(resultStr);
    } else if (resultStr && resultStr.error) {
        throw new Error(resultStr.error);
    } else {
        result = resultStr;
    }

    return {
        ...result,
        itemsScanned: items.length
    };
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        TitusInit,
        TitusIsReady,
        TitusScanPage,
        collectInlineScripts,
        collectExternalScripts,
        collectStylesheets,
        collectLocalStorage,
        collectNetworkResponses,
        enableNetworkCapture,
        clearNetworkResponses
    };
}
