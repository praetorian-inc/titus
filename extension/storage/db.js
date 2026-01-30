// IndexedDB wrapper for Titus findings storage
// Note: Using global functions (not ES modules) for service worker compatibility

const DB_NAME = 'TitusDB';
const DB_VERSION = 1;

let db = null;

async function getDB() {
    if (db) return db;

    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            db = request.result;
            resolve(db);
        };

        request.onupgradeneeded = (event) => {
            const database = event.target.result;

            // Findings store
            if (!database.objectStoreNames.contains('findings')) {
                const store = database.createObjectStore('findings', {
                    keyPath: 'id',
                    autoIncrement: true
                });
                store.createIndex('url', 'url', { unique: false });
                store.createIndex('timestamp', 'timestamp', { unique: false });
                store.createIndex('ruleId', 'ruleId', { unique: false });
                store.createIndex('structuralId', 'structuralId', { unique: true });
            }
        };
    });
}

// Decode base64 string to plaintext
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
        // Try to decode base64 (Go encodes []byte as base64 in JSON)
        return decodeBase64(value);
    }
    if (Array.isArray(value)) {
        try {
            return String.fromCharCode(...value);
        } catch (e) {
            // Fallback for large arrays
            return value.map(b => String.fromCharCode(b)).join('');
        }
    }
    if (value instanceof Uint8Array) {
        return new TextDecoder().decode(value);
    }
    return String(value || '');
}

async function storeFindings(url, scanResults) {
    const database = await getDB();
    const tx = database.transaction('findings', 'readwrite');
    const store = tx.objectStore('findings');

    const stored = [];
    const requests = [];

    // Prepare all findings first (synchronously)
    const findings = [];
    for (const result of scanResults.results || []) {
        for (const match of result.matches || []) {
            // Extract and convert secret value to string
            // Prefer Groups[0] (capture group), fallback to Snippet.Matching with HTML stripped
            let rawSecret = match.Groups?.[0];
            if (!rawSecret && match.Snippet?.Matching) {
                // Snippet.Matching may contain HTML context from full page scan - strip tags
                let snippet = byteArrayToString(match.Snippet.Matching);
                rawSecret = snippet.replace(/<[^>]*>/g, '').trim();
            }
            rawSecret = rawSecret || '';
            const secretString = byteArrayToString(rawSecret);

            findings.push({
                url,
                source: result.source,
                ruleId: match.RuleID,
                ruleName: match.RuleName,
                structuralId: match.StructuralID,
                // Store full secret value as string for red team use
                secret: secretString,
                snippet: match.Snippet,
                location: match.Location,
                timestamp: new Date().toISOString()
            });
        }
    }

    // Add all findings synchronously within the same transaction
    for (const finding of findings) {
        const req = store.add(finding);
        requests.push({ req, finding });
    }

    // Wait for transaction to complete
    return new Promise((resolve, reject) => {
        tx.oncomplete = () => {
            // Collect successful results
            for (const { req, finding } of requests) {
                if (req.result !== undefined) {
                    finding.id = req.result;
                    stored.push(finding);
                }
            }
            resolve(stored);
        };
        tx.onerror = (e) => {
            // Ignore ConstraintError (duplicate structuralId) - that's expected
            if (e.target.error?.name === 'ConstraintError') {
                e.preventDefault(); // Prevent transaction abort
            }
        };
        tx.onabort = () => {
            // If aborted due to constraint error, still resolve with what we have
            if (tx.error?.name === 'ConstraintError') {
                resolve(stored);
            } else {
                reject(tx.error);
            }
        };
    });
}

async function getFindings(url = null) {
    const database = await getDB();
    const tx = database.transaction('findings', 'readonly');
    const store = tx.objectStore('findings');

    return new Promise((resolve, reject) => {
        let request;
        if (url) {
            const index = store.index('url');
            request = index.getAll(url);
        } else {
            request = store.getAll();
        }
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

async function getFindingsByTab(tabUrl) {
    return getFindings(tabUrl);
}

async function getAllFindings() {
    return getFindings();
}

async function clearFindings() {
    const database = await getDB();
    const tx = database.transaction('findings', 'readwrite');
    return new Promise((resolve, reject) => {
        const request = tx.objectStore('findings').clear();
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
}

async function exportFindings() {
    const findings = await getAllFindings();
    return JSON.stringify(findings, null, 2);
}

async function getStats() {
    const findings = await getAllFindings();
    const urls = new Set(findings.map(f => f.url));
    return {
        totalFindings: findings.length,
        uniqueSites: urls.size
    };
}
