# BApp Store Compliance Audit Report — Titus Secret Scanner

**Extension:** Titus Secret Scanner
**Branch:** `burp/ui-ux-improvements-lab-1266`
**Audit Date:** 2026-03-26
**Audited Against:** [BApp Compliance Research Synthesis](../ai/pi-agentic-framework-research/bapp-compliance-requirements/SYNTHESIS.md)

---

## Overall Assessment

| Category | Status | Blocking Issues |
|----------|--------|-----------------|
| Build & Packaging | **FAIL** | Java 17 instead of Java 21 |
| Security | **PASS** | None |
| Threading & Performance | **FAIL** | EDT blocking in SecretEditorProvider |
| Resource Management | **FAIL** | statsTimer and validation threads not cleaned up on unload |
| UI/UX | **FAIL** | Zero dialog calls use `SwingUtils.suiteFrame()` |
| Documentation | **FAIL** | No README.md exists |

**Result: 5 blocking issues must be fixed before BApp Store submission.**

---

## 1. Build & Packaging

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 1.1 | Montoya API as `compileOnly` | **PASS** | `build.gradle.kts:23` — `compileOnly("...montoya-api:2023.12.1")` |
| 1.2 | Java 21 compatibility | **FAIL** | `build.gradle.kts:10-11` — targets Java 17, not Java 21 |
| 1.3 | Gradle wrapper included | **WARN** | `gradlew` present, `gradlew.bat` (Windows) missing |
| 1.4 | Fat JAR bundles all deps | **PASS** | Shadow plugin configured, Gson relocated to avoid conflicts |
| 1.5 | BurpExtension entry point | **PASS** | `TitusExtension.java:22` implements `BurpExtension`, line 36 `initialize(MontoyaApi)` |
| 1.6 | Montoya API version | **WARN** | Using `2023.12.1` (3+ years old), latest is `2026.2` |

### Required Fix
```kotlin
// build.gradle.kts lines 10-11: change from
sourceCompatibility = JavaVersion.VERSION_17
targetCompatibility = JavaVersion.VERSION_17
// to
sourceCompatibility = JavaVersion.VERSION_21
targetCompatibility = JavaVersion.VERSION_21
```

### Recommended
- Update `montoya-api` from `2023.12.1` to `2025.x` or `2026.2`
- Run `gradle wrapper` to regenerate `gradlew.bat`

---

## 2. Security

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 2.1 | HTTP content treated as untrusted | **PASS** | `IssueReporter.java:105-114` and `SecretsView.java:1187-1194` — all untrusted data HTML-escaped via `escapeHtml()` |
| 2.2 | XXE protection | **N/A** | No XML parsing anywhere. Uses Gson for JSON only |
| 2.3 | Code injection protection | **PASS** | HTML output escaped, JSON via Gson serialization, no shell command construction with untrusted input |
| 2.4 | GUI auto-fill validation | **PASS** | All display components non-editable (`setEditable(false)`), table cells non-editable |
| 2.5 | Uses Burp HTTP API (no java.net.URL) | **PASS** | Zero usage of `java.net.URL`, `HttpURLConnection`, `OkHttp`, or `HttpClient`. Extension makes no outbound HTTP calls — scans via local subprocess IPC |
| 2.6 | No network in passiveAudit | **N/A** | No `ScanCheck` implementation. `HttpHandler` only enqueues to local queue |
| 2.7 | AI features use Montoya API | **N/A** | No AI features |

**No security issues found. The extension handles untrusted data correctly throughout.**

---

## 3. Threading & Performance

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 3.1 | No slow ops on EDT | **FAIL** | `SecretEditorProvider.java:345-386` — `isEnabledFor()` calls synchronous `scanner.scan()` (process I/O) on EDT |
| 3.2 | Background threads for heavy work | **PASS** | `ScanQueue` uses 4-worker `ExecutorService`; `BulkScanHandler` uses `SwingWorker`; `ValidationManager` uses background threads |
| 3.3 | Background thread try/catch | **PASS** | `ScanQueue.Worker.run()` lines 188-215 has try/catch; validation thread has try/catch; SwingWorker handles exceptions internally |
| 3.4 | Shared data protected with locks | **PASS** | `ConcurrentHashMap` for caches, `ReentrantLock` in `ProcessManager`, `synchronized` methods in `TitusProcessScanner`, `LinkedBlockingQueue` in `ScanQueue` |
| 3.5 | No slow ops in HttpHandler | **PASS** | `TitusHttpHandler.handleHttpResponseReceived()` only checks booleans, calls fast filter, and enqueues — returns immediately |

### Required Fix: SecretEditorProvider EDT Blocking

**Files:** `SecretEditorProvider.java`

`isEnabledFor()` (line 345-386) is called by Burp on the EDT. It currently calls `scanner.scan()` which performs synchronous process I/O (writes to subprocess stdin, reads from stdout). This blocks the EDT.

Similarly, `setRequestResponse()` → `scanForSecrets()` (line 214) calls `scanner.scan()` synchronously.

**Fix approach:** Only show the editor tab when the DedupCache already has findings for the URL (from the passive scan). If cache miss, return `false` from `isEnabledFor()` — the passive scan will eventually populate the cache, and the user can re-select the request.

---

## 4. Resource Management

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 4.1 | Unload handler registered | **PASS** | `TitusExtension.java:93-100` — calls `saveMessages()`, `scanQueue.close()`, `processManager.close()` |
| 4.2 | All threads terminated on unload | **FAIL** | `statsTimer` (SettingsTab.java:650-657) never cancelled; `ValidationManager` uses fire-and-forget `new Thread()` with no tracking |
| 4.3 | No long-lived callback refs | **WARN** | `RequestsTableModel` retains up to 1000 `ScanJob` objects with full `HttpRequest`/`HttpResponse` refs. Bounded but memory-heavy |
| 4.4 | temporaryFileContext() usage | **N/A** | Uses custom JSON serialization for persistence, not Burp's message persistence API |
| 4.5 | Careful with history/siteMap | **PASS** | `proxy().history()` called in SwingWorker background thread, not EDT |

### Required Fixes

**Fix 1: statsTimer not cancelled on unload**
- **File:** `SettingsTab.java:650-657`
- `java.util.Timer` runs every 1 second, never cancelled
- **Fix:** Add `statsTimer.cancel()` to a `close()` method on `SettingsTab`, called from the unload handler

**Fix 2: Validation threads not tracked**
- **File:** `ValidationManager.java:89`
- Uses `new Thread(...)` for each validation — fire-and-forget, no tracking
- **Fix:** Replace with an `ExecutorService`, add `close()` method that calls `executor.shutdownNow()`, call from unload handler

### Recommended
- Consider storing only essential data (URL, status, snippet) in `RequestsTableModel` instead of full `HttpRequest`/`HttpResponse` objects to reduce memory footprint

---

## 5. UI/UX

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 5.1 | Dialogs parented to `SwingUtils.suiteFrame()` | **FAIL** | 0 of 10+ dialog calls use correct parent — all use `null`, `this`, or other components |
| 5.2 | No nested HttpRequestEditor | **PASS** | No `ExtensionProvidedHttpRequestEditor` implemented |
| 5.3 | SettingsPanelBuilder usage | **WARN** | Manual Swing settings panel within extension's own tab — acceptable but not ideal |
| 5.4 | Suite tabs justified | **PASS** | 1 tab with 3 sub-tabs (Secrets, Statistics, Settings) — all justified |
| 5.5 | Extension name descriptive | **PASS** | "Titus Secret Scanner" — clear and descriptive |

### Required Fix: SwingUtils.suiteFrame() for ALL dialogs

**Every `JOptionPane` and `JFileChooser` call must be updated:**

| File | Line(s) | Current Parent | Fix |
|------|---------|----------------|-----|
| `TitusExtension.java` | 259-260 | `null` | `SwingUtils.suiteFrame()` |
| `BulkScanHandler.java` | 129-130, 137-138 | `null` | `SwingUtils.suiteFrame()` |
| `SettingsTab.java` | 241 | `secretsView` | `SwingUtils.suiteFrame()` |
| `SettingsTab.java` | 455 | `this` | `SwingUtils.suiteFrame()` |
| `FindingsExporter.java` | 63, 91, 128, 137 | `parent` (Component) | Change `parent` param or use `SwingUtils.suiteFrame()` |
| `SecretsView.java` | 534 | `this` | `SwingUtils.suiteFrame()` |
| `SecretsView.java` | 1262 | `this` | `SwingUtils.suiteFrame()` |

Import needed: `import burp.api.montoya.ui.swing.SwingUtils;`

---

## 6. Documentation

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 6.1 | README.md | **FAIL** | No README exists in burp/ directory |
| 6.2 | Submission metadata prepared | **N/A** | Not yet submitted |

### Required Fix
Create `burp/README.md` covering:
- **What it does**: Scans HTTP traffic for leaked secrets/credentials using Titus (Go NoseyParker port)
- **How it works**: Passive scanning on proxy traffic + active right-click scanning, pattern matching via local subprocess IPC
- **How to use it**: Passive scan auto-enabled, right-click for active scan, view findings in Secrets tab, validate secrets, export findings
- **Setup**: Titus binary installation (supported locations: `~/.titus/titus`, `~/bin/titus`, `/usr/local/bin/titus`, or bundled in JAR)

---

## 7. Offline & Compatibility

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 7.1 | Offline support | **PASS** | Titus binary runs locally with bundled rules — no internet dependency |
| 7.2 | Corporate proxy compatibility | **PASS** | Extension makes no outbound HTTP calls |
| 7.3 | Large project compatibility | **WARN** | `proxy().history()` called in bulk scan (SwingWorker background) — OK but could be slow on large projects |
| 7.4 | Extension does not duplicate existing BApps | **PASS** | No existing BApp Store extension integrates Titus/NoseyParker for secret scanning in HTTP traffic |

---

## Priority Action Items

### P0 — Must Fix (Blocking BApp Submission)

| # | Issue | File(s) | Effort |
|---|-------|---------|--------|
| 1 | Java 17 → Java 21 | `build.gradle.kts:10-11` | 5 min |
| 2 | `SwingUtils.suiteFrame()` for all dialogs | 5 files, 10+ locations | 30 min |
| 3 | EDT blocking in `SecretEditorProvider` | `SecretEditorProvider.java` | 1-2 hrs |
| 4 | `statsTimer` not cancelled on unload | `SettingsTab.java` | 15 min |
| 5 | Validation threads not tracked/cleaned | `ValidationManager.java` | 30 min |

### P1 — Should Fix (May Raise Reviewer Concerns)

| # | Issue | File(s) | Effort |
|---|-------|---------|--------|
| 6 | Create README.md | `burp/README.md` | 30 min |
| 7 | Update Montoya API version | `build.gradle.kts:23` | 5 min + testing |
| 8 | Add `gradlew.bat` | Run `gradle wrapper` | 5 min |

### P2 — Nice to Have

| # | Issue | File(s) | Effort |
|---|-------|---------|--------|
| 9 | Reduce memory in RequestsTableModel (store minimal data, not full request/response) | `RequestsTableModel.java` | 1-2 hrs |
| 10 | Consider `SettingsPanelBuilder` for settings | `SettingsTab.java` | 2-4 hrs |

---

## Estimated Total Effort

- **P0 fixes**: ~3-4 hours
- **P1 fixes**: ~40 minutes
- **P2 fixes**: ~3-6 hours (optional)
- **Total for submission readiness**: ~4-5 hours (P0 + P1)
