# BApp Store Compliance Audit Report — Titus Secret Scanner

**Extension:** Titus Secret Scanner
**Branch:** `burp/ui-ux-improvements-lab-1266`
**Audit Date:** 2026-03-27
**Audited Against:** [BApp Compliance Research Synthesis](~/.claude/.output/research/2026-03-26-095836-bapp-compliance-requirements/SYNTHESIS.md) (12 research agents, 4 sources, confidence 0.92)
**Method:** Fresh from-scratch audit — all 24 Java source files read, every requirement verified independently

---

## Overall Assessment

| Category | Status | Blocking Issues |
|----------|--------|-----------------|
| Build & Packaging | **WARN** | Montoya API 3+ years outdated; `gradlew.bat` missing |
| Security | **PASS** | No blocking issues (1 defensive recommendation) |
| Threading & Performance | **PASS** | No blocking issues |
| Resource Management | **FAIL** | `RequestsFilterPanel` Swing Timer never cancelled on unload |
| UI/UX | **PASS** | All 12 dialog calls use `suiteFrame()` correctly |
| Documentation | **FAIL** | No `burp/README.md` exists |

**Result: 2 blocking issues must be fixed before BApp Store submission.**

---

## 1. Build & Packaging

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 1.1 | Montoya API as `compileOnly` | **PASS** | `build.gradle.kts:23` — `compileOnly("...montoya-api:2023.12.1")` |
| 1.2 | Java 21 compatibility | **PASS** | `build.gradle.kts:10-11` — `VERSION_21` for both source and target |
| 1.3 | Gradle wrapper included | **WARN** | `gradlew` present (5090 bytes, executable), `gradlew.bat` **missing** |
| 1.4 | Fat JAR bundles all deps | **PASS** | Shadow plugin 8.3.6 configured; Gson relocated to `com.praetorian.titus.shadow.gson` |
| 1.5 | BurpExtension entry point | **PASS** | `TitusExtension.java:22` implements `BurpExtension`, line 36 `initialize(MontoyaApi)` |
| 1.6 | Montoya API version | **WARN** | Using `2023.12.1` (3+ years old), latest is `2026.2` |
| 1.7 | Shadow plugin version | **PASS** | `com.gradleup.shadow:8.3.6` — supports Java 21 class files |
| 1.8 | No external runtime deps | **PASS** | Only Gson (bundled). Titus binary is a separate install but is a local subprocess, not a Java dependency |

### Recommended Fixes

**1. Update Montoya API** — `build.gradle.kts:23,28`: Change `2023.12.1` to `2026.2` (or latest stable). While backward-compatible, an outdated API may raise reviewer concerns about maintenance posture.

**2. Add `gradlew.bat`** — Run `gradle wrapper` from `burp/` to regenerate the Windows wrapper script for cross-platform build support.

---

## 2. Security

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 2.1 | HTTP content treated as untrusted | **PASS** | `IssueReporter.java:105-115` — comprehensive `escapeHtml()` escapes `&`, `<`, `>`, `"`, `'`. Used in all HTML output (lines 57-71). |
| 2.2 | XXE protection | **N/A** | No XML parsing anywhere. Uses Gson for JSON only. Zero `javax.xml` imports. |
| 2.3 | Code injection protection | **PASS** | HTML output escaped via `escapeHtml()`. JSON via Gson serialization. No shell command construction with untrusted input. |
| 2.4 | GUI auto-fill validation | **PASS** | All display components non-editable. Filter fields use safe string matching. Spinners use type-safe Integer values with range validation. |
| 2.5 | Uses Burp HTTP API (no java.net.URL) | **PASS** | Zero usage of `java.net.URL`, `HttpURLConnection`, `OkHttp`, or `HttpClient`. Extension makes no outbound HTTP calls — scans via local subprocess IPC. |
| 2.6 | No network in passiveAudit | **N/A** | No `ScanCheck` implementation. `HttpHandler` only enqueues to local queue. |
| 2.7 | AI features use Montoya API | **N/A** | No AI features. |
| 2.8 | Shell command safety | **PASS** | `ProcessBuilder` with separate arguments (not shell-interpreted). Binary path from `findTitusBinary()` checks predefined filesystem locations. |

### Note on SecretEditorProvider Detail Display

`SecretEditorProvider.java:132-152` — Secret content is displayed in a `JTextArea` (plain text, not HTML-rendering). While `JTextArea` is inherently safe against HTML injection, the code does not escape control characters. This is **acceptable** because:
- `JTextArea` does not interpret HTML or ANSI escape sequences
- The data displayed comes from the Titus subprocess JSON output (already parsed)
- No path from this display leads to code execution

**No security issues found. The extension handles untrusted data correctly throughout.**

---

## 3. Threading & Performance

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 3.1 | No slow ops on EDT | **PASS** | `SecretEditorProvider.java:347-351` — `isEnabledFor()` returns `false` on cache miss with comment "do NOT scan synchronously here (this runs on the EDT)". `scanForSecrets()` similarly defers on cache miss (line 229-234). |
| 3.2 | Background threads for heavy work | **PASS** | `ScanQueue` uses 4-worker `ExecutorService` (line 96); `BulkScanHandler` uses `SwingWorker` (line 39); `ValidationManager` uses 2-thread `ExecutorService` (lines 30-31) |
| 3.3 | Background thread try/catch | **PASS** | `ScanQueue.Worker.run()` lines 188-216 has full try/catch; `ValidationManager.validateAsync()` lines 93-126 has try/catch; `BulkScanHandler.done()` lines 114-135 has try/catch |
| 3.4 | Shared data protected with locks | **PASS** | `ConcurrentHashMap` for caches (DedupCache:59-63), `ReentrantLock` in `ProcessManager` (line 28), `synchronized` methods in `TitusProcessScanner` (lines 96,118,155,161), `AtomicLong` counters in ScanQueue (lines 35-37), `LinkedBlockingQueue` for job queue |
| 3.5 | No slow ops in HttpHandler | **PASS** | `TitusHttpHandler.handleHttpResponseReceived()` lines 170-195: checks booleans, calls fast filter, does non-blocking `queue.offer()`, returns immediately |

### Deadlock Analysis

No deadlock risk detected:
- `ProcessManager` uses a single `ReentrantLock` — no nested lock acquisitions
- `TitusProcessScanner` uses intrinsic `synchronized` on `this` — single lock per scanner instance
- No cross-lock dependencies between components
- All Burp API calls return quickly, no long-held locks

**No threading violations detected.**

---

## 4. Resource Management

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 4.1 | Unload handler registered | **PASS** | `TitusExtension.java:92-102` — calls `saveMessages()`, `settingsTab.close()`, `validationManager.close()`, `scanQueue.close()`, `processManager.close()` |
| 4.2 | All threads terminated on unload | **FAIL** | `RequestsFilterPanel.java:73-85` — Swing `Timer` in anonymous `DocumentListener` has no cleanup path |
| 4.3 | No long-lived callback refs | **PASS** | `RequestsTableModel` bounded to 1000 entries (line 18). `DedupCache` bounded to 50,000 entries with eviction (lines 185-241). `MessagePersistence` limited to 1000 messages (line 23). |
| 4.4 | Persistent HTTP storage | **PASS** | `MessagePersistence.java:65-87` uses `api.persistence().extensionData().setString()` with Base64-encoded JSON — correct Burp persistence pattern |
| 4.5 | Careful with history/siteMap | **PASS** | `BulkScanHandler` calls `proxy().history()` in `SwingWorker.doInBackground()` (background thread), applies scope filter, content hash dedup, and fast-path filter |

### Thread/Timer Lifecycle Inventory

| Resource | Created At | Shut Down At | Status |
|----------|-----------|--------------|--------|
| `ScanQueue` ExecutorService (4 workers) | `ScanQueue:96` | `ScanQueue.close():160-174` via `executor.shutdownNow()` + `awaitTermination(5s)` | **PASS** |
| `ValidationManager` ExecutorService (2 workers) | `ValidationManager:30-31` | `ValidationManager.close():205-207` via `executor.shutdownNow()` | **PASS** |
| `SettingsTab` java.util.Timer ("titus-stats") | `SettingsTab:651` | `SettingsTab.close():663-667` via `statsTimer.cancel()` | **PASS** |
| Titus subprocess (`titus serve`) | `TitusProcessScanner:37-45` | `TitusProcessScanner.close():160-194` via graceful close message + `process.destroy()` + `waitFor(5s)` | **PASS** |
| `BulkScanHandler` SwingWorker | `BulkScanHandler:39` | Self-terminates after `doInBackground()` completes | **PASS** |
| **`RequestsFilterPanel` javax.swing.Timer** | **`RequestsFilterPanel:82`** | **NEVER — no close() method, timer in anonymous listener scope** | **FAIL** |
| `SecretsView` temporary status timer | `SecretsView:1441` | Self-terminates (non-repeating, 5s) — no explicit cancel | **WARN** (low risk) |

### Required Fix: RequestsFilterPanel Timer Leak

**File:** `RequestsFilterPanel.java:72-86`

A `javax.swing.Timer` is created inside an anonymous `DocumentListener`. While individual timers are stopped before new ones are created (`timer.stop()` on line 81), **the last pending timer is never cancelled on unload**. The timer reference is trapped in the anonymous listener's scope and inaccessible from outside.

**Impact:** If a user types in the search field close to extension unload, a 300ms timer may fire after unload, calling `notifyFilterChange()` on a destroyed component graph. This can cause `NullPointerException` or access to stale Burp API references.

**Fix approach:** Extract the `DocumentListener` to a named inner class with a `close()` method. Add `close()` to `RequestsFilterPanel`. Call it from `RequestsView.close()` (new), called from `SettingsTab.close()`.

### Recommended Fix: SecretsView Temporary Timer

**File:** `SecretsView.java:1440-1445`

`showTemporaryStatus()` creates a fire-once 5-second `javax.swing.Timer` with no reference held. Low risk since it's non-repeating and short-lived, but rapid scan completions could accumulate timers in the Swing event queue.

**Fix approach:** Store a single `temporaryStatusTimer` field, cancel previous before creating new.

---

## 5. UI/UX

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 5.1 | Dialogs parented to `suiteFrame()` | **PASS** | **12/12 calls correct** — see detailed table below |
| 5.2 | No nested HttpRequestEditor | **PASS** | `SecretEditorProvider` uses `JTextArea` and `JTable`, not nested editors. `RequestsView` and `SecretsView` use standalone editors. |
| 5.3 | SettingsPanelBuilder usage | **WARN** | Manual Swing settings panel within extension's own tab — acceptable but not ideal. Uses `MessagePersistence` for state. |
| 5.4 | Suite tabs justified | **PASS** | 1 tab ("Titus") with 3 sub-tabs (Secrets, Statistics, Settings) — all justified |
| 5.5 | Extension name descriptive | **PASS** | "Titus Secret Scanner" — clear and descriptive |

### Complete Dialog Audit

| File | Line(s) | Dialog Type | Parent Argument | Status |
|------|---------|-------------|-----------------|--------|
| `TitusExtension.java` | 261-262 | `showMessageDialog` | `api.userInterface().swingUtils().suiteFrame()` | **PASS** |
| `BulkScanHandler.java` | 129-130 | `showMessageDialog` | `api.userInterface().swingUtils().suiteFrame()` | **PASS** |
| `BulkScanHandler.java` | 137-138 | `showMessageDialog` | `api.userInterface().swingUtils().suiteFrame()` | **PASS** |
| `SettingsTab.java` | 241-242 | `showMessageDialog` | `api.userInterface().swingUtils().suiteFrame()` | **PASS** |
| `SettingsTab.java` | 455-456 | `showConfirmDialog` | `api.userInterface().swingUtils().suiteFrame()` | **PASS** |
| `FindingsExporter.java` | 63-64 | `showMessageDialog` | `api.userInterface().swingUtils().suiteFrame()` | **PASS** |
| `FindingsExporter.java` | 77 | `showSaveDialog` | `api.userInterface().swingUtils().suiteFrame()` | **PASS** |
| `FindingsExporter.java` | 91-92 | `showConfirmDialog` | `api.userInterface().swingUtils().suiteFrame()` | **PASS** |
| `FindingsExporter.java` | 128-129 | `showMessageDialog` | `api.userInterface().swingUtils().suiteFrame()` | **PASS** |
| `FindingsExporter.java` | 137-138 | `showMessageDialog` | `api.userInterface().swingUtils().suiteFrame()` | **PASS** |
| `SecretsView.java` | 534-535 | `showConfirmDialog` | `api.userInterface().swingUtils().suiteFrame()` | **PASS** |
| `SecretsView.java` | 1262 | `showConfirmDialog` | `api.userInterface().swingUtils().suiteFrame()` | **PASS** |

---

## 6. Documentation

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 6.1 | README.md | **FAIL** | No README exists in `burp/` directory. A root-level `README.md` exists for the whole Titus project but does not serve as BApp-specific documentation. |
| 6.2 | Submission metadata prepared | **N/A** | Not yet submitted |

### Required Fix

Create `burp/README.md` covering:
- **What it does**: Scans HTTP traffic for leaked secrets/credentials using Titus (Go NoseyParker port) with 487+ detection rules
- **How it works**: Passive scanning on proxy traffic + active right-click scanning, pattern matching via local subprocess IPC (NDJSON over stdin/stdout)
- **How to use it**: Passive scan auto-enabled, right-click for active scan, view findings in Secrets tab, validate secrets, mark false positives, export findings
- **Setup**: Titus binary installation (supported locations: `~/.titus/titus`, `~/bin/titus`, `/usr/local/bin/titus`)

---

## 7. Offline & Compatibility

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 7.1 | Offline support | **PASS** | Titus binary runs locally with bundled rules — no internet dependency |
| 7.2 | Corporate proxy compatibility | **PASS** | Extension makes no outbound HTTP calls |
| 7.3 | Large project compatibility | **PASS** | `proxy().history()` called in SwingWorker background thread with dedup, scope filter, and fast-path filter |
| 7.4 | Extension does not duplicate existing BApps | **PASS** | No existing BApp Store extension integrates Titus/NoseyParker for secret scanning in HTTP traffic |

---

## Priority Action Items

### P0 — Must Fix (Blocking BApp Submission)

| # | Issue | File(s) | Severity |
|---|-------|---------|----------|
| 1 | `RequestsFilterPanel` Swing Timer never cancelled on unload — can fire after extension destroyed | `RequestsFilterPanel.java:72-86` | Thread/resource leak |
| 2 | No `burp/README.md` — BApp Store requires extension-specific documentation | `burp/README.md` (missing) | Documentation |

### P1 — Should Fix (May Raise Reviewer Concerns)

| # | Issue | File(s) |
|---|-------|---------|
| 3 | Montoya API version 3+ years outdated (`2023.12.1` vs `2026.2`) | `build.gradle.kts:23,28` |
| 4 | Missing `gradlew.bat` for Windows builds | Run `gradle wrapper` |
| 5 | `SecretsView.showTemporaryStatus()` creates untracked fire-once timers | `SecretsView.java:1440-1445` |

### P2 — Nice to Have

| # | Issue | File(s) |
|---|-------|---------|
| 6 | Consider `SettingsPanelBuilder` for settings panel | `SettingsTab.java` |
| 7 | Reduce memory in `RequestsTableModel` (store minimal data, not full request/response) | `RequestsTableModel.java` |

---

## Changes Since Previous Audit (2026-03-26)

The following issues from the previous audit have been **resolved**:

| Previous Issue | Status |
|---------------|--------|
| Java 17 instead of Java 21 | **FIXED** — now targets Java 21 |
| Shadow plugin 8.1.1 can't handle Java 21 class files | **FIXED** — upgraded to 8.3.6 |
| EDT blocking in `SecretEditorProvider.isEnabledFor()` | **FIXED** — returns `false` on cache miss, no synchronous scan |
| EDT blocking in `SecretEditorProvider.scanForSecrets()` | **FIXED** — shows "not yet scanned" on cache miss |
| 0/12 dialog calls use `suiteFrame()` | **FIXED** — 12/12 now use `api.userInterface().swingUtils().suiteFrame()` |
| `statsTimer` not cancelled on unload | **FIXED** — `SettingsTab.close()` cancels timer |
| Validation threads fire-and-forget | **FIXED** — replaced with `ExecutorService`, `close()` calls `shutdownNow()` |

### New Issues Found in This Audit

| Issue | Notes |
|-------|-------|
| `RequestsFilterPanel` Swing Timer leak | Not caught in previous audit — timer is in anonymous listener scope |
| `SecretsView` temporary status timers | Minor — fire-once, 5s, low risk |
