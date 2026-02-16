# Titus Burp Extension UI Enhancements Design

**Date:** 2026-02-13
**Status:** Approved

## Overview

Enhance the Titus Burp Extension with improved secret visibility, filtering, statistics, and validation capabilities.

## Features Summary

1. **Secrets sub-tab** - Deduplicated secrets table with counts and validation
2. **Enhanced Requests sub-tab** - Filtering and secret category highlighting
3. **Statistics sub-tab** - Per-host and per-type secret breakdowns
4. **Inline highlighting** - Visual markers for secrets in request/response viewers
5. **Secret validation** - Opt-in per-secret validation against source APIs

---

## 1. New Tab Structure

### Current Structure
```
Titus Tab
├── Settings (sub-tab)
└── Requests (sub-tab)
```

### Proposed Structure
```
Titus Tab
├── Settings (sub-tab) - existing, with validation settings added
├── Requests (sub-tab) - enhanced with filters and secret column
├── Secrets (sub-tab) - NEW
└── Statistics (sub-tab) - NEW
```

---

## 2. Secrets Sub-Tab

### Table Columns

| Column | Description |
|--------|-------------|
| # | Row number |
| Type | Rule name (e.g., "AWS API Key", "Slack Bot Token") |
| Secret Preview | First 20 chars + "..." (from `DedupCache.FindingRecord`) |
| Host | Extracted from URL |
| Occurrences | Count from `FindingRecord.occurrenceCount` |
| Validation | Status indicator (see below) |
| Actions | "Validate" button |

### Validation Status Display

| Status | Display | Color |
|--------|---------|-------|
| Not checked | `-` | Gray |
| Valid/Active | `Active ✓` | Green |
| Invalid/Revoked | `Inactive ✗` | Red |
| Undetermined | `Unknown ?` | Yellow |
| Validating... | `⏳` | Gray spinner |

### Behavior

- Row selection shows full secret details in a panel below the table
- "Validate" buttons disabled until validation is enabled in Settings
- Tooltip on disabled buttons: "Enable validation in Settings first"

### New Java Classes

- `SecretsTableModel.java` - Table model for secrets data
- `SecretsView.java` - Panel containing secrets table and detail view

---

## 3. Enhanced Requests Sub-Tab

### New Table Column

Add "Secrets" column showing count + color-coded badges by category:
- Example: `🔴 2 AWS` `🟡 1 Slack` or just count `3`
- Empty if no secrets found

### Filter Bar

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Filter: [Host: ▼ all] [Secret Type: ▼ all] [Has Secrets: ▼ all]        │
│         [Method: ▼ all] [Status: ▼ all] [🔍 Search URL...] [Clear]     │
└─────────────────────────────────────────────────────────────────────────┘
```

### Filter Options

| Filter | Options |
|--------|---------|
| Host | Dropdown populated with discovered hosts |
| Secret Type | "All", "AWS", "Slack", "Generic API Key", etc. |
| Has Secrets | "All", "With Secrets Only", "No Secrets" |
| Method | "All", "GET", "POST", "PUT", "DELETE", etc. |
| Status | "All", "2xx", "3xx", "4xx", "5xx" |
| Search URL | Text field for substring matching |
| Clear | Reset all filters |

### Category Color Coding

| Category | Color | Examples |
|----------|-------|----------|
| AWS/Cloud | Red 🔴 | AWS keys, GCP, Azure |
| Database/Passwords | Orange 🟠 | DB passwords, connection strings |
| API Keys | Yellow 🟡 | Slack, Stripe, Twilio |
| Private Keys/Certs | Purple 🟣 | SSH keys, PEM files |
| Generic/Other | Gray ⚪ | Generic secrets, tokens |

### New Java Classes

- `RequestsFilterPanel.java` - Filter bar component
- `FilteredRequestsTableModel.java` - Wrapper with filtering logic

---

## 4. Statistics Sub-Tab

### Layout

Two side-by-side tables with summary bar below.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Statistics                                     │
├────────────────────────────────┬────────────────────────────────────────┤
│   Secrets by Host              │   Secrets by Type                      │
├────────────────────────────────┼────────────────────────────────────────┤
│ Host              | Count      │ Type                | Count | Color    │
│-------------------|------------|---------------------|-------|----------|
│ api.example.com   | 12         │ AWS API Key         | 8     | 🔴       │
│ cdn.example.com   | 5          │ Slack Bot Token     | 5     | 🟡       │
│ auth.example.com  | 3          │ Generic API Key     | 4     | ⚪       │
├────────────────────────────────┴────────────────────────────────────────┤
│ Summary: 22 unique secrets across 4 hosts | 15 validated (8 active)     │
└─────────────────────────────────────────────────────────────────────────┘
```

### Secrets by Host Table

- Sortable by Host or Count
- Click row to filter Requests/Secrets tabs to that host

### Secrets by Type Table

- Sortable by Type or Count
- Color indicator matches category color coding
- Click row to filter Secrets tab to that type

### Summary Bar

- Total unique secrets count
- Total hosts with secrets
- Validation summary: "X validated (Y active, Z inactive)"

### New Java Classes

- `StatisticsView.java` - Panel with both tables and summary
- `HostStatsTableModel.java` - Model for host statistics
- `TypeStatsTableModel.java` - Model for type statistics

---

## 5. Inline Secret Highlighting

### Implementation

Register custom `HttpRequestEditorProvider` and `HttpResponseEditorProvider` that add highlight markers.

### Flow

1. When request/response displayed, use cached scan results
2. For each secret, add `Marker` at byte offset range
3. Burp renders with highlight background

### Highlight Colors by Severity

| Severity | Color | Hex |
|----------|-------|-----|
| High (AWS, DB creds) | Orange | `#FFE4B5` |
| Medium (API keys) | Yellow | `#FFFF99` |
| Low (Generic) | Light Gray | `#E0E0E0` |

### Performance

- Cache scan results by response hash
- Use existing `DedupCache` mechanism
- Only highlight in Titus tab editors

### New Java Classes

- `HighlightingRequestEditor.java` - Custom editor with markers
- `HighlightingResponseEditor.java` - Custom editor with markers
- `SecretMarkerCache.java` - Cache for marker positions

---

## 6. Secret Validation

### Settings Panel Addition

```
┌─ Validation Settings ─────────────────────────────────────┐
│ ☐ Enable secret validation (makes outbound API requests)  │
│                                                           │
│ ⚠️ Warning: Validation may trigger alerts (e.g., AWS      │
│    CloudTrail) and makes requests to external services.   │
│                                                           │
│ Supported validators: AWS, Azure, Slack, Twilio,          │
│ PostgreSQL, Dropbox, Contentful, SauceLabs               │
└───────────────────────────────────────────────────────────┘
```

- Disabled by default
- "Validate" buttons disabled until enabled

### Titus CLI Protocol Extension

New message type for `titus serve`:

```json
// Request
{
  "type": "validate",
  "payload": {
    "rule_id": "np.aws.1",
    "secret": "AKIA...",
    "named_groups": {"key_id": "AKIA...", "secret_key": "..."}
  }
}

// Response
{
  "success": true,
  "data": {
    "status": "valid",
    "confidence": 1.0,
    "message": "AWS STS GetCallerIdentity succeeded"
  }
}
```

### Validation Flow

1. User clicks "Validate" button on a secret
2. Button shows loading spinner
3. Extension sends validate request to Titus CLI
4. Result updates table cell and is cached

### New Java Classes

- `ValidationManager.java` - Handles validation requests and caching
- Updates to `TitusProcessScanner.java` - Add validate method

### Go CLI Changes

- `pkg/serve/server.go` - Add "validate" message handler
- Wire up existing `pkg/validator/engine.go`

---

## Data Model Changes

### Enhanced FindingRecord

```java
public static class FindingRecord {
    public String ruleId;
    public String ruleName;           // NEW: human-readable name
    public String secretPreview;
    public String host;               // NEW: extracted from URL
    public Set<String> urls;
    public int occurrenceCount;
    public Instant firstSeen;
    public ValidationStatus validationStatus;  // NEW
    public String validationMessage;           // NEW
    public Instant validatedAt;                // NEW
}
```

### Category Mapping

```java
public class SecretCategoryMapper {
    public static Category getCategory(String ruleId) {
        if (ruleId.contains("aws") || ruleId.contains("gcp") || ruleId.contains("azure")) {
            return Category.CLOUD;
        }
        if (ruleId.contains("password") || ruleId.contains("postgres") || ruleId.contains("mysql")) {
            return Category.DATABASE;
        }
        // ... etc
    }
}
```

---

## Implementation Order

### Phase 1: Data Model & Core
1. Enhance `FindingRecord` with new fields
2. Add `SecretCategoryMapper` for color coding
3. Add validation protocol to Titus CLI `serve` command

### Phase 2: Secrets Sub-Tab
4. Create `SecretsTableModel` and `SecretsView`
5. Add to main tabbed pane

### Phase 3: Statistics Sub-Tab
6. Create statistics models and views
7. Add cross-tab filtering support

### Phase 4: Enhanced Requests
8. Add Secrets column to `RequestsTableModel`
9. Create `RequestsFilterPanel`
10. Integrate filtering logic

### Phase 5: Highlighting
11. Create custom editor providers
12. Implement marker caching

### Phase 6: Validation
13. Add `ValidationManager`
14. Wire up validate buttons
15. Add settings panel checkbox

---

## Testing Plan

- Unit tests for new table models
- Unit tests for category mapping
- Unit tests for filter logic
- Integration tests for validation protocol
- Manual testing in Burp Suite

---

## Dependencies

- No new external dependencies required
- Uses existing Burp Montoya API
- Uses existing Titus validator infrastructure
