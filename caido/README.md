# Titus Secret Scanner - Caido Plugin

A [Caido](https://caido.io/) plugin that scans HTTP traffic for secrets and credentials using the [Titus](https://github.com/praetorian-inc/titus) detection engine (444+ rules).

## Features

- **Passive scanning** - Automatically scans HTTP responses flowing through the Caido proxy
- **444+ detection rules** - AWS keys, Azure tokens, GitHub PATs, JWTs, database credentials, private keys, and more
- **Smart filtering** - Skips binary content (images, fonts, PDFs) to minimize overhead
- **Deduplication** - Same secret across multiple URLs is reported once
- **Severity mapping** - Findings categorized as High/Medium/Low based on rule type
- **Request scanning** - Optionally scan request bodies and headers
- **Scope filtering** - Limit scanning to in-scope targets only

## Prerequisites

The Titus CLI binary must be installed on your system. The plugin communicates with Titus via its `titus serve` NDJSON protocol (same as the Burp extension).

### Install Titus

```bash
# Download the latest release
# https://github.com/praetorian-inc/titus/releases

# Or build from source
git clone https://github.com/praetorian-inc/titus.git
cd titus
make build

# Install to ~/.titus/
mkdir -p ~/.titus
cp titus ~/.titus/titus
```

The plugin searches these paths (in order):
1. `~/.titus/titus`
2. `~/bin/titus`
3. `/usr/local/bin/titus`
4. `titus` (PATH lookup)

## Installation

### From source

```bash
cd caido/
pnpm install
pnpm build
```

This produces `plugin_package.zip` which can be installed in Caido via **Settings > Plugins > Install from file**.

### Development

```bash
cd caido/
pnpm install
pnpm dev   # Watch mode - rebuilds on changes
```

## Architecture

The plugin mirrors the architecture of the existing Burp Suite extension:

```
┌─────────────────────┐     NDJSON/stdin/stdout     ┌──────────────┐
│   Caido Backend      │◄──────────────────────────►│ titus serve  │
│                      │                             │              │
│  - onInterceptResp() │  {"type":"scan",            │  444+ rules  │
│  - FastPathFilter    │   "payload":{"content":...}}│  Hyperscan   │
│  - DedupCache        │                             │  engine      │
│  - FindingsReporter  │  {"success":true,           │              │
│                      │   "data":{"matches":[...]}} │              │
└─────────┬───────────┘                             └──────────────┘
          │
          │ sdk.api (RPC)
          │
┌─────────▼───────────┐
│   Caido Frontend     │
│                      │
│  - Stats dashboard   │
│  - Findings table    │
│  - Settings toggles  │
└─────────────────────┘
```

### Backend (`packages/backend/`)

| File | Description |
|------|-------------|
| `index.ts` | Plugin entry point - registers HTTP handler and API |
| `scanner.ts` | `TitusScanner` class - spawns and communicates with `titus serve` |
| `filter.ts` | `FastPathFilter` - skips non-scannable content types and extensions |
| `dedup.ts` | `DedupCache` - deduplicates findings by rule + secret content |
| `types.ts` | TypeScript types for the NDJSON protocol |

### Frontend (`packages/frontend/`)

| File | Description |
|------|-------------|
| `index.ts` | UI page with stats, findings table, and settings |
| `style.css` | Dark theme styles matching Caido's look |

## Protocol

The plugin uses the same NDJSON protocol as the Burp extension, documented in `pkg/serve/`:

**Scan request:**
```json
{"type":"scan","payload":{"content":"response body...","source":"https://example.com/api"}}
```

**Scan response:**
```json
{"success":true,"type":"scan","data":{"matches":[{"RuleID":"np.aws.1","RuleName":"AWS API Key",...}]}}
```

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Passive Scan | On | Scan responses automatically |
| Scan Requests | Off | Also scan request bodies |
| Scope Only | Off | Only scan in-scope targets |
