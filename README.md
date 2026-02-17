<img width="2976" height="1440" alt="titus" src="https://github.com/user-attachments/assets/ac2a94c3-6282-44bc-9379-8fd88132be8a" />
# Titus

Go port of NoseyParker secrets scanner - a high-performance secrets detection tool.

## Installation

```bash
make build
```

The binary will be at `dist/titus`.

## Usage

### Scan Files

```bash
# Scan a single file
titus scan --file path/to/file.txt

# Scan a directory
titus scan --directory path/to/dir

# Scan with specific rules
titus scan --file config.json --rules custom-rules.json
```

### Output Options

The `--output` flag controls where scan results are stored during a scan:

- `:memory:` (default) — results are held in-memory for the duration of the scan. This is the default and works on all platforms.
- `<file-path>` — writes results to a SQLite database file (requires a CGO-enabled build with SQLite support; not available in prebuilt release binaries).

Results can also be emitted to stdout in different formats using `--format`:

- `human` (default) — summarized findings printed to the console
- `json` — full match details as JSON
- `sarif` — SARIF 2.1.0 for CI/CD integration

### Server Mode (for Burp Integration)

Titus can run as a streaming server for integration with Burp Suite:

```bash
titus serve
```

The serve command:
- Loads all 444+ detection rules once at startup (~10-20 seconds)
- Accepts scan requests via stdin using NDJSON protocol
- Returns findings via stdout
- Runs until stdin closes or receives a close command

#### NDJSON Protocol

**Ready signal (sent on startup):**
```json
{"success":true,"type":"ready","data":{"version":"1.0.0"}}
```

**Scan request:**
```json
{"type":"scan","payload":{"content":"aws_access_key_id=AKIAIOSFODNN7EXAMPLE","source":"config.txt"}}
```

**Scan response:**
```json
{"success":true,"type":"scan","data":{"source":"config.txt","matches":[...]}}
```

**Batch scan request:**
```json
{"type":"scan_batch","payload":{"items":[{"source":"file1","content":"..."},{"source":"file2","content":"..."}]}}
```

**Close command:**
```json
{"type":"close","payload":{}}
```

## Burp Suite Integration

Titus includes a Burp Suite extension that scans HTTP responses for secrets.

### Quick Install

```bash
# Build everything and install (recommended)
make install-burp
```

This single command:
1. Builds the `titus` binary
2. Builds the Burp extension JAR
3. Installs the binary to `~/.titus/titus`

Then load `dist/titus-burp-1.0.0-all.jar` in Burp Suite (Extensions → Add).

### Manual Build

```bash
# Build Titus binary
make build

# Build Burp extension JAR
make build-burp

# Install binary to ~/.titus/
make install
```

The extension JAR will be at `dist/titus-burp-1.0.0-all.jar`.

### Architecture

The extension uses native process communication instead of WASM:
- Single `titus serve` process shared across all scan workers
- NDJSON protocol over stdin/stdout
- ~20 second startup (vs ~2 minutes for WASM)
- 4 concurrent workers by default
- Automatic process restart on failure with exponential backoff

### Features

- **Passive scanning**: Automatically scans proxy traffic
- **Active scanning**: Right-click context menu on selected requests
- **Deduplication**: Avoids reporting the same secret multiple times
- **Fast-path filtering**: Skips binary content, images, and other non-scannable content

## Browser Extension

Titus includes a Chrome browser extension that scans web pages for secrets.

### Building

```bash
make build-extension
```

### Installation

1. Go to `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `extension/` directory

### Features

- Scans inline and external JavaScript
- Scans stylesheets
- Scans localStorage and sessionStorage
- Optional network response capture
- Results displayed in popup and dashboard

### Security Notice

**CSP Bypass:** The browser extension removes Content Security Policy headers from visited pages in order to scan external script and stylesheet resources. This is necessary for comprehensive secret detection but weakens the security posture of websites you visit while the extension is active. **Only enable this extension during active security testing and disable it for normal browsing.**

## Testing

```bash
# Run unit tests
make test

# Run integration tests
make integration-test

# Run Burp extension tests
cd burp && ./gradlew test
```

## Project Structure

```
titus/
├── cmd/titus/          # CLI commands
│   ├── root.go         # Root command
│   ├── scan.go         # Scan command
│   └── serve.go        # Server mode command
├── pkg/
│   ├── scanner/        # Core scanning logic
│   │   ├── core.go     # Scanner core with rule caching
│   │   └── types.go    # Shared types
│   ├── serve/          # Server mode implementation
│   │   ├── server.go   # NDJSON streaming server
│   │   └── types.go    # Protocol types
│   ├── matcher/        # Pattern matching
│   ├── rule/           # Rule loading and management
│   ├── store/          # Match storage
│   └── types/          # Common types
├── burp/               # Burp Suite extension (Java)
│   └── src/main/java/com/praetorian/titus/burp/
│       ├── TitusExtension.java      # Main extension
│       ├── TitusProcessScanner.java # Process communication
│       ├── ProcessManager.java      # Process lifecycle
│       └── ScanQueue.java           # Scan job queue
├── extension/          # Chrome browser extension
│   ├── manifest.json   # Extension manifest
│   ├── lib/            # WASM and JS libraries
│   ├── background/     # Service worker
│   ├── content/        # Content scripts
│   └── popup/          # Popup UI
├── wasm/               # WASM build for browser extension
│   ├── main.go         # WASM entry point
│   └── scanner.go      # WASM scanner wrapper
└── tests/
    └── integration/    # Integration tests
```

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

Detection rules derived from [NoseyParker](https://github.com/praetorian-inc/noseyparker) are also licensed under Apache 2.0. See [NOTICE](NOTICE) for attribution.
