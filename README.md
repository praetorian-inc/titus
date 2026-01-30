<img width="2976" height="1440" alt="titus" src="https://github.com/user-attachments/assets/ac2a94c3-6282-44bc-9379-8fd88132be8a" />
# Titus

Go port of NoseyParker secrets scanner - a high-performance secrets detection tool.

## Installation

```bash
go build -o titus ./cmd/titus
```

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

### Building the Extension

```bash
# Build Titus binary first
go build -o dist/titus ./cmd/titus

# Build Burp extension
cd burp
./gradlew shadowJar
```

The extension JAR will be at `burp/build/libs/titus-burp-*-all.jar`.

### Installation

1. Copy the `titus` binary to one of:
   - `~/.titus/titus`
   - `~/bin/titus`
   - `/usr/local/bin/titus`
   - Or bundle it in the JAR resources

2. Load the extension JAR in Burp Suite (Extensions → Add)

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

## Testing

```bash
# Run unit tests
go test ./...

# Run integration tests (requires building titus first)
go build -o dist/titus ./cmd/titus
go test -tags=integration ./tests/integration/...

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
├── wasi/               # WASM build (legacy)
└── tests/
    └── integration/    # Integration tests
```

## License

Proprietary - Praetorian Inc.
