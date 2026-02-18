<img width="1200" height="628" alt="Titus" src="https://github.com/user-attachments/assets/c42a712a-58bb-48bf-a947-abba8a851e68" />

# Titus

Titus is a high-performance secrets scanner that detects credentials, API keys, and tokens in source code, files, and git history. It ships with 459 detection rules covering hundreds of services and credential types, drawn from [NoseyParker](https://github.com/praetorian-inc/noseyparker) and [Kingfisher](https://github.com/mongodb/kingfisher).

Titus runs as a CLI, a Go library, a Burp Suite extension, and a Chrome browser extension. All four share the same detection engine and rule set.

### Why Titus?

- **Fast**: Regex matching is accelerated by [Hyperscan](https://github.com/intel/hyperscan)/[Vectorscan](https://github.com/VectorCamp/vectorscan) when available, with a pure-Go fallback for portability.
- **Broad coverage**: 459 rules detect credentials for cloud providers, SaaS platforms, databases, CI/CD systems, and more.
- **Validation**: Detected secrets can be checked against their source APIs to confirm whether they are live.
- **Multiple interfaces**: Scan from the command line, embed as a Go library, passively in Burp Suite, or in the browser during web application testing.

## Installation

Download a prebuilt binary from the [Releases](../../releases) page, or build from source:

```bash
make build
```

The binary will be at `dist/titus`.

## Usage

### Scanning

Scan a file, directory, or git repository:

```bash
# Scan a file
titus scan path/to/file.txt

# Scan a directory
titus scan path/to/directory

# Scan git history
titus scan --git path/to/repo

# Scan a GitHub repository via API (no clone required)
titus github owner/repo --token $GITHUB_TOKEN
```

Results are written to a datastore (`titus.ds` by default) and printed to the console.

### Viewing Results

Use `report` to re-read findings from a previous scan:

```bash
# Human-readable summary
titus report

# JSON output
titus report --format json

# SARIF for CI/CD integration
titus report --format sarif

# Report from a specific datastore
titus report --datastore path/to/titus.ds
```

You can also control the output format at scan time with `--format`:

```bash
titus scan path/to/code --format json
```

### Validating Findings

Pass `--validate` during a scan to check detected secrets against their source APIs:

```bash
titus scan path/to/code --validate
```

Validation runs concurrently (4 workers by default, configurable with `--validate-workers`) and marks each finding as confirmed, denied, or unknown.

### Filtering Rules

```bash
# List all available rules
titus rules list

# Scan with only specific rules
titus scan path/to/code --rules-include "aws,gcp"

# Exclude rules by pattern
titus scan path/to/code --rules-exclude "kingfisher.generic"

# Use a custom rules file
titus scan path/to/code --rules path/to/custom-rules.yaml
```

### Extracting from Binary Files

Titus can extract text from binary file formats and scan the contents for secrets:

```bash
# Extract and scan all supported formats
titus scan path/to/files --extract=all

# Target specific formats
titus scan path/to/files --extract=xlsx,docx,pdf,zip
```

Supported formats include Office documents (xlsx, docx, pptx, odp, ods, odt), PDFs, Jupyter notebooks, SQLite databases, email (eml, rtf), and archives (zip, tar, tar.gz, jar, war, ear, apk, ipa, crx, xpi, 7z). Archives are recursively extracted up to configurable depth and size limits.

```bash
# Tune extraction limits
titus scan path/to/files --extract=all \
  --extract-max-size 10MB \
  --extract-max-total 100MB \
  --extract-max-depth 5
```

## Go Library

Titus can be imported as a Go library to add secrets detection to your own tools.

```bash
go get github.com/praetorian-inc/titus
```

```go
package main

import (
    "fmt"
    "log"

    "github.com/praetorian-inc/titus"
)

func main() {
    scanner, err := titus.NewScanner()
    if err != nil {
        log.Fatal(err)
    }
    defer scanner.Close()

    matches, err := scanner.ScanString(`aws_access_key_id = AKIAIOSFODNN7EXAMPLE`)
    if err != nil {
        log.Fatal(err)
    }

    for _, match := range matches {
        fmt.Printf("%s (rule: %s) at line %d\n",
            match.RuleName, match.RuleID,
            match.Location.SourceSpan.Start.Line,
        )
    }
}
```

The library also supports scanning bytes and files, validating detected secrets, and loading custom rules:

```go
// Scan a file
matches, err := scanner.ScanFile("/path/to/config.json")

// Enable validation to check if secrets are live
scanner, err := titus.NewScanner(titus.WithValidation())

// Load custom rules
rules, err := titus.LoadRulesFromFile("/path/to/rules.yaml")
scanner, err := titus.NewScanner(titus.WithRules(rules))
```

See [docs/library-usage.md](docs/library-usage.md) for the full API reference, concurrency patterns, and more examples.

## Burp Suite Extension

The Burp extension scans HTTP responses for secrets during proxy traffic and active testing.

### Setup

```bash
# Build the CLI and extension JAR, install CLI to ~/.titus/
make install-burp
```

Then load `dist/titus-burp-1.0.0-all.jar` in Burp Suite under Extensions > Add.

The extension launches a `titus serve` process in the background and communicates over stdin/stdout using NDJSON. Rules are loaded once at startup.

### Features

- **Passive scanning**: automatically scans proxy traffic as it flows through Burp
- **Active scanning**: right-click context menu to scan selected requests
- **Deduplication**: same secret is reported only once per engagement
- **Fast-path filtering**: binary content, images, and non-text responses are skipped
- **Validation**: check detected secrets against source APIs to confirm if they're live
- **False positive management**: mark findings as false positives to filter noise
- **Severity classification**: findings color-coded by risk (High/Medium/Low)
- **Export**: save findings to JSON for reporting

### Interface

The extension adds a **Titus** tab to Burp with three sub-tabs:

**Secrets**: All detected secrets with filtering by type, host, and validation status.

 <img width="2108" height="1634" alt="image" src="https://github.com/user-attachments/assets/245bc848-353e-48f8-a4c2-82f719057e28" />

- **Validation status**: Shows whether secrets have been checked (Active/Inactive/Unknown)
- **Filtering**: Click Type, Host, or Status buttons to filter by specific values; use the search box for text and regex matching
- **Bulk actions**: Select multiple rows to validate or mark as false positive in batch
- **Secret Details panel**: Select a finding to view:
    - **Details**: Rule info, category, full secret value, first seen timestamp
    - **URLs**: All locations where this secret was found
    - **Validation**: Validation result with details (e.g., AWS account ID, ARN)
    - **Request/Response**: Full HTTP traffic with the secret highlighted


**Statistics**: Aggregate view of secrets grouped by type and host.

<img width="1964" height="848" alt="image" src="https://github.com/user-attachments/assets/bace159d-c74a-45e0-8162-035078dd8c2c" />

- **Summary**: Total unique secrets, hosts scanned, validation breakdown (active vs inactive), and false positive count
- **Secrets by Type**: Count of each secret type with category classification
- **Secrets by Host**: Number of secrets found per host
    
**Settings**: Configure scanning options, validation, and severity mappings.

<img width="2164" height="1192" alt="image" src="https://github.com/user-attachments/assets/4bdcfe59-8a0c-45eb-a476-6a6346dd1809" />
 
- **Scan Settings**:
    - *Passive scanning*: Automatically scan all proxy traffic (enabled by default)
    - *Request body scanning*: Also scan request bodies for secrets sent by the application
    - *Validation*: Enable to check secrets against source APIs (makes outbound requests and may trigger alerts)
- **Scan Parameters**: Worker threads, max file size, context snippet length
- **Severity Configuration**: Customize severity levels per secret category
- **Actions**: Clear cache, reset settings, save/export findings to JSON
    

When viewing any request in Burp, a **Titus** tab appears in the response inspector if secrets are detected, providing quick access to findings without switching to the main Titus tab.

<img width="2658" height="946" alt="image" src="https://github.com/user-attachments/assets/27cc1fa3-60aa-4aa2-bea0-1131d8bfaf6e" />

## Browser Extension

The Chrome extension scans web pages for secrets during web application assessments.

### Setup

```bash
make build-extension
```

1. Navigate to `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked** and select the `extension/` directory

### Features

- Scans inline and external JavaScript and stylesheets
- Scans localStorage and sessionStorage
- Optional network response capture
- Results displayed in popup and dashboard

<img width="1719" height="958" alt="image" src="https://github.com/user-attachments/assets/789f6e18-9305-421c-93e2-40e72b71e246" />

<img width="1744" height="827" alt="image" src="https://github.com/user-attachments/assets/696d9b4d-3581-4da2-b081-86d21bb4b41f" />

### Security Notice

The browser extension removes Content Security Policy and CORS headers from visited pages to scan external resources. This weakens the security posture of sites you visit while the extension is active. **Only enable during active security testing.**

## Building from Source

```bash
# CLI binary
make build

# Burp extension JAR
make build-burp

# Browser extension
make build-extension

# Run tests
make test

# Run integration tests
make integration-test
```

## License

Apache License 2.0 -- see [LICENSE](LICENSE).

Detection rules are derived from [NoseyParker](https://github.com/praetorian-inc/noseyparker) (Praetorian Security, Inc.) and [Kingfisher](https://github.com/mongodb/kingfisher) (MongoDB, Inc.), both licensed under Apache 2.0. See [NOTICE](NOTICE) for full attribution.
