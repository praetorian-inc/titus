<img width="1200" height="628" alt="Titus - high-performance secrets scanner for source code, git history, and binary files" src="https://github.com/user-attachments/assets/c42a712a-58bb-48bf-a947-abba8a851e68" />

# Titus: High-Performance Secrets Scanner

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/praetorian-inc/titus/ci.yml?branch=main&label=CI)](https://github.com/praetorian-inc/titus/actions)

**Titus** is a high-performance secrets scanner that detects credentials, API keys, and tokens in source code, files, and git history. It ships with 459 detection rules covering hundreds of services and credential types, drawn from [NoseyParker](https://github.com/praetorian-inc/noseyparker) and [Kingfisher](https://github.com/mongodb/kingfisher). Titus runs as a CLI, a Go library, a Burp Suite extension, and a Chrome browser extension — all sharing the same detection engine and rule set.

Built for security engineers, penetration testers, and DevSecOps teams, Titus combines [Hyperscan](https://github.com/intel/hyperscan)/[Vectorscan](https://github.com/VectorCamp/vectorscan)-accelerated regex matching with live credential validation to find and verify leaked secrets across your entire codebase.

## Table of Contents

- [Why Titus?](#why-titus)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Scanning Options](#scanning-options)
- [Go Library](#go-library-for-secrets-detection)
- [Burp Suite Extension](#burp-suite-extension-for-secret-scanning)
- [Browser Extension](#chrome-browser-extension-for-secret-scanning)
- [Building from Source](#building-from-source)
- [Contributing](#contributing)
- [License](#license)

## Why Titus?

- **Fast secrets scanning**: Regex matching accelerated by [Hyperscan](https://github.com/intel/hyperscan)/[Vectorscan](https://github.com/VectorCamp/vectorscan) when available, with a pure-Go fallback for portability on any platform.
- **Broad credential detection coverage**: 459 rules detect API keys, tokens, and credentials for AWS, GCP, Azure, GitHub, Slack, databases, CI/CD systems, and hundreds more services.
- **Live secret validation**: Detected secrets are checked against their source APIs to confirm whether they are active, reducing false positives and prioritizing remediation.
- **Multiple interfaces for every workflow**: Scan from the CLI, embed as a Go library, passively scan HTTP traffic in Burp Suite, or scan web pages in Chrome during application security testing.
- **Binary file extraction**: Extract and scan secrets from Office documents, PDFs, archives (zip, tar, 7z), mobile apps (APK, IPA), browser extensions, and more.

## Installation

Download a prebuilt binary from the [Releases](../../releases) page, or build from source:

```bash
make build
```

The binary will be at `dist/titus`.

## Quick Start

```bash
# Scan a file for secrets
titus scan path/to/file.txt

# Scan a directory for leaked credentials
titus scan path/to/directory

# Scan git history for secrets in past commits
titus scan --git path/to/repo

# Scan a GitHub repository via API (no clone required)
titus github owner/repo --token $GITHUB_TOKEN

# Validate detected secrets against source APIs
titus scan path/to/code --validate
```

Results are written to a datastore (`titus.ds` by default) and printed to the console.

## Scanning Options

### Viewing Scan Results

Use `report` to re-read findings from a previous scan:

```bash
# Human-readable summary of detected secrets
titus report

# JSON output for programmatic processing
titus report --format json

# SARIF output for CI/CD integration with GitHub Advanced Security
titus report --format sarif

# Report from a specific datastore
titus report --datastore path/to/titus.ds
```

You can also control the output format at scan time with `--format`:

```bash
titus scan path/to/code --format json
```

### Validating Detected Secrets

Pass `--validate` during a scan to check detected secrets against their source APIs:

```bash
titus scan path/to/code --validate
```

Validation runs concurrently (4 workers by default, configurable with `--validate-workers`) and marks each finding as confirmed, denied, or unknown.

### Filtering Detection Rules

```bash
# List all available detection rules
titus rules list

# Scan with only specific rules (e.g., AWS and GCP credentials)
titus scan path/to/code --rules-include "aws,gcp"

# Exclude rules by pattern
titus scan path/to/code --rules-exclude "kingfisher.generic"

# Use a custom rules file for organization-specific secrets
titus scan path/to/code --rules path/to/custom-rules.yaml
```

### Extracting Secrets from Binary Files

Titus can extract text from binary file formats and scan the contents for secrets:

```bash
# Extract and scan all supported binary formats
titus scan path/to/files --extract=all

# Target specific formats
titus scan path/to/files --extract=xlsx,docx,pdf,zip
```

Supported formats include Office documents (xlsx, docx, pptx, odp, ods, odt), PDFs, Jupyter notebooks, SQLite databases, email (eml, rtf), and archives (zip, tar, tar.gz, jar, war, ear, apk, ipa, crx, xpi, 7z). Archives are recursively extracted up to configurable depth and size limits.

```bash
# Tune extraction limits for large codebases
titus scan path/to/files --extract=all \
  --extract-max-size 10MB \
  --extract-max-total 100MB \
  --extract-max-depth 5
```

## Go Library for Secrets Detection

Titus can be imported as a Go library to add secrets detection to your own tools and pipelines.

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
    // Initialize the secrets scanner with default rules
    scanner, err := titus.NewScanner()
    if err != nil {
        log.Fatal(err)
    }
    defer scanner.Close()

    // Scan a string for API keys, tokens, and credentials
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
// Scan a file for leaked credentials
matches, err := scanner.ScanFile("/path/to/config.json")

// Enable validation to check if detected secrets are live
scanner, err := titus.NewScanner(titus.WithValidation())

// Load custom detection rules for organization-specific secrets
rules, err := titus.LoadRulesFromFile("/path/to/rules.yaml")
scanner, err := titus.NewScanner(titus.WithRules(rules))
```

See [docs/library-usage.md](docs/library-usage.md) for the full API reference, concurrency patterns, and more examples.

## Burp Suite Extension for Secret Scanning

The Burp extension scans HTTP responses for secrets during proxy traffic and active penetration testing.

### Setup

```bash
# Build the secrets scanner CLI and Burp extension JAR, install CLI to ~/.titus/
make install-burp
```

Then load `dist/titus-burp-1.0.0-all.jar` in Burp Suite under Extensions > Add.

The extension launches a `titus serve` process in the background and communicates over stdin/stdout using NDJSON. Detection rules are loaded once at startup.

### Burp Extension Features

- **Passive secret scanning**: automatically scans proxy traffic as it flows through Burp
- **Active secret scanning**: right-click context menu to scan selected requests
- **Deduplication**: same secret is reported only once per engagement
- **Fast-path filtering**: binary content, images, and non-text responses are skipped
- **Live credential validation**: check detected secrets against source APIs to confirm if they're active
- **False positive management**: mark findings as false positives to filter noise
- **Severity classification**: findings color-coded by risk (High/Medium/Low)
- **Export**: save findings to JSON for reporting

### Burp Extension Interface

The extension adds a **Titus** tab to Burp with three sub-tabs:

**Secrets**: All detected secrets with filtering by type, host, and validation status.

<img width="2108" height="1634" alt="Titus Burp Suite extension secrets tab showing detected API keys and credentials with validation status" src="https://github.com/user-attachments/assets/245bc848-353e-48f8-a4c2-82f719057e28" />

- **Validation status**: Shows whether secrets have been checked (Active/Inactive/Unknown)
- **Filtering**: Click Type, Host, or Status buttons to filter by specific values; use the search box for text and regex matching
- **Bulk actions**: Select multiple rows to validate or mark as false positive in batch
- **Secret Details panel**: Select a finding to view:
    - **Details**: Rule info, category, full secret value, first seen timestamp
    - **URLs**: All locations where this secret was found
    - **Validation**: Validation result with details (e.g., AWS account ID, ARN)
    - **Request/Response**: Full HTTP traffic with the secret highlighted


**Statistics**: Aggregate view of secrets grouped by type and host.

<img width="1964" height="848" alt="Titus Burp Suite extension statistics tab showing secrets by type and host" src="https://github.com/user-attachments/assets/bace159d-c74a-45e0-8162-035078dd8c2c" />

- **Summary**: Total unique secrets, hosts scanned, validation breakdown (active vs inactive), and false positive count
- **Secrets by Type**: Count of each secret type with category classification
- **Secrets by Host**: Number of secrets found per host

**Settings**: Configure scanning options, validation, and severity mappings.

<img width="2164" height="1192" alt="Titus Burp Suite extension settings tab with scan configuration options" src="https://github.com/user-attachments/assets/4bdcfe59-8a0c-45eb-a476-6a6346dd1809" />

- **Scan Settings**:
    - *Passive scanning*: Automatically scan all proxy traffic (enabled by default)
    - *Request body scanning*: Also scan request bodies for secrets sent by the application
    - *Validation*: Enable to check secrets against source APIs (makes outbound requests and may trigger alerts)
- **Scan Parameters**: Worker threads, max file size, context snippet length
- **Severity Configuration**: Customize severity levels per secret category
- **Actions**: Clear cache, reset settings, save/export findings to JSON


When viewing any request in Burp, a **Titus** tab appears in the response inspector if secrets are detected, providing quick access to findings without switching to the main Titus tab.

<img width="2658" height="946" alt="Titus tab in Burp Suite response inspector highlighting detected secrets in HTTP responses" src="https://github.com/user-attachments/assets/27cc1fa3-60aa-4aa2-bea0-1131d8bfaf6e" />

## Chrome Browser Extension for Secret Scanning

The Chrome extension scans web pages for secrets during web application security assessments.

### Setup

```bash
make build-extension
```

1. Navigate to `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked** and select the `extension/` directory

### Browser Extension Features

- Scans inline and external JavaScript and stylesheets for API keys and tokens
- Scans localStorage and sessionStorage for leaked credentials
- Optional network response capture for comprehensive secret detection
- Results displayed in popup and dashboard

<img width="1719" height="958" alt="Titus Chrome extension popup showing detected secrets on a web page" src="https://github.com/user-attachments/assets/789f6e18-9305-421c-93e2-40e72b71e246" />

<img width="1744" height="827" alt="Titus Chrome extension dashboard with aggregated secret detection results" src="https://github.com/user-attachments/assets/696d9b4d-3581-4da2-b081-86d21bb4b41f" />

### Security Notice

The browser extension removes Content Security Policy and CORS headers from visited pages to scan external resources. This weakens the security posture of sites you visit while the extension is active. **Only enable during active security testing.**

## Building from Source

### Standard Build (Pure Go)

The default build uses a pure-Go regex engine — no C dependencies required:

```bash
# Build the CLI binary (outputs to dist/titus)
make build

# Build the Burp Suite extension JAR
make build-burp

# Build the Chrome browser extension
make build-extension

# Run unit tests
make test

# Run integration tests
make integration-test
```

### Vectorscan/Hyperscan Build (Recommended for Performance)

For significantly faster regex matching, build with [Vectorscan](https://github.com/VectorCamp/vectorscan) (ARM) or [Hyperscan](https://github.com/intel/hyperscan) (x86). This requires the C library installed and CGO enabled.

**Install Vectorscan:**

```bash
# macOS (Homebrew)
brew install vectorscan

# Ubuntu/Debian
sudo apt-get install libhyperscan-dev

# Fedora/RHEL
sudo dnf install hyperscan-devel

# Or build from source:
git clone --depth 1 --branch vectorscan/5.4.11 https://github.com/VectorCamp/vectorscan.git
cd vectorscan && cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local && cmake --build build && sudo cmake --install build
```

**Build with Vectorscan:**

```bash
# macOS (Homebrew) — adjust PKG_CONFIG_PATH to your installed version
CGO_ENABLED=1 PKG_CONFIG_PATH="$(brew --prefix vectorscan)/lib/pkgconfig" \
  go build -tags vectorscan -o dist/titus ./cmd/titus

# Linux (system-installed)
CGO_ENABLED=1 go build -tags vectorscan -o dist/titus ./cmd/titus
```

You'll see `[vectorscan] N/N rules compiled for Hyperscan` on startup when the accelerated engine is active. Without vectorscan, Titus falls back to the pure-Go regex engine automatically.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to Titus.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Detection rules are derived from [NoseyParker](https://github.com/praetorian-inc/noseyparker) (Praetorian Security, Inc.) and [Kingfisher](https://github.com/mongodb/kingfisher) (MongoDB, Inc.), both licensed under Apache 2.0. See [NOTICE](NOTICE) for full attribution.
