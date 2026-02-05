# Using Titus as a Library

Titus can be imported as a Go library to add secrets detection to your own applications.

## Installation

```bash
go get github.com/praetorian-inc/titus
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/praetorian-inc/titus"
)

func main() {
    // Create a scanner with builtin rules (444+ detection patterns)
    scanner, err := titus.NewScanner()
    if err != nil {
        log.Fatal(err)
    }
    defer scanner.Close()

    // Scan a string for secrets
    content := `
        # Config file
        aws_access_key_id = AKIAIOSFODNN7EXAMPLE
        aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    `

    matches, err := scanner.ScanString(content)
    if err != nil {
        log.Fatal(err)
    }

    // Process results
    fmt.Printf("Found %d potential secrets:\n", len(matches))
    for _, match := range matches {
        fmt.Printf("  - %s (rule: %s) at line %d\n",
            match.RuleName,
            match.RuleID,
            match.Location.SourceSpan.Start.Line,
        )
    }
}
```

## Features

### Basic Scanning

```go
// Scan a string
matches, err := scanner.ScanString("api_key=sk_live_1234567890")

// Scan raw bytes
matches, err := scanner.ScanBytes([]byte(content))

// Scan a file
matches, err := scanner.ScanFile("/path/to/config.json")
```

### With Secret Validation

Enable validation to check if detected secrets are still active:

```go
scanner, err := titus.NewScanner(titus.WithValidation())
if err != nil {
    log.Fatal(err)
}
defer scanner.Close()

matches, err := scanner.ScanString(content)
if err != nil {
    log.Fatal(err)
}

for _, match := range matches {
    if match.ValidationResult != nil {
        switch match.ValidationResult.Status {
        case titus.StatusValid:
            fmt.Printf("ACTIVE SECRET: %s\n", match.RuleName)
        case titus.StatusInvalid:
            fmt.Printf("Expired/revoked: %s\n", match.RuleName)
        case titus.StatusUndetermined:
            fmt.Printf("Could not verify: %s\n", match.RuleName)
        }
    }
}
```

### Custom Rules

Use your own detection rules:

```go
// Load rules from a YAML file
rules, err := titus.LoadRulesFromFile("/path/to/custom-rules.yaml")
if err != nil {
    log.Fatal(err)
}

scanner, err := titus.NewScanner(titus.WithRules(rules))
```

### Filter Builtin Rules

Use a subset of builtin rules:

```go
rules, err := titus.LoadBuiltinRules()
if err != nil {
    log.Fatal(err)
}

// Filter to only AWS-related rules
var awsRules []*titus.Rule
for _, r := range rules {
    if strings.HasPrefix(r.ID, "np.aws") {
        awsRules = append(awsRules, r)
    }
}

scanner, err := titus.NewScanner(titus.WithRules(awsRules))
```

### Configuration Options

```go
scanner, err := titus.NewScanner(
    titus.WithContextLines(5),           // Lines of context around matches (default: 2)
    titus.WithValidation(),               // Enable secret validation
    titus.WithValidationWorkers(8),       // Concurrent validation workers (default: 4)
    titus.WithRules(customRules),         // Custom detection rules
)
```

## Working with Matches

Each `Match` contains detailed information about the detected secret:

```go
for _, match := range matches {
    // Rule information
    fmt.Printf("Rule ID: %s\n", match.RuleID)       // e.g., "np.aws.1"
    fmt.Printf("Rule Name: %s\n", match.RuleName)   // e.g., "AWS API Key"

    // Location in source
    fmt.Printf("Line: %d, Column: %d\n",
        match.Location.SourceSpan.Start.Line,
        match.Location.SourceSpan.Start.Column,
    )
    fmt.Printf("Byte offset: %d-%d\n",
        match.Location.Offset.Start,
        match.Location.Offset.End,
    )

    // Matched content with context
    fmt.Printf("Before: %s\n", string(match.Snippet.Before))
    fmt.Printf("Match:  %s\n", string(match.Snippet.Matching))
    fmt.Printf("After:  %s\n", string(match.Snippet.After))

    // Named capture groups (when available)
    if secret, ok := match.NamedGroups["secret"]; ok {
        fmt.Printf("Secret value: %s\n", string(secret))
    }

    // Validation result (if validation enabled)
    if match.ValidationResult != nil {
        fmt.Printf("Validation: %s (%s)\n",
            match.ValidationResult.Status,
            match.ValidationResult.Message,
        )
    }
}
```

## Context and Cancellation

For long-running scans or when you need cancellation support:

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

matches, err := scanner.ScanStringWithContext(ctx, largeContent)
if err != nil {
    if ctx.Err() != nil {
        log.Println("Scan timed out")
    }
    return err
}
```

## Concurrency

**Important:** Each scanner instance uses Hyperscan internally, which requires exclusive access to its scratch memory during scanning. For concurrent scanning, use one of these patterns:

### Pattern 1: Multiple Scanner Instances

Create a scanner per goroutine:

```go
var wg sync.WaitGroup
for _, file := range files {
    wg.Add(1)
    go func(path string) {
        defer wg.Done()

        scanner, _ := titus.NewScanner()
        defer scanner.Close()

        matches, _ := scanner.ScanFile(path)
        processMatches(matches)
    }(file)
}
wg.Wait()
```

### Pattern 2: Worker Pool with Scanner Pool

For high-throughput scanning, use a pool of scanners:

```go
type ScannerPool struct {
    scanners chan *titus.Scanner
}

func NewScannerPool(size int) (*ScannerPool, error) {
    pool := &ScannerPool{
        scanners: make(chan *titus.Scanner, size),
    }
    for i := 0; i < size; i++ {
        s, err := titus.NewScanner()
        if err != nil {
            return nil, err
        }
        pool.scanners <- s
    }
    return pool, nil
}

func (p *ScannerPool) Scan(content string) ([]*titus.Match, error) {
    scanner := <-p.scanners
    defer func() { p.scanners <- scanner }()
    return scanner.ScanString(content)
}
```

### Pattern 3: Sequential Scanning (Single Scanner)

A single scanner is safe for sequential scans:

```go
scanner, _ := titus.NewScanner()
defer scanner.Close()

for _, file := range files {
    matches, _ := scanner.ScanFile(file)
    processMatches(matches)
}
```

## Complete Example

Here's a complete example that scans a directory for secrets:

```go
package main

import (
    "fmt"
    "log"
    "os"
    "path/filepath"

    "github.com/praetorian-inc/titus"
)

func main() {
    // Create scanner with validation
    scanner, err := titus.NewScanner(
        titus.WithValidation(),
        titus.WithContextLines(3),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer scanner.Close()

    fmt.Printf("Loaded %d detection rules\n", scanner.RuleCount())

    // Walk directory and scan files
    root := "./src"
    var totalSecrets int

    err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }

        // Skip directories and binary files
        if info.IsDir() {
            return nil
        }

        matches, err := scanner.ScanFile(path)
        if err != nil {
            // Skip files that can't be scanned
            return nil
        }

        for _, match := range matches {
            totalSecrets++
            status := "unknown"
            if match.ValidationResult != nil {
                status = string(match.ValidationResult.Status)
            }

            fmt.Printf("[%s] %s:%d - %s\n",
                status,
                path,
                match.Location.SourceSpan.Start.Line,
                match.RuleName,
            )
        }

        return nil
    })

    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("\nTotal secrets found: %d\n", totalSecrets)
}
```

## Performance Tips

1. **Reuse the scanner**: Creating a scanner loads all rules into memory. Create one scanner and reuse it.

2. **Batch scanning**: For many small pieces of content, the scanning overhead is minimal per call.

3. **Disable validation for discovery**: Validation makes API calls which can be slow. Use `ScanString` without validation for initial discovery, then validate only interesting finds.

4. **Filter rules**: If you only care about specific secret types, filter the rules to reduce matching overhead:

```go
rules, _ := titus.LoadBuiltinRules()
var cloudRules []*titus.Rule
for _, r := range rules {
    if strings.Contains(r.ID, "aws") ||
       strings.Contains(r.ID, "azure") ||
       strings.Contains(r.ID, "gcp") {
        cloudRules = append(cloudRules, r)
    }
}
scanner, _ := titus.NewScanner(titus.WithRules(cloudRules))
```

## API Reference

See the [GoDoc](https://pkg.go.dev/github.com/praetorian-inc/titus) for complete API documentation.

### Main Functions

| Function | Description |
|----------|-------------|
| `NewScanner(opts...)` | Create a new scanner with options |
| `LoadBuiltinRules()` | Load all builtin detection rules |
| `LoadRulesFromFile(path)` | Load rules from a YAML file |

### Scanner Methods

| Method | Description |
|--------|-------------|
| `ScanString(content)` | Scan a string for secrets |
| `ScanBytes(content)` | Scan raw bytes for secrets |
| `ScanFile(path)` | Read and scan a file |
| `ScanStringWithContext(ctx, content)` | Scan with cancellation support |
| `ScanBytesWithContext(ctx, content)` | Scan bytes with cancellation |
| `Close()` | Release scanner resources |
| `RuleCount()` | Number of loaded rules |
| `Rules()` | Get loaded rules |
| `ValidationEnabled()` | Check if validation is on |

### Options

| Option | Description |
|--------|-------------|
| `WithRules(rules)` | Use custom detection rules |
| `WithContextLines(n)` | Lines of context around matches |
| `WithValidation()` | Enable secret validation |
| `WithValidationWorkers(n)` | Concurrent validation workers |
