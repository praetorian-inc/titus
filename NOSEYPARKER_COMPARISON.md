# Titus vs NoseyParker v0.24.0 Comparison

This document compares Titus (Go port) against NoseyParker v0.24.0 (original Rust implementation) for detection accuracy and performance.

## Summary

| Metric | NoseyParker v0.24.0 | Titus (non-CGO) |
|--------|---------------------|-----------------|
| **Detection** | Baseline | **+18-33% more findings** |
| **Dependencies** | Rust binary, Hyperscan | Pure Go, no CGO |
| **Small files (<100KB)** | ~1.3s | ~0.9-1.3s (comparable) |
| **Large files (1MB)** | ~1.2s (3.7 MiB/s) | ~6.1s (0.16 MiB/s) |
| **Cross-platform** | x86_64 only | Any (Windows, ARM, WASM) |

## Detection Accuracy

### Test File: test-secrets.html (4.7 KB)

**NoseyParker v0.24.0: 15 findings**
```
3 GitHub Personal Access Token
3 Generic API Key
2 AWS Secret Access Key
1 Stripe API Test Key
1 Slack Bot Token
1 SendGrid API Key
1 JSON Web Token
1 Google API Key
1 GitHub OAuth Access Token
1 Generic Password
```

**Titus: 18 findings (+20%)**
```
3 GitHub Personal Access Token
3 Generic API Key
2 AWS Secret Access Key
2 AWS API Key              ← ADDITIONAL
1 YouTube API Key          ← ADDITIONAL
1 Stripe API Test Key
1 Slack Bot Token
1 SendGrid API Key
1 JSON Web Token
1 Google API Key
1 GitHub OAuth Access Token
1 Generic Password
```

### Test Directory: testdata/secrets/ (4 files, 3.5 KB)

**NoseyParker: 15 findings**

**Titus: 20 findings (+33%)**
- Includes all NoseyParker detections
- Additional: AWS API Key, Stability AI API Key, Contains Private Key, AWS Account ID

## Performance Comparison

| Test | NoseyParker | Titus | Ratio |
|------|-------------|-------|-------|
| 4.7 KB (small) | 1.35s | 1.29s | **1.0x** |
| 100 KB (medium) | 1.37s | 0.90s | **0.7x (faster!)** |
| 1 MB (large) | 1.19s | 6.14s | 5.2x slower |
| 100 files (800 KB) | 1.06s | 3.18s | 3.0x slower |

### Analysis

1. **Startup overhead**: Both tools have ~1s startup cost (rule compilation)
2. **Small files**: Titus is competitive or faster (startup dominates)
3. **Large files**: NoseyParker's Hyperscan provides 3-5x speedup
4. **Throughput**:
   - NoseyParker: 3.7 MiB/s
   - Titus (non-CGO): ~0.16 MiB/s on large files

## Technical Differences

### NoseyParker
- Written in Rust
- Uses Hyperscan (Intel/Vectorscan) for regex matching
- Requires x86_64 architecture
- Binary distribution only

### Titus (non-CGO)
- Written in Go
- Uses regexp2 (pure Go, Perl-compatible regex)
- Cross-platform (Windows, macOS, Linux, ARM, WASM)
- Library and CLI modes
- No CGO dependency

### Titus (CGO mode, optional)
- Can use Hyperscan for 3-5x speedup on large files
- Requires CGO and Hyperscan library installed
- Build with: `CGO_ENABLED=1 go build -tags hyperscan`

## Parity Test

A dedicated test ensures Titus finds all secrets that NoseyParker finds:

```go
// pkg/matcher/noseyparker_comparison_test.go
func TestNoseyParkerParity_HTMLTestFile(t *testing.T)
func TestNoseyParkerParity_MixedSecrets(t *testing.T)
```

Run with:
```bash
go test ./pkg/matcher/... -run TestNoseyParkerParity -v
```

## Recommendations

### Use Titus non-CGO for:
- Library integration in Go projects
- Cross-platform deployment
- Small to medium file scanning
- Maximum detection coverage
- Environments where CGO is problematic

### Consider Hyperscan (CGO) for:
- Bulk scanning of large repositories
- High-throughput production pipelines
- When 3-5x speedup justifies CGO complexity

## Running the Comparison

```bash
# Download NoseyParker
curl -sL "https://github.com/praetorian-inc/noseyparker/releases/download/v0.24.0/noseyparker-v0.24.0-$(uname -m)-apple-darwin.tar.gz" | tar -xz

# Run NoseyParker
./bin/noseyparker scan --datastore /tmp/np testdata/secrets/
./bin/noseyparker report --datastore /tmp/np

# Run Titus
CGO_ENABLED=0 go build -o titus ./cmd/titus
./titus scan testdata/secrets/ --output :memory:
```
