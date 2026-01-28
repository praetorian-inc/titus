# Test Secrets Fixtures

This directory contains **intentionally fake secrets** for integration testing.

## Purpose

These files contain patterns that match Titus detection rules to verify the scanner correctly identifies secrets. All values are:

- **Completely fake** - not real credentials
- **Obviously test data** - using patterns like `TESTKEY`, `FAKE`, etc.
- **Safe to commit** - designed for testing purposes only

## Usage

```bash
# Run integration tests
make integration-test

# Manual test
./titus scan testdata/secrets/ --format=json
```

## Files

| File | Secret Types | Expected Findings |
|------|--------------|-------------------|
| `aws-keys.txt` | AWS API Key, AWS Secret | 2+ |
| `github-tokens.txt` | GitHub PAT, GitHub OAuth | 2+ |
| `mixed-secrets.txt` | Various types | 3+ |

## Adding New Test Cases

1. Add fake secrets that match rule patterns in `pkg/rule/rules/*.yml`
2. Use obviously fake values (TESTKEY, FAKE, etc.)
3. Update expected counts in `scripts/integration-test.sh`
