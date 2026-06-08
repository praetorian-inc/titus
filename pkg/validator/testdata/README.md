# Cassette Provenance Convention

Each service directory under `pkg/validator/testdata/` contains:

1. One or more `.yaml` cassette files (recorded HTTP interactions, redacted by go-vcr)
2. A mandatory `provenance.yaml` sidecar documenting the recording context

## Required `provenance.yaml` Format

```yaml
service: huggingface
ticket: LAB-4074
captured: 2026-06-08
account_type: free-personal     # free | trial | self-host | cloud-free-tier
key_revoked: true               # MUST be true before commit
valid_response: {status: 200, discriminator: body "name"}
invalid_response: {status: 401}
notes: token created + revoked at hf.co/settings/tokens
```

## Fields

| Field              | Required | Description                                                                 |
|--------------------|----------|-----------------------------------------------------------------------------|
| `service`          | yes      | Service name matching the validator YAML filename (without `.yaml`)         |
| `ticket`           | yes      | Linear ticket ID that originated this cassette                              |
| `captured`         | yes      | ISO date when the cassette was recorded (YYYY-MM-DD)                        |
| `account_type`     | yes      | One of: `free`, `trial`, `self-host`, `cloud-free-tier`                     |
| `key_revoked`      | yes      | MUST be `true` — the key used to record MUST be revoked before committing   |
| `valid_response`   | yes      | Short description of what a valid credential response looks like            |
| `invalid_response` | yes      | Short description of what an invalid credential response looks like         |
| `notes`            | no       | Any additional context (where the key was created, special setup, etc.)     |

## Security Requirements

**DO NOT commit cassettes with live secrets.** The `vcrtest` harness automatically
redacts secrets via the `AfterCaptureHook` before writing to disk. Additionally:

- Set `SECRET_PLAINTEXT` env var during recording so the hook can scrub the raw value
- Run `make scan-fixtures` before every commit touching `testdata/` — it fails on any finding
- When testing the scanner gate manually, use a valid-format canary key. For AWS, the
  `np.aws.1` rule expects exactly 20 characters starting with `AKIA`. Example format:
  `AKIA` + 16 uppercase letters/digits. Keys with fewer or more than 20 total characters
  will not trigger the rule.
- Revoke the recording key immediately after capture; set `key_revoked: true`

## Directory Structure

```
pkg/validator/testdata/
├── README.md              <- This file
├── huggingface/
│   ├── provenance.yaml    <- Required sidecar
│   ├── valid.yaml         <- Cassette: valid token response
│   └── invalid.yaml       <- Cassette: invalid/expired token response
├── github/
│   ├── provenance.yaml
│   ├── valid.yaml
│   └── invalid.yaml
└── ...
```

## Recording New Cassettes

```bash
# 1. Export your (temporary) key
export RECORD=1
export SECRET_PLAINTEXT="your-actual-key-here"

# 2. Record cassettes for a specific service
make record-fixtures SVC=huggingface

# 3. Immediately revoke the key at the service provider

# 4. Scan for leftover secrets
make scan-fixtures

# 5. Create provenance.yaml next to the cassettes

# 6. Commit
git add pkg/validator/testdata/
git commit -m "test(validator): add huggingface cassettes (LAB-4074)"
```
