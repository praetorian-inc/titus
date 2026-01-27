# NoseyParker Feature Gap Analysis

This document tracks features in NoseyParker that have not yet been ported to Titus.

## Feature Comparison

| Feature | NoseyParker | Titus | Priority | Effort |
|---------|-------------|-------|----------|--------|
| **Builtin Rules** | 189 detection rules | Placeholder only | **Critical** | 2-4h |
| **Full Git History** | All commits, all branches | HEAD only | **High** | 4-6h |
| **GitHub API Enumeration** | Enumerate repos/orgs via API | Not implemented | Medium | 4-6h |
| **GitLab API Enumeration** | Enumerate projects via API | Not implemented | Medium | 4-6h |
| **SARIF Output** | Full SARIF 2.1.0 format | Stub only | Medium | 2-3h |
| **Report Command** | `noseyparker report` summaries | Not implemented | Medium | 2-3h |
| **Incremental Scanning** | Skip already-scanned blobs | Not implemented | Medium | 2-4h |
| **Snippet Context** | Before/after lines around match | Match only | Low | 1-2h |
| **Rule Allowlist/Denylist** | `--rules-include/exclude` | Not implemented | Low | 1h |
| **Datastore Merging** | Merge multiple .db files | Not implemented | Low | 2h |
| **Multiple Provenance** | Multiple sources per blob | Single provenance | Low | 2h |
| **GitHub Actions** | CI/CD workflow support | Not implemented | Low | 1h |

## Critical Gaps (Must Have)

### 1. Builtin Rules
**Status**: Placeholder YAML files only

NoseyParker ships with 189 detection rules covering:
- AWS credentials (access keys, secret keys)
- GCP service accounts
- Azure credentials
- GitHub/GitLab tokens
- Database connection strings
- SSH private keys
- JWT tokens
- API keys (Stripe, Twilio, SendGrid, etc.)

**Action**: Port rules from NoseyParker's `crates/noseyparker/data/default/rules/` to `pkg/rule/rules/`

### 2. Full Git History Walking
**Status**: Only scans HEAD commit

NoseyParker walks:
- All commits in history
- All branches (local and remote)
- Detached HEAD states
- Tags

**Current limitation**: `GitEnumerator` only processes the tree at HEAD.

**Action**: Extend `pkg/enum/git.go` to walk commit history with:
```go
// Walk all commits
commitIter, _ := repo.Log(&git.LogOptions{All: true})
commitIter.ForEach(func(c *object.Commit) error {
    // Process each commit's tree
})
```

## High Priority Gaps

### 3. GitHub/GitLab API Enumeration
NoseyParker can enumerate repositories from:
- GitHub organizations
- GitHub users
- GitLab groups
- GitLab users

This allows scanning without cloning repos locally.

### 4. SARIF Output
Static Analysis Results Interchange Format - required for:
- GitHub Code Scanning
- Azure DevOps
- Many CI/CD integrations

Current: Returns "SARIF output not yet implemented" error.

## What Works Today

```bash
# Scan a directory
titus scan /path/to/code

# Scan git repository (HEAD only)
titus scan /path/to/repo --git

# List available rules
titus rules list

# JSON output
titus scan /path/to/code --format json

# Custom rules
titus scan /path/to/code --rules /path/to/custom-rules.yaml
```

## Recommended Implementation Order

1. **Port builtin rules** - Essential for real-world usage
2. **Full git history** - Major feature gap
3. **SARIF output** - CI/CD integration requirement
4. **Report command** - User experience
5. **Incremental scanning** - Performance for large repos
6. **API enumeration** - Enterprise feature
