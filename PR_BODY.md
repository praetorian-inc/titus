## Summary

Complete Go port of NoseyParker secrets scanner with core functionality:

- **pkg/types**: Core types (BlobID, Match, Finding, Rule, Provenance) - 39 tests
- **pkg/rule**: YAML rule loading (NoseyParker format compatible) - 33 tests
- **pkg/matcher**: Hyperscan-based multi-pattern matching - 26 tests
- **pkg/store**: SQLite persistence (NoseyParker schema v70) - 14 tests
- **pkg/enum**: Filesystem + Git enumeration - 11 tests
- **cmd/titus**: CLI commands (scan, rules, version) - 5 tests

**Total: 128 tests passing**

## Architecture Decisions

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Regex Engine | Hyperscan (cgo) | Fast multi-pattern matching, SOM support |
| SQLite | mattn/go-sqlite3 | NoseyParker schema compatibility |
| Git | go-git | Pure Go, no CGO for git ops |
| CLI | Cobra | Standard Go CLI pattern |

## Key Implementation Details

- **Two-stage matching**: Hyperscan finds offsets → Go regexp extracts capture groups
- **Git-style BlobID**: SHA-1("blob {len}\0{content}") for content addressing
- **Schema v70**: Compatible with NoseyParker tooling

## Test plan

- [x] All 128 unit tests pass
- [x] CLI builds and runs (`titus --help`, `titus scan`, `titus rules list`)
- [x] Hyperscan integration verified with real patterns
- [ ] Manual testing with real codebase
- [ ] Integration with actual NoseyParker rules
