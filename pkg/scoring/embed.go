package scoring

import "embed"

// builtinFS embeds the built-in scorer YAML files under scorers/.
// Phase 0 uses the all: prefix so .gitkeep (a dot-file) is included,
// keeping the embed valid until Phase 2 adds real scorer YAML files.
// Phase 2 tightens to `//go:embed scorers/*.yaml` once real files land.
//
//go:embed all:scorers
var builtinFS embed.FS
