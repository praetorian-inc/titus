package scoring

import "embed"

// builtinFS embeds the built-in scorer YAML files.
//
//go:embed scorers/*.yaml
var builtinFS embed.FS
