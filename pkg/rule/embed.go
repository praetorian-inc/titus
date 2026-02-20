package rule

import "embed"

// builtinFS embeds the built-in rules and rulesets directories.
//
//go:embed rules/*.yml rulesets/*.yml
var builtinFS embed.FS
