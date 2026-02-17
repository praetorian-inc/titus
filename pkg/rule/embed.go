package rule

import "embed"

// builtinRulesFS embeds the built-in rules directory.
// Contains 189 detection rules ported from NoseyParker.
//
//go:embed rules/*.yml
var builtinRulesFS embed.FS

// builtinRulesetsFS embeds the built-in rulesets directory.
// Contains rulesets ported from NoseyParker.
//
//go:embed rulesets/*.yml
var builtinRulesetsFS embed.FS
