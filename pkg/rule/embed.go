package rule

import "embed"

// builtinRulesFS embeds the built-in rules directory.
// Rules will be added later during porting from NoseyParker.
//
//go:embed rules/*.yaml
var builtinRulesFS embed.FS

// builtinRulesetsFS embeds the built-in rulesets directory.
// Rulesets will be added later during porting from NoseyParker.
//
//go:embed rulesets/*.yaml
var builtinRulesetsFS embed.FS
