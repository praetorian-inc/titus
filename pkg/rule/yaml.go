package rule

// yamlPatternRequirements is the intermediate struct for parsing pattern requirements.
type yamlPatternRequirements struct {
	MinDigits        int      `yaml:"min_digits,omitempty"`
	MinUppercase     int      `yaml:"min_uppercase,omitempty"`
	MinLowercase     int      `yaml:"min_lowercase,omitempty"`
	MinSpecialChars  int      `yaml:"min_special_chars,omitempty"`
	SpecialChars     string   `yaml:"special_chars,omitempty"`
	IgnoreIfContains []string `yaml:"ignore_if_contains,omitempty"`
}

// yamlRule is the intermediate struct for parsing NoseyParker YAML rule format.
// Maps YAML fields to types.Rule structure.
type yamlRule struct {
	Name                string                   `yaml:"name"`
	ID                  string                   `yaml:"id"`
	Pattern             string                   `yaml:"pattern"`
	Description         string                   `yaml:"description,omitempty"`
	Examples            []string                 `yaml:"examples,omitempty"`
	NegativeExamples    []string                 `yaml:"negative_examples,omitempty"`
	References          []string                 `yaml:"references,omitempty"`
	Categories          []string                 `yaml:"categories,omitempty"`
	MinEntropy          float64                  `yaml:"min_entropy,omitempty"`
	PatternRequirements *yamlPatternRequirements `yaml:"pattern_requirements,omitempty"`
}

// yamlRulesFile represents the top-level structure of a rules YAML file.
// NoseyParker format uses a "rules" array at the top level.
type yamlRulesFile struct {
	Rules []yamlRule `yaml:"rules"`
}

// yamlRuleset is the intermediate struct for parsing NoseyParker YAML ruleset format.
type yamlRuleset struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	RuleIDs     []string `yaml:"include_rule_ids"`
}

// yamlRulesetsFile represents the top-level structure of a rulesets YAML file.
type yamlRulesetsFile struct {
	Rulesets []yamlRuleset `yaml:"rulesets"`
}
