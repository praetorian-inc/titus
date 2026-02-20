package rule

// yamlRule is the intermediate struct for parsing NoseyParker YAML rule format.
// Maps YAML fields to types.Rule structure.
type yamlRule struct {
	Name             string   `yaml:"name"`
	ID               string   `yaml:"id"`
	Pattern          string   `yaml:"pattern"`
	Description      string   `yaml:"description,omitempty"`
	Examples         []string `yaml:"examples,omitempty"`
	NegativeExamples []string `yaml:"negative_examples,omitempty"`
	References       []string `yaml:"references,omitempty"`
	Categories       []string `yaml:"categories,omitempty"`
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
