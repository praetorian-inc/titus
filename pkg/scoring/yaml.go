package scoring

// yamlScorersFile is the top-level structure of a scorer YAML file.
//
//	scorers:
//	  - name: aws-key-scope
//	    rule_ids: [np.aws.1]
//	    modifiers:
//	      - name: akia-long-term
//	        priority: 100
//	        match_group: { name: key_id, matches: '^AKIA' }
//	        delta: 10
type yamlScorersFile struct {
	Scorers []yamlScorer `yaml:"scorers"`
}

type yamlScorer struct {
	Name      string         `yaml:"name"`
	RuleIDs   []string       `yaml:"rule_ids"`
	Modifiers []yamlModifier `yaml:"modifiers"`
}

// yamlModifier is a single modifier entry. Exactly one condition leaf MUST
// be present (match_group OR surrounding_context_contains OR match_length);
// exactly one of delta / set_score MUST be present. Loader enforces both.
type yamlModifier struct {
	Name     string `yaml:"name"`
	Priority int    `yaml:"priority,omitempty"`

	// Condition leaves (exactly one expected)
	MatchGroup                 *yamlMatchGroup                 `yaml:"match_group,omitempty"`
	SurroundingContextContains *yamlSurroundingContextContains `yaml:"surrounding_context_contains,omitempty"`
	MatchLength                *yamlMatchLength                `yaml:"match_length,omitempty"`

	// Action (exactly one expected). Pointers so absent vs. zero are distinct.
	Delta    *int `yaml:"delta,omitempty"`
	SetScore *int `yaml:"set_score,omitempty"`
}

type yamlMatchGroup struct {
	Name    string `yaml:"name"`
	Matches string `yaml:"matches"` // regex, compiled at load time
}

type yamlSurroundingContextContains struct {
	Within int    `yaml:"within,omitempty"`
	Value  string `yaml:"value"`
}

type yamlMatchLength struct {
	Op    string `yaml:"op"`    // "gt" | "lt" | "eq"
	Value int    `yaml:"value"`
}
