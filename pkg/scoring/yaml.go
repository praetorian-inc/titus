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
// be present (match_group OR surrounding_context_contains OR match_length OR
// http+fires_when pair); exactly one of delta / set_score MUST be present.
// Loader enforces both.
type yamlModifier struct {
	Name     string `yaml:"name"`
	Priority int    `yaml:"priority,omitempty"`

	// Static condition leaves (M2)
	MatchGroup                 *yamlMatchGroup                 `yaml:"match_group,omitempty"`
	SurroundingContextContains *yamlSurroundingContextContains `yaml:"surrounding_context_contains,omitempty"`
	MatchLength                *yamlMatchLength                `yaml:"match_length,omitempty"`

	// Dynamic conditions (M3)
	HTTP      *yamlHTTPDef   `yaml:"http,omitempty"`
	FiresWhen *yamlFiresWhen `yaml:"fires_when,omitempty"`

	// Action (exactly one expected). Pointers so absent vs. zero are distinct.
	Delta    *int `yaml:"delta,omitempty"`
	SetScore *int `yaml:"set_score,omitempty"`
}

// yamlHTTPDef mirrors pkg/validator/yaml.go HTTPDef but lives in the scorer package.
type yamlHTTPDef struct {
	Method  string         `yaml:"method"`
	URL     string         `yaml:"url"`
	Auth    yamlScorerAuth `yaml:"auth,omitempty"`
	Headers []yamlHeader   `yaml:"headers,omitempty"`
	Body    string         `yaml:"body,omitempty"`
}

type yamlScorerAuth struct {
	Type        string `yaml:"type"`
	SecretGroup string `yaml:"secret_group"`
	HeaderName  string `yaml:"header_name,omitempty"`
	QueryParam  string `yaml:"query_param,omitempty"`
	Username    string `yaml:"username,omitempty"`
	KeyPrefix   string `yaml:"key_prefix,omitempty"`
}

type yamlHeader struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// yamlFiresWhen holds exactly one fires_when leaf (validated at load time).
type yamlFiresWhen struct {
	StatusCode           *int                    `yaml:"status_code,omitempty"`
	StatusCodeIn         []int                   `yaml:"status_code_in,omitempty"`
	ResponseBodyContains string                  `yaml:"response_body_contains,omitempty"`
	HeaderContains       *yamlHeaderContains     `yaml:"header_contains,omitempty"`
	JSONPathEquals       *yamlJSONPathEquals     `yaml:"json_path_equals,omitempty"`
	JSONPathMatches      *yamlJSONPathMatches    `yaml:"json_path_matches,omitempty"`
	JSONArrayLengthGte   *yamlJSONArrayLengthGte `yaml:"json_array_length_gte,omitempty"`
}

type yamlHeaderContains struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type yamlJSONPathEquals struct {
	Path  string      `yaml:"path"`
	Value interface{} `yaml:"value"`
}

type yamlJSONPathMatches struct {
	Path  string `yaml:"path"`
	Regex string `yaml:"regex"`
}

type yamlJSONArrayLengthGte struct {
	Path  string `yaml:"path"`
	Value int    `yaml:"value"`
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
