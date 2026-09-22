package scoring

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// buildFiresWhenLeafInner converts a yamlFiresWhen into the underlying firesWhenLeaf,
// ignoring the negative: flag (applied by buildFiresWhenLeaf).
// Exactly one field must be set; returns an error if zero or multiple are set.
func buildFiresWhenLeafInner(fw *yamlFiresWhen) (firesWhenLeaf, error) {
	if n := countFiresWhenLeaves(fw); n != 1 {
		return nil, fmt.Errorf("fires_when: exactly one condition leaf required (got %d)", n)
	}
	switch {
	case fw.StatusCode != nil:
		return &statusCodeLeaf{Code: *fw.StatusCode}, nil
	case len(fw.StatusCodeIn) > 0:
		return &statusCodeInLeaf{Codes: fw.StatusCodeIn}, nil
	case fw.ResponseBodyContains != "":
		return &responseBodyContainsLeaf{Value: fw.ResponseBodyContains}, nil
	case fw.HeaderContains != nil:
		return &headerContainsLeaf{Name: fw.HeaderContains.Name, Value: fw.HeaderContains.Value}, nil
	case fw.JSONPathEquals != nil:
		return &jsonPathEqualsLeaf{Path: fw.JSONPathEquals.Path, Value: fw.JSONPathEquals.Value}, nil
	case fw.JSONPathMatches != nil:
		re, err := regexp.Compile(fw.JSONPathMatches.Regex)
		if err != nil {
			return nil, fmt.Errorf("json_path_matches regex: %w", err)
		}
		return &jsonPathMatchesLeaf{Path: fw.JSONPathMatches.Path, Regex: fw.JSONPathMatches.Regex, re: re}, nil
	case fw.JSONArrayLengthGte != nil:
		return &jsonArrayLengthGteLeaf{Path: fw.JSONArrayLengthGte.Path, Value: fw.JSONArrayLengthGte.Value}, nil
	default:
		return nil, fmt.Errorf("fires_when: no leaf condition specified (need status_code, header_contains, etc.)")
	}
}

// yamlAuthToScorerAuth converts a YAML auth definition to the internal scorerAuth type.
func yamlAuthToScorerAuth(a yamlScorerAuth) scorerAuth {
	return scorerAuth(a)
}

// yamlHeadersToScorerHeaders converts a slice of YAML header definitions to scorerHeaders.
func yamlHeadersToScorerHeaders(hs []yamlHeader) []scorerHeader {
	out := make([]scorerHeader, len(hs))
	for i, h := range hs {
		out[i] = scorerHeader(h)
	}
	return out
}

// ScorerLoader handles loading scorer YAML files. Mirrors pkg/rule.Loader.
type ScorerLoader struct {
	fs fs.FS
}

// NewLoader creates a loader backed by the embedded builtinFS.
func NewLoader() *ScorerLoader {
	return &ScorerLoader{fs: builtinFS}
}

// NewLoaderWithFS creates a loader backed by a custom fs.FS (for tests).
func NewLoaderWithFS(fsys fs.FS) *ScorerLoader {
	return &ScorerLoader{fs: fsys}
}

// LoadScorers parses a scorers YAML document and returns the compiled Scorers.
// Regex compile errors, missing leaves, ambiguous actions, etc. are hard
// failures — the caller (scan startup) must abort.
func (l *ScorerLoader) LoadScorers(data []byte) ([]*Scorer, error) {
	var yf yamlScorersFile
	if err := yaml.Unmarshal(data, &yf); err != nil {
		return nil, fmt.Errorf("failed to parse scorer YAML: %w", err)
	}
	if len(yf.Scorers) == 0 {
		return nil, fmt.Errorf("no scorers found in YAML")
	}
	result := make([]*Scorer, 0, len(yf.Scorers))
	for i, ys := range yf.Scorers {
		s, err := convertYAMLScorer(ys)
		if err != nil {
			return nil, fmt.Errorf("scorer[%d] %q: %w", i, ys.Name, err)
		}
		result = append(result, s)
	}
	return result, nil
}

// LoadBuiltinScorers walks the embedded scorers/ directory and loads every
// .yaml file. Mirrors pkg/rule/loader.go:86-125.
func (l *ScorerLoader) LoadBuiltinScorers() ([]*Scorer, error) {
	var scorers []*Scorer
	err := fs.WalkDir(l.fs, "scorers", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		data, err := fs.ReadFile(l.fs, path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}
		loaded, err := l.LoadScorers(data)
		if err != nil {
			return fmt.Errorf("loading %s: %w", path, err)
		}
		scorers = append(scorers, loaded...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return scorers, nil
}

// convertYAMLScorer compiles a yamlScorer into a *Scorer, validating every
// modifier and precompiling all regexes.
func convertYAMLScorer(ys yamlScorer) (*Scorer, error) {
	if ys.Name == "" {
		return nil, fmt.Errorf("scorer name is required")
	}
	if len(ys.RuleIDs) == 0 {
		return nil, fmt.Errorf("scorer %q: rule_ids must be non-empty", ys.Name)
	}
	if len(ys.Modifiers) == 0 {
		return nil, fmt.Errorf("scorer %q: modifiers must be non-empty", ys.Name)
	}
	out := &Scorer{
		Name:      ys.Name,
		RuleIDs:   append([]string(nil), ys.RuleIDs...),
		Modifiers: make([]Modifier, 0, len(ys.Modifiers)),
	}
	for i, ym := range ys.Modifiers {
		m, err := convertYAMLModifier(ym)
		if err != nil {
			return nil, fmt.Errorf("modifier[%d] %q: %w", i, ym.Name, err)
		}
		out.Modifiers = append(out.Modifiers, m)
	}
	return out, nil
}

// convertYAMLModifier enforces the "exactly one condition, exactly one action"
// rule and compiles the regex (if any).
func convertYAMLModifier(ym yamlModifier) (Modifier, error) {
	if ym.Name == "" {
		return Modifier{}, fmt.Errorf("modifier name is required")
	}

	// Validate http: and fires_when: must appear together.
	if ym.HTTP != nil && ym.FiresWhen == nil {
		return Modifier{}, fmt.Errorf("http: block requires a fires_when: block")
	}
	if ym.FiresWhen != nil && ym.HTTP == nil {
		return Modifier{}, fmt.Errorf("fires_when: block requires an http: block")
	}

	// Condition: exactly one
	condCount := 0
	var cond Condition
	if ym.MatchGroup != nil {
		condCount++
		if ym.MatchGroup.Name == "" {
			return Modifier{}, fmt.Errorf("match_group.name is required")
		}
		if ym.MatchGroup.Matches == "" {
			return Modifier{}, fmt.Errorf("match_group.matches is required")
		}
		re, err := regexp.Compile(ym.MatchGroup.Matches)
		if err != nil {
			return Modifier{}, fmt.Errorf("match_group.matches regex %q: %w", ym.MatchGroup.Matches, err)
		}
		cond = &matchGroupCondition{Name: ym.MatchGroup.Name, Regex: re}
	}
	if ym.SurroundingContextContains != nil {
		condCount++
		if ym.SurroundingContextContains.Value == "" {
			return Modifier{}, fmt.Errorf("surrounding_context_contains.value is required")
		}
		if ym.SurroundingContextContains.Within < 0 {
			return Modifier{}, fmt.Errorf("surrounding_context_contains.within must be >= 0")
		}
		cond = &surroundingContextContainsCondition{
			Within: ym.SurroundingContextContains.Within,
			Value:  ym.SurroundingContextContains.Value,
		}
	}
	if ym.MatchLength != nil {
		condCount++
		op := matchLengthOp(ym.MatchLength.Op)
		switch op {
		case matchLengthOpGT, matchLengthOpLT, matchLengthOpEQ:
		default:
			return Modifier{}, fmt.Errorf("match_length.op must be gt|lt|eq, got %q", ym.MatchLength.Op)
		}
		cond = &matchLengthCondition{Op: op, Value: ym.MatchLength.Value}
	}
	if ym.HTTP != nil && ym.FiresWhen != nil {
		condCount++
		if t := strings.ToLower(ym.HTTP.Auth.Type); t != "" && !supportedAuthTypes[t] {
			return Modifier{}, fmt.Errorf("http.auth.type %q is not supported (want one of: api_key, basic, bearer, header, none, query)", ym.HTTP.Auth.Type)
		}
		leaf, err := buildFiresWhenLeaf(ym.FiresWhen)
		if err != nil {
			return Modifier{}, fmt.Errorf("modifier %q fires_when: %w", ym.Name, err)
		}
		cond = &httpCondition{
			method:       ym.HTTP.Method,
			url:          ym.HTTP.URL,
			fallbackURLs: ym.HTTP.FallbackURLs,
			auth:         yamlAuthToScorerAuth(ym.HTTP.Auth),
			headers:      yamlHeadersToScorerHeaders(ym.HTTP.Headers),
			body:         ym.HTTP.Body,
			firesWhen:    leaf,
		}
	}
	if condCount != 1 {
		return Modifier{}, fmt.Errorf("exactly one condition leaf required (got %d)", condCount)
	}

	// Action: exactly one
	actionCount := 0
	var kind ModifierKind
	var value int
	if ym.Delta != nil {
		actionCount++
		kind = ModifierKindDelta
		value = *ym.Delta
	}
	if ym.SetScore != nil {
		actionCount++
		kind = ModifierKindSetScore
		value = *ym.SetScore
		if value < 0 || value > 100 {
			return Modifier{}, fmt.Errorf("set_score must be in [0, 100], got %d", value)
		}
	}
	if actionCount != 1 {
		return Modifier{}, fmt.Errorf("exactly one of delta or set_score required (got %d)", actionCount)
	}

	return Modifier{
		Name:      ym.Name,
		Priority:  ym.Priority, // default 0 when omitted
		Kind:      kind,
		Value:     value,
		Condition: cond,
	}, nil
}

// buildFiresWhenLeaf builds the fires_when leaf and applies the negative: flag.
// negative: is a modifier ON a leaf rather than a leaf in its own right, so it is
// deliberately not part of the "exactly one condition leaf" accounting.
func buildFiresWhenLeaf(fw *yamlFiresWhen) (firesWhenLeaf, error) {
	leaf, err := buildFiresWhenLeafInner(fw)
	if err != nil {
		return nil, err
	}
	if fw.Negative {
		return &negatedLeaf{inner: leaf}, nil
	}
	return leaf, nil
}

// countFiresWhenLeaves counts how many condition leaves a fires_when block
// declares. negative: is a flag on a leaf, not a leaf, so it is not counted.
func countFiresWhenLeaves(fw *yamlFiresWhen) int {
	n := 0
	for _, set := range []bool{
		fw.StatusCode != nil,
		len(fw.StatusCodeIn) > 0,
		fw.ResponseBodyContains != "",
		fw.HeaderContains != nil,
		fw.JSONPathEquals != nil,
		fw.JSONPathMatches != nil,
		fw.JSONArrayLengthGte != nil,
	} {
		if set {
			n++
		}
	}
	return n
}
