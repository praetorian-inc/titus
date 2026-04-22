package sarif

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/titus/pkg/types"
)

// SARIF 2.1.0 constants
const (
	SchemaURI   = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	Version     = "2.1.0"
	ToolName    = "titus"
	ToolVersion = "0.1.0"
)

// Report is the top-level SARIF report structure
type Report struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single invocation of the tool
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool describes the analysis tool
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver contains tool metadata
type Driver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Rules   []Rule `json:"rules,omitempty"`
}

// Rule represents a detection rule
type Rule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription ShortDescription `json:"shortDescription"`
	HelpURI          string           `json:"helpUri,omitempty"`
}

// ShortDescription contains rule description text
type ShortDescription struct {
	Text string `json:"text"`
}

// ResultProperties holds the SARIF `properties` bag. Emitted under
// `result.properties` in the output JSON.
type ResultProperties struct {
	// SecuritySeverity is a string-encoded float in [0.0, 10.0] — the
	// GitHub Code Scanning convention. Computed as Score.Final / 10.
	SecuritySeverity string `json:"security-severity,omitempty"`
	// TitusScore is the full Score object for consumers that want the breakdown.
	TitusScore *types.Score `json:"titus_score,omitempty"`
}

// Result represents a single finding
type Result struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"`
	Message    Message           `json:"message"`
	Locations  []Location        `json:"locations"`
	Properties *ResultProperties `json:"properties,omitempty"`
}

// Message contains the result message
type Message struct {
	Text string `json:"text"`
}

// Location describes where a result was found
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation specifies file location
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

// ArtifactLocation identifies the file
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region specifies the line/column range
type Region struct {
	StartLine   int     `json:"startLine"`
	StartColumn int     `json:"startColumn"`
	EndLine     int     `json:"endLine"`
	EndColumn   int     `json:"endColumn"`
	Snippet     Snippet `json:"snippet,omitempty"`
}

// Snippet contains the matched text
type Snippet struct {
	Text string `json:"text"`
}

// NewReport creates a new SARIF report with initialized structure
func NewReport() *Report {
	return &Report{
		Schema:  SchemaURI,
		Version: Version,
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:    ToolName,
						Version: ToolVersion,
						Rules:   []Rule{},
					},
				},
				Results: []Result{},
			},
		},
	}
}

// AddRule adds a detection rule to the report
func (r *Report) AddRule(rule *types.Rule) {
	sarifRule := Rule{
		ID:   rule.ID,
		Name: rule.Name,
		ShortDescription: ShortDescription{
			Text: rule.Description,
		},
	}

	// Add first reference as helpUri if available
	if len(rule.References) > 0 {
		sarifRule.HelpURI = rule.References[0]
	}

	r.Runs[0].Tool.Driver.Rules = append(r.Runs[0].Tool.Driver.Rules, sarifRule)
}

// AddResult adds a finding result to the report
func (r *Report) AddResult(match *types.Match, filePath string) {
	// Convert file path to URI format
	uri := formatFileURI(filePath)

	// Create region with line/column information
	region := Region{
		StartLine:   match.Location.Source.Start.Line,
		StartColumn: match.Location.Source.Start.Column,
		EndLine:     match.Location.Source.End.Line,
		EndColumn:   match.Location.Source.End.Column,
	}

	// Add snippet if available
	if len(match.Snippet.Matching) > 0 {
		region.Snippet = Snippet{
			Text: string(match.Snippet.Matching),
		}
	}

	result := Result{
		RuleID: match.RuleID,
		Level:  "warning",
		Message: Message{
			Text: match.RuleName,
		},
		Locations: []Location{
			{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{
						URI: uri,
					},
					Region: region,
				},
			},
		},
	}

	r.Runs[0].Results = append(r.Runs[0].Results, result)
}

// ToJSON serializes the report to JSON bytes
func (r *Report) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// LevelForScore maps a 0-100 score to a SARIF level enum value.
func LevelForScore(score int) string {
	switch {
	case score < 20:
		return "none"
	case score < 40:
		return "note"
	case score < 60:
		return "warning"
	default:
		return "error"
	}
}

// AddResultWithScore adds a finding result with score metadata. Preferred over
// AddResult when a Score is available — level is band-mapped from score, and
// properties carry the full Score object for downstream consumers.
func (r *Report) AddResultWithScore(match *types.Match, filePath string, score *types.Score) {
	uri := formatFileURI(filePath)

	region := Region{
		StartLine:   match.Location.Source.Start.Line,
		StartColumn: match.Location.Source.Start.Column,
		EndLine:     match.Location.Source.End.Line,
		EndColumn:   match.Location.Source.End.Column,
	}
	if len(match.Snippet.Matching) > 0 {
		region.Snippet = Snippet{Text: string(match.Snippet.Matching)}
	}

	level := "warning"
	var props *ResultProperties
	if score != nil {
		level = LevelForScore(score.Final)
		props = &ResultProperties{
			SecuritySeverity: fmt.Sprintf("%.1f", float64(score.Final)/10.0),
			TitusScore:       score,
		}
	}

	result := Result{
		RuleID:  match.RuleID,
		Level:   level,
		Message: Message{Text: match.RuleName},
		Locations: []Location{{
			PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: uri},
				Region:           region,
			},
		}},
		Properties: props,
	}
	r.Runs[0].Results = append(r.Runs[0].Results, result)
}

// formatFileURI converts a file path to SARIF URI format
// Absolute paths get file:// prefix, relative paths stay as-is
func formatFileURI(path string) string {
	if filepath.IsAbs(path) {
		// Normalize path separators for URI format
		path = filepath.ToSlash(path)
		// Ensure path starts with /
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		return "file://" + path
	}
	// Relative paths stay as-is
	return filepath.ToSlash(path)
}
