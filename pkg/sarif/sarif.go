package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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

	// Location fields, set by AddResultForOccurrence. Repository is
	// credential-free (repoid). HostRecorded is set for git locations only;
	// false marks a location read from a datastore that predates host
	// identity.
	Repository   string `json:"repository,omitempty"`
	Source       string `json:"source,omitempty"` // extended locations, e.g. "confluence"
	Commit       string `json:"commit,omitempty"`
	CommitDate   string `json:"commit_date,omitempty"` // RFC 3339
	AbsolutePath string `json:"absolute_path,omitempty"`
	WorkingTree  bool   `json:"working_tree,omitempty"`
	HostRecorded *bool  `json:"host_recorded,omitempty"`
}

// LocationFingerprintKey names the partialFingerprints entry that identifies
// a result's location, so per-location results are not deduplicated.
const LocationFingerprintKey = "titusLocation/v1"

// Result represents a single finding
type Result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"`
	Message   Message    `json:"message"`
	Locations []Location `json:"locations"`
	// PartialFingerprints is set by AddResultForOccurrence.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          *ResultProperties `json:"properties,omitempty"`
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
	r.Runs[0].Results = append(r.Runs[0].Results, newResult(match, filePath, nil))
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
	r.Runs[0].Results = append(r.Runs[0].Results, newResult(match, filePath, score))
}

// AddResultForOccurrence adds one result for one location of a match. Call it
// once per occurrence: N locations give N results (SARIF §3.27.12). The URI is
// the occurrence path (repository-relative for git); the repository, commit,
// commit date, absolute path and working-tree flag go in result.properties,
// and partialFingerprints carries a location hash so that consumers such as
// GitHub Code Scanning do not dedupe the locations away.
func (r *Report) AddResultForOccurrence(match *types.Match, o types.Occurrence, score *types.Score) {
	res := newResult(match, o.Path, score)
	if res.Properties == nil {
		res.Properties = &ResultProperties{}
	}
	res.Properties.Repository = o.Repository
	res.Properties.Source = o.Source
	res.Properties.Commit = o.Commit
	if !o.CommitDate.IsZero() {
		res.Properties.CommitDate = o.CommitDate.UTC().Format(time.RFC3339)
	}
	res.Properties.AbsolutePath = o.AbsolutePath
	res.Properties.WorkingTree = o.WorkingTree
	if o.Kind == "git" {
		res.Properties.HostRecorded = &o.HostRecorded
	}
	res.PartialFingerprints = map[string]string{LocationFingerprintKey: locationFingerprint(match, o)}
	r.Runs[0].Results = append(r.Runs[0].Results, res)
}

// newResult builds a single-location result. A nil score gives level
// "warning" and no properties.
func newResult(match *types.Match, filePath string, score *types.Score) Result {
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

	return Result{
		RuleID:  match.RuleID,
		Level:   level,
		Message: Message{Text: types.SanitizeDisplay(match.RuleName)},
		Locations: []Location{{
			PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: formatFileURI(filePath)},
				Region:           region,
			},
		}},
		Properties: props,
	}
}

// locationFingerprint hashes the rule, the matched span and every field that
// identifies the location. Fields are NUL-separated, so no two distinct
// locations share an input.
func locationFingerprint(match *types.Match, o types.Occurrence) string {
	src := match.Location.Source
	h := sha256.New()
	for _, f := range []string{
		match.RuleID, match.BlobID.Hex(),
		strconv.Itoa(src.Start.Line), strconv.Itoa(src.Start.Column),
		strconv.Itoa(src.End.Line), strconv.Itoa(src.End.Column),
		o.Kind, o.Source, o.Repository, o.Path, o.AbsolutePath, o.Commit,
		strconv.FormatBool(o.WorkingTree),
	} {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// formatFileURI converts a file path to an RFC 3986 URI reference. An absolute
// path becomes a file:// URI; a relative path stays a relative reference with
// each segment percent-encoded. Control bytes and invalid UTF-8 are
// percent-encoded, never dropped.
func formatFileURI(path string) string {
	if filepath.IsAbs(path) {
		path = filepath.ToSlash(path)
		if !strings.HasPrefix(path, "/") {
			path = "/" + path // Windows drive path: C:/x -> /C:/x
		}
		return (&url.URL{Scheme: "file", Path: path}).String()
	}
	if path == "*" {
		// net/url reserves the lone asterisk (the "OPTIONS *" request
		// target) and renders it unescaped; it is a valid path segment.
		return path
	}
	segments := strings.Split(filepath.ToSlash(path), "/")
	for i, seg := range segments {
		// PathEscape keeps ':', which would turn a first segment such as
		// "a:b" into a URI scheme.
		segments[i] = strings.ReplaceAll(url.PathEscape(seg), ":", "%3A")
	}
	return strings.Join(segments, "/")
}
