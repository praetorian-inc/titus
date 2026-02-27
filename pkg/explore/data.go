package explore

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
)

// exploreData holds all loaded data for the TUI.
type exploreData struct {
	store    store.Store
	ruleMap  map[string]*types.Rule
	findings []*findingRow
}

// loadData opens a datastore and loads all findings, matches, provenance, and annotations.
// The storePath can be a directory (datastore format) or a direct .db file path.
// This follows the same pattern as cmd/titus/report.go:runReport.
func loadData(storePath string) (*exploreData, error) {
	// Resolve path: if directory, append datastore.db
	info, err := os.Stat(storePath)
	if err != nil {
		return nil, fmt.Errorf("datastore not found: %s", storePath)
	}
	if info.IsDir() {
		storePath = filepath.Join(storePath, "datastore.db")
	}

	// Open store (same as report.go:100-105)
	s, err := store.New(store.Config{Path: storePath})
	if err != nil {
		return nil, fmt.Errorf("opening datastore: %w", err)
	}

	// Load rules for name/category lookup
	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("loading rules: %w", err)
	}
	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	// Load findings (same as report.go:109-111)
	findings, err := s.GetFindings()
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("retrieving findings: %w", err)
	}

	// Load all matches (same as report.go:114-116)
	matches, err := s.GetAllMatches()
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("retrieving matches: %w", err)
	}

	// Group matches by finding ID (same as report.go:buildFindingMatchMap)
	matchesByFinding := make(map[string][]*types.Match)
	for _, m := range matches {
		r, ok := ruleMap[m.RuleID]
		if ok {
			findingID := types.ComputeFindingID(r.StructuralID, m.Groups)
			matchesByFinding[findingID] = append(matchesByFinding[findingID], m)
		}
	}

	// Build view models
	rows := make([]*findingRow, 0, len(findings))
	for _, f := range findings {
		fMatches := matchesByFinding[f.ID]
		row := buildFindingRow(f, fMatches, ruleMap, s)
		rows = append(rows, row)
	}

	return &exploreData{
		store:    s,
		ruleMap:  ruleMap,
		findings: rows,
	}, nil
}

// buildFindingRow creates a findingRow from a Finding and its matches.
func buildFindingRow(f *types.Finding, matches []*types.Match, ruleMap map[string]*types.Rule, s store.Store) *findingRow {
	row := &findingRow{
		FindingID:  f.ID,
		RuleID:     f.RuleID,
		RuleName:   f.RuleID, // fallback
		Groups:     f.Groups,
		MatchCount: len(matches),
	}

	// Populate rule metadata
	if r, ok := ruleMap[f.RuleID]; ok {
		row.RuleName = r.Name
		row.Categories = r.Categories
	}

	// Aggregate validation status from matches
	var totalConf float64
	var confCount int
	statusCounts := make(map[string]int)
	for _, m := range matches {
		if m.ValidationResult != nil {
			statusCounts[string(m.ValidationResult.Status)]++
			totalConf += m.ValidationResult.Confidence
			confCount++
		}
	}
	if confCount > 0 {
		row.Confidence = totalConf / float64(confCount)
	}
	// Pick dominant validation status
	if len(statusCounts) == 1 {
		for status := range statusCounts {
			row.ValidationStatus = status
		}
	} else if statusCounts["valid"] > 0 {
		row.ValidationStatus = "valid"
	} else if statusCounts["invalid"] > 0 {
		row.ValidationStatus = "invalid"
	} else if statusCounts["undetermined"] > 0 {
		row.ValidationStatus = "undetermined"
	}

	// Load annotation for this finding
	if s != nil {
		status, comment, err := s.GetAnnotation("finding", f.ID)
		if err == nil {
			row.AnnotationStatus = status
			row.Comment = comment
		}
	}

	// Build match rows
	row.Matches = make([]*matchRow, 0, len(matches))
	for _, m := range matches {
		mr := buildMatchRow(m, s)
		row.Matches = append(row.Matches, mr)
	}

	return row
}

// buildMatchRow creates a matchRow from a Match.
func buildMatchRow(m *types.Match, s store.Store) *matchRow {
	mr := &matchRow{
		StructuralID: m.StructuralID,
		BlobID:       m.BlobID,
		RuleName:     m.RuleName,
		Location:     m.Location,
		Groups:       m.Groups,
		NamedGroups:  m.NamedGroups,
		Snippet:      m.Snippet,
	}

	if m.ValidationResult != nil {
		mr.ValidationStatus = string(m.ValidationResult.Status)
		mr.Confidence = m.ValidationResult.Confidence
		mr.Message = m.ValidationResult.Message
	}

	// Load provenance
	if s != nil {
		provs, err := s.GetAllProvenance(m.BlobID)
		if err == nil {
			mr.Provenance = provs
		}

		// Load match annotation
		status, comment, err := s.GetAnnotation("match", m.StructuralID)
		if err == nil {
			mr.AnnotationStatus = status
			mr.Comment = comment
		}
	}

	return mr
}

// close closes the underlying store.
func (d *exploreData) close() error {
	if d.store != nil {
		return d.store.Close()
	}
	return nil
}

// setFindingAnnotation persists a finding annotation and updates the view model.
func (d *exploreData) setFindingAnnotation(findingID, status, comment string) error {
	return d.store.SetAnnotation("finding", findingID, status, comment)
}

// setMatchAnnotation persists a match annotation and updates the view model.
func (d *exploreData) setMatchAnnotation(matchID, status, comment string) error {
	return d.store.SetAnnotation("match", matchID, status, comment)
}
