package explore

import (
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
)

func TestBuildFindingRow(t *testing.T) {
	rule := &types.Rule{
		ID:         "np.aws.1",
		Name:       "AWS API Key",
		Categories: []string{"cloud", "aws"},
	}
	rule.StructuralID = rule.ComputeStructuralID()

	ruleMap := map[string]*types.Rule{"np.aws.1": rule}

	finding := &types.Finding{
		ID:     "test-finding-id",
		RuleID: "np.aws.1",
		Groups: [][]byte{[]byte("AKIAIOSFODNN7EXAMPLE")},
	}

	matches := []*types.Match{
		{
			StructuralID: "match-1",
			RuleID:       "np.aws.1",
			RuleName:     "AWS API Key",
			Snippet:      types.Snippet{Matching: []byte("AKIAIOSFODNN7EXAMPLE")},
			ValidationResult: &types.ValidationResult{
				Status:     types.StatusValid,
				Confidence: 0.95,
				Message:    "Active credential",
			},
		},
		{
			StructuralID: "match-2",
			RuleID:       "np.aws.1",
			RuleName:     "AWS API Key",
			Snippet:      types.Snippet{Matching: []byte("AKIAIOSFODNN7EXAMPLE")},
			ValidationResult: &types.ValidationResult{
				Status:     types.StatusValid,
				Confidence: 0.90,
				Message:    "Active credential",
			},
		},
	}

	// Each match is on the zero blob, which has one location: MatchCount counts
	// locations, so two matches give 2.
	row := buildFindingRow(finding, matches, ruleMap, storeWithOneLocation(t, types.BlobID{}))

	if row.RuleName != "AWS API Key" {
		t.Errorf("expected rule name 'AWS API Key', got '%s'", row.RuleName)
	}
	if row.MatchCount != 2 {
		t.Errorf("expected 2 matches, got %d", row.MatchCount)
	}
	if row.ValidationStatus != "valid" {
		t.Errorf("expected validation 'valid', got '%s'", row.ValidationStatus)
	}
	if row.Confidence < 0.92 || row.Confidence > 0.93 {
		t.Errorf("expected mean confidence ~0.925, got %f", row.Confidence)
	}
	if len(row.Categories) != 2 {
		t.Errorf("expected 2 categories, got %d", len(row.Categories))
	}
	if len(row.Matches) != 2 {
		t.Errorf("expected 2 match rows, got %d", len(row.Matches))
	}
}

func TestBuildMatchRow(t *testing.T) {
	match := &types.Match{
		StructuralID: "match-1",
		BlobID:       types.BlobID{},
		RuleName:     "AWS API Key",
		Location: types.Location{
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 10, Column: 5},
				End:   types.SourcePoint{Line: 10, Column: 25},
			},
		},
		NamedGroups: map[string][]byte{
			"token": []byte("AKIAIOSFODNN7EXAMPLE"),
		},
		Snippet: types.Snippet{
			Before:   []byte("key = "),
			Matching: []byte("AKIAIOSFODNN7EXAMPLE"),
			After:    []byte("\n"),
		},
		ValidationResult: &types.ValidationResult{
			Status:     types.StatusValid,
			Confidence: 0.95,
			Message:    "Active credential",
		},
	}

	row := buildMatchRow(match, nil)

	if row.ValidationStatus != "valid" {
		t.Errorf("expected validation 'valid', got '%s'", row.ValidationStatus)
	}
	if row.Confidence != 0.95 {
		t.Errorf("expected confidence 0.95, got %f", row.Confidence)
	}
	if row.Message != "Active credential" {
		t.Errorf("expected message 'Active credential', got '%s'", row.Message)
	}
	if len(row.NamedGroups) != 1 {
		t.Errorf("expected 1 named group, got %d", len(row.NamedGroups))
	}
	if string(row.NamedGroups["token"]) != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("expected token group value 'AKIAIOSFODNN7EXAMPLE'")
	}
}

func TestFormatGroups(t *testing.T) {
	tests := []struct {
		groups   [][]byte
		expected string
	}{
		{nil, ""},
		{[][]byte{[]byte("val1")}, "val1"},
		{[][]byte{[]byte("val1"), []byte("val2")}, "val1, val2"},
	}

	for _, tt := range tests {
		result := formatGroups(tt.groups)
		if result != tt.expected {
			t.Errorf("formatGroups(%v) = %q, want %q", tt.groups, result, tt.expected)
		}
	}
}

func TestRenderValidationStatus(t *testing.T) {
	// Just ensure these don't panic
	renderValidationStatus("valid")
	renderValidationStatus("invalid")
	renderValidationStatus("undetermined")
	renderValidationStatus("")
}

func TestRenderAnnotationStatus(t *testing.T) {
	// Just ensure these don't panic
	renderAnnotationStatus("accept")
	renderAnnotationStatus("reject")
	renderAnnotationStatus("")
}

// TestGroupMatchesByFinding_CustomRule verifies that matches for custom
// rules (not present in ruleMap) are still grouped onto their findings via
// the RuleID + Groups fallback. Regression test for the bug where the
// explore TUI rendered "No matches" for custom-rule findings.
func TestGroupMatchesByFinding_CustomRule(t *testing.T) {
	// Custom rule: deliberately NOT inserted into ruleMap, mimicking a
	// rule loaded via --rules at scan time.
	finding := &types.Finding{
		ID:     "finding-custom-1",
		RuleID: "ps.cred.1",
		Groups: [][]byte{[]byte("supersecret")},
	}

	matches := []*types.Match{
		{
			StructuralID: "match-a",
			RuleID:       "ps.cred.1",
			RuleName:     "PowerShell Hardcoded Credential",
			Groups:       [][]byte{[]byte("supersecret")},
		},
		{
			StructuralID: "match-b",
			RuleID:       "ps.cred.1",
			RuleName:     "PowerShell Hardcoded Credential",
			Groups:       [][]byte{[]byte("supersecret")},
		},
		{
			// Different groups — must not be paired with the finding.
			StructuralID: "match-c",
			RuleID:       "ps.cred.1",
			RuleName:     "PowerShell Hardcoded Credential",
			Groups:       [][]byte{[]byte("other")},
		},
	}

	ruleMap := map[string]*types.Rule{} // empty: custom rule not in builtins

	got := groupMatchesByFinding([]*types.Finding{finding}, matches, ruleMap)

	paired := got[finding.ID]
	if len(paired) != 2 {
		t.Fatalf("expected 2 matches paired with custom-rule finding, got %d", len(paired))
	}
	if paired[0].StructuralID != "match-a" || paired[1].StructuralID != "match-b" {
		t.Errorf("unexpected matches paired: %+v", paired)
	}

	// Sanity: buildFindingRow surfaces the friendly name from m.RuleName
	// when the rule is missing from ruleMap.
	row := buildFindingRow(finding, paired, ruleMap, storeWithOneLocation(t, types.BlobID{}))
	if row.RuleName != "PowerShell Hardcoded Credential" {
		t.Errorf("expected RuleName fallback to match-record RuleName, got %q", row.RuleName)
	}
	if row.MatchCount != 2 {
		t.Errorf("expected MatchCount=2, got %d", row.MatchCount)
	}
}

// TestGroupMatchesByFinding_BuiltinFastPath verifies that builtin rules
// (present in ruleMap) continue to flow through the structural-ID fast
// path and are grouped correctly.
func TestGroupMatchesByFinding_BuiltinFastPath(t *testing.T) {
	r := &types.Rule{
		ID:   "np.aws.1",
		Name: "AWS API Key",
	}
	r.StructuralID = r.ComputeStructuralID()
	ruleMap := map[string]*types.Rule{r.ID: r}

	groups := [][]byte{[]byte("AKIAIOSFODNN7EXAMPLE")}
	findingID := types.ComputeFindingID(r.StructuralID, groups)

	finding := &types.Finding{
		ID:     findingID,
		RuleID: r.ID,
		Groups: groups,
	}

	matches := []*types.Match{
		{StructuralID: "m1", RuleID: r.ID, RuleName: r.Name, Groups: groups},
		{StructuralID: "m2", RuleID: r.ID, RuleName: r.Name, Groups: groups},
	}

	got := groupMatchesByFinding([]*types.Finding{finding}, matches, ruleMap)
	if len(got[finding.ID]) != 2 {
		t.Fatalf("expected 2 matches via fast path, got %d", len(got[finding.ID]))
	}
}

// TestGroupMatchesByFinding_SameCustomRuleDifferentGroups verifies that when two
// findings share the same custom RuleID but have distinct captured groups, each
// finding is paired only with its own matches — not the other finding's matches.
func TestGroupMatchesByFinding_SameCustomRuleDifferentGroups(t *testing.T) {
	findingA := &types.Finding{
		ID:     "finding-a",
		RuleID: "custom.token.1",
		Groups: [][]byte{[]byte("secret-a")},
	}
	findingB := &types.Finding{
		ID:     "finding-b",
		RuleID: "custom.token.1",
		Groups: [][]byte{[]byte("secret-b")},
	}

	matches := []*types.Match{
		{StructuralID: "m-a1", RuleID: "custom.token.1", RuleName: "Custom Token", Groups: [][]byte{[]byte("secret-a")}},
		{StructuralID: "m-a2", RuleID: "custom.token.1", RuleName: "Custom Token", Groups: [][]byte{[]byte("secret-a")}},
		{StructuralID: "m-b1", RuleID: "custom.token.1", RuleName: "Custom Token", Groups: [][]byte{[]byte("secret-b")}},
	}

	ruleMap := map[string]*types.Rule{} // custom rule not in builtins

	got := groupMatchesByFinding([]*types.Finding{findingA, findingB}, matches, ruleMap)

	pairedA := got[findingA.ID]
	pairedB := got[findingB.ID]

	if len(pairedA) != 2 {
		t.Errorf("findingA: expected 2 matches, got %d", len(pairedA))
	}
	if len(pairedB) != 1 {
		t.Errorf("findingB: expected 1 match, got %d", len(pairedB))
	}
	// findingA must not contain findingB's match
	for _, m := range pairedA {
		if m.StructuralID == "m-b1" {
			t.Error("findingA incorrectly contains findingB's match")
		}
	}
}

// TestGroupMatchesByFinding_OrphanedCustomFinding verifies that a custom-rule
// finding with no corresponding matches returns an empty (not nil) slice and
// does not panic. This covers the case where matches were deleted or an
// incomplete scan produced findings without associated matches.
func TestGroupMatchesByFinding_OrphanedCustomFinding(t *testing.T) {
	finding := &types.Finding{
		ID:     "orphaned-finding",
		RuleID: "custom.orphan.1",
		Groups: [][]byte{[]byte("some-value")},
	}
	// No match has the same RuleID — orphaned finding
	matches := []*types.Match{
		{StructuralID: "m1", RuleID: "other.rule.1", RuleName: "Other Rule", Groups: [][]byte{[]byte("some-value")}},
	}
	ruleMap := map[string]*types.Rule{}

	got := groupMatchesByFinding([]*types.Finding{finding}, matches, ruleMap)

	paired := got[finding.ID]
	if len(paired) != 0 {
		t.Errorf("orphaned finding should have 0 matches, got %d", len(paired))
	}
}

// TestBuildFindingRow_CustomRule_NoMatches verifies that buildFindingRow does
// not panic when given a custom rule finding with no matches, and that it falls
// back to the RuleID as the RuleName.
func TestBuildFindingRow_CustomRule_NoMatches(t *testing.T) {
	finding := &types.Finding{
		ID:     "custom-finding-no-matches",
		RuleID: "custom.nodata.1",
		Groups: [][]byte{[]byte("value")},
	}
	ruleMap := map[string]*types.Rule{} // custom rule absent

	// Must not panic; rule name should fall back to RuleID
	row := buildFindingRow(finding, nil, ruleMap, nil)

	if row == nil {
		t.Fatal("buildFindingRow returned nil")
	}
	if row.RuleName != "custom.nodata.1" {
		t.Errorf("expected RuleName fallback to RuleID, got %q", row.RuleName)
	}
	if row.MatchCount != 0 {
		t.Errorf("expected MatchCount 0, got %d", row.MatchCount)
	}
	if len(row.Matches) != 0 {
		t.Errorf("expected 0 match rows, got %d", len(row.Matches))
	}
}

// TestBuildFindingRow_CustomRule_EmptyMatchRuleName verifies that when a match
// record carries an empty RuleName (possible in older datastores), the finding
// row's RuleName falls back to the RuleID rather than returning an empty string.
func TestBuildFindingRow_CustomRule_EmptyMatchRuleName(t *testing.T) {
	finding := &types.Finding{
		ID:     "finding-empty-rulename",
		RuleID: "custom.norulename.1",
		Groups: [][]byte{[]byte("token")},
	}
	matches := []*types.Match{
		{
			StructuralID: "m1",
			RuleID:       "custom.norulename.1",
			RuleName:     "", // empty — older datastore or bug
			Groups:       [][]byte{[]byte("token")},
		},
	}
	ruleMap := map[string]*types.Rule{}

	row := buildFindingRow(finding, matches, ruleMap, storeWithOneLocation(t, types.BlobID{}))

	// Rule name must never be empty — should fall back to RuleID at minimum
	if row.RuleName == "" {
		t.Error("RuleName should never be empty; expected fallback to RuleID")
	}
	if row.MatchCount != 1 {
		t.Errorf("expected MatchCount 1, got %d", row.MatchCount)
	}
}

// TestLoadData_CustomRuleFindingHasMatches is the regression test for PR #232.
// It creates a real SQLite datastore with a custom-rule finding and verifies
// that loadData (the explore TUI entry point) correctly pairs the finding with
// its match. Before the fix, custom-rule findings appeared as "No matches" in
// the TUI because groupMatchesByFinding only used the builtin-rule fast path.
func TestLoadData_CustomRuleFindingHasMatches(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "datastore.db")

	s, err := store.New(store.Config{Path: dbPath})
	if err != nil {
		t.Fatalf("creating store: %v", err)
	}

	// Custom rule — NOT a builtin; won't be in explore's ruleMap
	customRule := &types.Rule{
		ID:        "acme.api.1",
		Name:      "ACME API Token",
		BaseScore: 70,
	}
	customRule.StructuralID = customRule.ComputeStructuralID()

	if err := s.AddRule(customRule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	groups := [][]byte{[]byte("ABCDEFGHIJKLMNOP1234567890ABCDEF")}

	blobID := types.BlobID{}
	if err := s.AddBlob(blobID, 100); err != nil {
		t.Fatalf("AddBlob: %v", err)
	}

	match := &types.Match{
		BlobID:       blobID,
		StructuralID: "match-structural-id",
		RuleID:       customRule.ID,
		RuleName:     customRule.Name,
		Groups:       groups,
	}
	if err := s.AddMatch(match); err != nil {
		t.Fatalf("AddMatch: %v", err)
	}
	if err := s.AddProvenance(blobID, types.FileProvenance{FilePath: "config.env"}); err != nil {
		t.Fatalf("AddProvenance: %v", err)
	}

	findingID := types.ComputeFindingID(customRule.StructuralID, groups)
	finding := &types.Finding{
		ID:     findingID,
		RuleID: customRule.ID,
		Groups: groups,
	}
	if err := s.AddFinding(finding); err != nil {
		t.Fatalf("AddFinding: %v", err)
	}
	_ = s.Close()

	// Load via explore's loadData — this is the actual bug regression path
	data, err := loadData(dbPath)
	if err != nil {
		t.Fatalf("loadData: %v", err)
	}
	defer data.store.Close()

	if len(data.findings) != 1 {
		t.Fatalf("expected 1 finding row, got %d", len(data.findings))
	}

	row := data.findings[0]

	// The fix (PR #232): custom rule finding must have its match populated
	if row.MatchCount != 1 {
		t.Errorf("expected MatchCount 1 (regression: was 0 before fix), got %d", row.MatchCount)
	}
	if len(row.Matches) != 1 {
		t.Errorf("expected 1 match row, got %d", len(row.Matches))
	}
	// Rule name must come from match record (not ruleMap, since custom)
	if row.RuleName != "ACME API Token" {
		t.Errorf("expected RuleName 'ACME API Token' from match record, got %q", row.RuleName)
	}
	if row.RuleID != "acme.api.1" {
		t.Errorf("expected RuleID 'acme.api.1', got %q", row.RuleID)
	}
}

// storeWithOneLocation returns a memory store in which blobID has exactly one
// location, a plain file. Fixtures that count locations use it so that each
// match on blobID contributes one location.
func storeWithOneLocation(t *testing.T, blobID types.BlobID) *store.MemoryStore {
	t.Helper()
	s := store.NewMemory()
	if err := s.AddProvenance(blobID, types.FileProvenance{FilePath: "config.env"}); err != nil {
		t.Fatalf("AddProvenance: %v", err)
	}
	return s
}

// occurrenceFixture returns a memory store holding one blob with three
// locations (github.com/acme/api twice, github.com/acme/web once), and a match
// on that blob. It is the C-EXPLORE-1 input.
func occurrenceFixture(t *testing.T) (*store.MemoryStore, *types.Match) {
	t.Helper()
	s := store.NewMemory()
	blobID := types.ComputeBlobID([]byte("AKIAIOSFODNN7EXAMPLE"))
	date := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	occs := []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/web", Path: ".env", Commit: "3333333cccccccc", CommitDate: date},
		{Kind: "git", Repository: "github.com/acme/api", Path: "config/b.env", Commit: "2222222bbbbbbbb", CommitDate: date},
		{Kind: "git", Repository: "github.com/acme/api", Path: "config/a.env", Commit: "1111111aaaaaaaa", CommitDate: date},
	}
	if err := s.AddOccurrences(blobID, occs); err != nil {
		t.Fatalf("AddOccurrences: %v", err)
	}
	m := &types.Match{StructuralID: "m1", BlobID: blobID, RuleID: "np.aws.1", RuleName: "AWS API Key"}
	return s, m
}

func TestBuildMatchRow_OccurrencesFromStore(t *testing.T) {
	s, m := occurrenceFixture(t)

	mr := buildMatchRow(m, s)

	want, err := s.GetOccurrences(m.BlobID)
	if err != nil {
		t.Fatalf("GetOccurrences: %v", err)
	}
	if len(want) != 3 {
		t.Fatalf("fixture: expected 3 occurrences, got %d", len(want))
	}
	if !reflect.DeepEqual(mr.Occurrences, want) {
		t.Errorf("matchRow.Occurrences = %+v, want %+v", mr.Occurrences, want)
	}
}

// failingOccurrenceStore fails GetOccurrences and delegates everything else.
type failingOccurrenceStore struct{ *store.MemoryStore }

func (failingOccurrenceStore) GetOccurrences(types.BlobID) ([]types.Occurrence, error) {
	return nil, errors.New("occurrences unavailable")
}

func TestBuildMatchRow_OccurrencesErrorLeavesRowUsable(t *testing.T) {
	blobID := types.ComputeBlobID([]byte("x"))
	s := failingOccurrenceStore{storeWithOneLocation(t, blobID)}

	mr := buildMatchRow(&types.Match{StructuralID: "m1", BlobID: blobID}, s)

	if mr.Occurrences != nil {
		t.Errorf("expected no occurrences on error, got %+v", mr.Occurrences)
	}
	if len(mr.Provenance) != 1 {
		t.Errorf("expected provenance to load despite the occurrence error, got %d rows", len(mr.Provenance))
	}
}

func TestBuildFindingRow_RepositoriesAndLocationCount(t *testing.T) {
	s, m := occurrenceFixture(t)
	finding := &types.Finding{ID: "f1", RuleID: m.RuleID}

	row := buildFindingRow(finding, []*types.Match{m}, map[string]*types.Rule{}, s)

	wantRepos := []string{"github.com/acme/api", "github.com/acme/web"}
	if !slices.Equal(row.Repositories, wantRepos) {
		t.Errorf("Repositories = %q, want %q", row.Repositories, wantRepos)
	}
	if row.MatchCount != 3 {
		t.Errorf("MatchCount (total locations) = %d, want 3", row.MatchCount)
	}
}

func TestBuildFindingRow_LocationCountSumsAcrossMatches(t *testing.T) {
	s, m := occurrenceFixture(t)
	other := types.ComputeBlobID([]byte("other"))
	if err := s.AddProvenance(other, types.FileProvenance{FilePath: "notes.txt"}); err != nil {
		t.Fatalf("AddProvenance: %v", err)
	}
	m2 := &types.Match{StructuralID: "m2", BlobID: other, RuleID: m.RuleID}

	row := buildFindingRow(&types.Finding{ID: "f1", RuleID: m.RuleID}, []*types.Match{m, m2}, map[string]*types.Rule{}, s)

	if row.MatchCount != 4 {
		t.Errorf("MatchCount = %d, want 4 (3 + 1 locations)", row.MatchCount)
	}
	if len(row.Matches) != 2 {
		t.Errorf("expected 2 match rows, got %d", len(row.Matches))
	}
}

// TestBuildFindingRow_FileAddsNoFacetValue_ExtendedSourceDoes verifies that a
// plain file contributes a location but no facet value, while an extended
// location contributes its source ("s3://bucket") as a facet value.
func TestBuildFindingRow_FileAddsNoFacetValue_ExtendedSourceDoes(t *testing.T) {
	s, m := occurrenceFixture(t)
	if err := s.AddProvenance(m.BlobID, types.FileProvenance{FilePath: "dump/creds.txt"}); err != nil {
		t.Fatalf("AddProvenance file: %v", err)
	}
	ext := types.ExtendedProvenance{Payload: map[string]interface{}{"source": "s3://bucket", "path": "k/creds"}}
	if err := s.AddProvenance(m.BlobID, ext); err != nil {
		t.Fatalf("AddProvenance extended: %v", err)
	}

	row := buildFindingRow(&types.Finding{ID: "f1", RuleID: m.RuleID}, []*types.Match{m}, map[string]*types.Rule{}, s)

	wantRepos := []string{"github.com/acme/api", "github.com/acme/web", "s3://bucket"}
	if !slices.Equal(row.Repositories, wantRepos) {
		t.Errorf("Repositories = %q, want %q", row.Repositories, wantRepos)
	}
	if row.MatchCount != 5 {
		t.Errorf("MatchCount = %d, want 5", row.MatchCount)
	}
}

// TestBuildFindingRow_LegacyRowIsOwnFacetValue verifies spec R5: a legacy git
// row (HostRecorded=false) keeps its stored repository string, so it is a
// facet value of its own beside the host-qualified form.
func TestBuildFindingRow_LegacyRowIsOwnFacetValue(t *testing.T) {
	s := store.NewMemory()
	blobID := types.ComputeBlobID([]byte("legacy"))
	if err := s.AddOccurrences(blobID, []types.Occurrence{
		{Kind: "git", Repository: "github.com/acme/api", Path: "a.env", Commit: "1111111aaaaaaaa"},
	}); err != nil {
		t.Fatalf("AddOccurrences: %v", err)
	}
	if err := s.AddProvenance(blobID, types.GitProvenance{RepoPath: "acme/api", BlobPath: "old.env"}); err != nil {
		t.Fatalf("AddProvenance: %v", err)
	}
	m := &types.Match{StructuralID: "m1", BlobID: blobID, RuleID: "r"}

	row := buildFindingRow(&types.Finding{ID: "f1", RuleID: "r"}, []*types.Match{m}, map[string]*types.Rule{}, s)

	legacy := slices.IndexFunc(row.Matches[0].Occurrences, func(o types.Occurrence) bool { return !o.HostRecorded })
	if legacy < 0 || row.Matches[0].Occurrences[legacy].Repository != "acme/api" {
		t.Fatalf("fixture: expected a legacy occurrence for acme/api, got %+v", row.Matches[0].Occurrences)
	}
	wantRepos := []string{"acme/api", "github.com/acme/api"}
	if !slices.Equal(row.Repositories, wantRepos) {
		t.Errorf("Repositories = %q, want %q", row.Repositories, wantRepos)
	}

	fs := buildFacets([]*findingRow{row})
	var values []string
	for _, v := range fs.Values[facetRepository] {
		values = append(values, v.Value)
	}
	if !slices.Equal(values, wantRepos) {
		t.Errorf("repository facet values = %q, want %q", values, wantRepos)
	}
}
