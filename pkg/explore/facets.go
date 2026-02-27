package explore

import (
	"sort"

	"github.com/praetorian-inc/titus/pkg/types"
)

// facetID identifies a facet category.
type facetID int

const (
	facetRuleName facetID = iota
	facetCategory
	facetValidation
)

// facetDef defines a facet category.
type facetDef struct {
	ID    facetID
	Label string
}

var facetDefs = []facetDef{
	{facetRuleName, "Rule Name"},
	{facetCategory, "Category"},
	{facetValidation, "Validation"},
}

// facetValue is a single selectable value within a facet.
type facetValue struct {
	FacetID  facetID
	Value    string
	Count    int
	Selected bool
}

// facetState holds the complete filter state.
type facetState struct {
	Values map[facetID][]*facetValue
}

func newFacetState() *facetState {
	return &facetState{
		Values: make(map[facetID][]*facetValue),
	}
}

// buildFacets builds facet values from findings data.
// Each finding has a rule (with name and categories) and matches (with validation results).
func buildFacets(findings []*findingRow) *facetState {
	fs := newFacetState()

	ruleNames := make(map[string]int)
	categories := make(map[string]int)
	validations := make(map[string]int)

	for _, f := range findings {
		ruleNames[f.RuleName]++

		for _, cat := range f.Categories {
			categories[cat]++
		}

		if f.ValidationStatus != "" {
			validations[f.ValidationStatus]++
		} else {
			validations["-"]++
		}
	}

	fs.Values[facetRuleName] = mapToFacetValues(facetRuleName, ruleNames)
	fs.Values[facetCategory] = mapToFacetValues(facetCategory, categories)
	fs.Values[facetValidation] = mapToFacetValues(facetValidation, validations)

	return fs
}

func mapToFacetValues(id facetID, counts map[string]int) []*facetValue {
	values := make([]*facetValue, 0, len(counts))
	for v, c := range counts {
		values = append(values, &facetValue{FacetID: id, Value: v, Count: c})
	}
	sort.Slice(values, func(i, j int) bool {
		return values[i].Value < values[j].Value
	})
	return values
}

// selectedValues returns the set of selected values for a facet.
func (fs *facetState) selectedValues(id facetID) map[string]bool {
	selected := make(map[string]bool)
	for _, v := range fs.Values[id] {
		if v.Selected {
			selected[v.Value] = true
		}
	}
	return selected
}

// hasActiveFilters returns true if any facet has selections.
func (fs *facetState) hasActiveFilters() bool {
	for _, values := range fs.Values {
		for _, v := range values {
			if v.Selected {
				return true
			}
		}
	}
	return false
}

// resetAll deselects all facet values.
func (fs *facetState) resetAll() {
	for _, values := range fs.Values {
		for _, v := range values {
			v.Selected = false
		}
	}
}

// matchesFinding returns true if a finding passes all active filters.
// Within a facet: OR (union). Across facets: AND (intersection).
func (fs *facetState) matchesFinding(f *findingRow) bool {
	for _, def := range facetDefs {
		selected := fs.selectedValues(def.ID)
		if len(selected) == 0 {
			continue // no filter active for this facet
		}

		switch def.ID {
		case facetRuleName:
			if !selected[f.RuleName] {
				return false
			}
		case facetCategory:
			found := false
			for _, cat := range f.Categories {
				if selected[cat] {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		case facetValidation:
			status := f.ValidationStatus
			if status == "" {
				status = "-"
			}
			if !selected[status] {
				return false
			}
		}
	}
	return true
}

// updateCounts recounts facet values based on currently visible findings.
func (fs *facetState) updateCounts(findings []*findingRow) {
	// Reset counts
	for _, values := range fs.Values {
		for _, v := range values {
			v.Count = 0
		}
	}

	for _, f := range findings {
		if !fs.matchesFinding(f) {
			continue
		}
		// Increment counts for this finding's facet values
		for _, v := range fs.Values[facetRuleName] {
			if v.Value == f.RuleName {
				v.Count++
			}
		}
		for _, v := range fs.Values[facetCategory] {
			for _, cat := range f.Categories {
				if v.Value == cat {
					v.Count++
					break
				}
			}
		}
		valStatus := f.ValidationStatus
		if valStatus == "" {
			valStatus = "-"
		}
		for _, v := range fs.Values[facetValidation] {
			if v.Value == valStatus {
				v.Count++
			}
		}
	}
}

// findingRow is the denormalized view model for a finding in the TUI.
// Built from types.Finding + types.Match data.
type findingRow struct {
	FindingID        string
	RuleID           string
	RuleName         string
	Categories       []string
	Groups           [][]byte
	MatchCount       int
	ValidationStatus string  // aggregated: "valid", "invalid", "undetermined", or ""
	Confidence       float64 // mean confidence across matches
	AnnotationStatus string  // "accept", "reject", or ""
	Comment          string
	Matches          []*matchRow
}

// matchRow is the denormalized view model for a match.
type matchRow struct {
	StructuralID     string
	BlobID           types.BlobID
	RuleName         string
	Location         types.Location
	Groups           [][]byte
	NamedGroups      map[string][]byte
	Snippet          types.Snippet
	ValidationStatus string
	Confidence       float64
	Message          string
	Provenance       []types.Provenance
	AnnotationStatus string
	Comment          string
}
