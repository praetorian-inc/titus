package types

import (
	"encoding/json"
	"testing"
)

func TestSeverityForScore(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, "info"}, {10, "info"}, {19, "info"},
		{20, "low"}, {30, "low"}, {39, "low"},
		{40, "medium"}, {50, "medium"}, {59, "medium"},
		{60, "high"}, {70, "high"}, {79, "high"},
		{80, "critical"}, {90, "critical"}, {100, "critical"},
	}
	for _, c := range cases {
		if got := SeverityForScore(c.score); got != c.want {
			t.Errorf("SeverityForScore(%d) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestSeverityForScore_OutOfRange(t *testing.T) {
	if got := SeverityForScore(-5); got != "info" {
		t.Errorf("SeverityForScore(-5) = %q, want info (clamped)", got)
	}
	if got := SeverityForScore(150); got != "critical" {
		t.Errorf("SeverityForScore(150) = %q, want critical (clamped)", got)
	}
}

func TestScore_JSONSerialization(t *testing.T) {
	s := &Score{
		Final:             85,
		Base:              60,
		SuggestedSeverity: "critical",
		Applied: []ScoreModifier{
			{Name: "iam-admin", Scorer: "aws", Kind: "set_score", Value: 95, Priority: 50},
		},
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	got := string(data)
	want := `{"Final":85,"Base":60,"SuggestedSeverity":"critical","Applied":[{"Name":"iam-admin","Scorer":"aws","Kind":"set_score","Value":95,"Priority":50}]}`
	if got != want {
		t.Errorf("JSON mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestScore_EmptyAppliedSerializesAsEmptyArray(t *testing.T) {
	s := &Score{Final: 50, Base: 50, SuggestedSeverity: "medium", Applied: []ScoreModifier{}}
	data, _ := json.Marshal(s)
	got := string(data)
	// Must contain "Applied":[] not "Applied":null
	want := `"Applied":[]`
	if !containsSubstring(got, want) {
		t.Errorf("expected %q in output, got %s", want, got)
	}
}

func containsSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
