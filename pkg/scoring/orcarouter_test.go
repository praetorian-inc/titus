package scoring

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A clearly synthetic key. Never a real credential.
const orcaTestKey = "sk-orca-TEST-ONLY-000011112222333344445555"

// orcaMixedCatalog mirrors the real GET /v1/models envelope and mixes every
// capability class the filter has to distinguish: text chat, image-input
// chat, embedding, image generation, video, rerank, and one entry that
// declares no endpoint types at all (must fail closed).
const orcaMixedCatalog = `{"data":[
 {"id":"orcarouter/auto","supported_endpoint_types":["openai"],"architecture":{"input_modalities":["text"],"output_modalities":["text"]}},
 {"id":"anthropic/claude-opus-4.8","supported_endpoint_types":["anthropic"],"architecture":{"input_modalities":["text"],"output_modalities":["text"]}},
 {"id":"google/gemini-3.5-flash","supported_endpoint_types":["gemini"],"architecture":{"input_modalities":["text","image"],"output_modalities":["text"]}},
 {"id":"deepseek/deepseek-v4-pro","supported_endpoint_types":["openai"],"architecture":{"input_modalities":["text"],"output_modalities":["text"]}},
 {"id":"openai/gpt-5.5","supported_endpoint_types":["openai-response"],"architecture":{"input_modalities":["text"],"output_modalities":["text"]}},
 {"id":"openai/text-embedding-3-large","supported_endpoint_types":["openai-embedding"]},
 {"id":"openai/gpt-image-1","supported_endpoint_types":["image-generation"]},
 {"id":"openai/sora-2","supported_endpoint_types":["openai-video"]},
 {"id":"jina/jina-rerank-v3","supported_endpoint_types":["jina-rerank"]},
 {"id":"legacy/undeclared-model"}
]}`

// orcaBroadCatalog declares enough chat-capable models to cross the
// broad-access threshold.
func orcaBroadCatalog() string {
	var entries []string
	for i := 0; i < 12; i++ {
		entries = append(entries, fmt.Sprintf(
			`{"id":"vendor/model-%d","supported_endpoint_types":["openai"],"architecture":{"input_modalities":["text"]}}`, i))
	}
	return `{"data":[` + strings.Join(entries, ",") + `]}`
}

// orcaCyberCatalog declares an OrcaCyber-tier model next to a general one.
const orcaCyberCatalog = `{"data":[
 {"id":"orcacyber-ultra-1.0","supported_endpoint_types":["openai"],"architecture":{"input_modalities":["text"]}},
 {"id":"orcacyber-zero-1.5","supported_endpoint_types":["openai"],"architecture":{"input_modalities":["text"]}},
 {"id":"orcarouter/auto","supported_endpoint_types":["openai"],"architecture":{"input_modalities":["text"]}}
]}`

func orcaTestMatch(key string) *types.Match {
	return &types.Match{
		RuleID:      orcaRouterRuleID,
		Groups:      [][]byte{[]byte(key)},
		NamedGroups: map[string][]byte{"key": []byte(key)},
	}
}

// orcaTestServer serves a fixed status/body and records the request it saw.
type orcaTestServer struct {
	*httptest.Server
	requests atomic.Int64
	lastPath string
	lastAuth string
	lastVerb string
}

func newOrcaTestServer(t *testing.T, status int, body string) *orcaTestServer {
	t.Helper()
	ts := &orcaTestServer{}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.requests.Add(1)
		ts.lastPath = r.URL.Path
		ts.lastAuth = r.Header.Get("Authorization")
		ts.lastVerb = r.Method
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	return ts
}

func (ts *orcaTestServer) condition(mode orcaRouterProbeMode) *orcaRouterCatalogCondition {
	return &orcaRouterCatalogCondition{
		mode:   mode,
		client: ts.Client(),
		url:    ts.URL + "/v1/models",
		cache:  newOrcaRouterProbeCache(),
	}
}

// --- provider registration -------------------------------------------------

func TestOrcaRouterScorer_RegisteredAsBuiltin(t *testing.T) {
	var found *Scorer
	for _, s := range BuiltinGoScorers() {
		if s.canScore(orcaRouterRuleID) {
			found = s
			break
		}
	}
	require.NotNil(t, found, "no built-in scorer targets %s", orcaRouterRuleID)
	assert.Equal(t, "orcarouter-key-scope", found.Name)

	names := make([]string, 0, len(found.Modifiers))
	for _, m := range found.Modifiers {
		names = append(names, m.Name)
		assert.Truef(t, m.IsDynamic(), "modifier %q must be dynamic (--score-scope gated)", m.Name)
	}
	assert.Equal(t, []string{
		"cyber-model-access", "broad-model-access", "limited-model-access", "revoked-key",
	}, names)
}

func TestOrcaRouterScorer_UsesProviderInferenceOrigin(t *testing.T) {
	// Discovery and inference share the api.orcarouter.ai origin. The
	// authentication/consent site (www.orcarouter.ai) is a different host and
	// must never be the target of a scoring request.
	assert.Equal(t, "https://api.orcarouter.ai/v1/models", orcaRouterModelsURL)
	assert.NotContains(t, orcaRouterModelsURL, "www.orcarouter.ai")
}

func TestOrcaRouterScorer_RevokedKeyIsLowestPriority(t *testing.T) {
	s := newOrcaRouterScorer(nil, "")
	prio := make(map[string]int, len(s.Modifiers))
	for _, m := range s.Modifiers {
		prio[m.Name] = m.Priority
	}
	for name, p := range prio {
		if name == "revoked-key" {
			continue
		}
		assert.Greater(t, p, prio["revoked-key"], "revoked-key must evaluate last; %q has lower or equal priority", name)
	}
}

// --- catalog parsing and capability filtering ------------------------------

func TestSummarizeOrcaRouterCatalog_FiltersByDeclaredCapability(t *testing.T) {
	models, err := parseOrcaRouterCatalog([]byte(orcaMixedCatalog))
	require.NoError(t, err)

	got := summarizeOrcaRouterCatalog(models)
	assert.Equal(t, 10, got.TotalModels)
	// auto, claude, gemini, deepseek, gpt-5.5. Embedding, image generation,
	// video, rerank and the undeclared entry are all excluded: capability is
	// read from supported_endpoint_types, never inferred from a model name.
	assert.Equal(t, 5, got.ChatModels)
	// Only the gemini entry declares an image input modality.
	assert.Equal(t, 1, got.MultimodalModels)
	assert.Equal(t, 0, got.CyberModels)
}

func TestSummarizeOrcaRouterCatalog_DetectsCyberTier(t *testing.T) {
	models, err := parseOrcaRouterCatalog([]byte(orcaCyberCatalog))
	require.NoError(t, err)

	got := summarizeOrcaRouterCatalog(models)
	assert.Equal(t, 3, got.ChatModels)
	assert.Equal(t, 2, got.CyberModels)
}

func TestSummarizeOrcaRouterCatalog_FailsClosedWithoutEndpointTypes(t *testing.T) {
	models, err := parseOrcaRouterCatalog([]byte(`{"data":[{"id":"mystery/model"}]}`))
	require.NoError(t, err)

	got := summarizeOrcaRouterCatalog(models)
	assert.Equal(t, 1, got.TotalModels, "the entry is counted as present")
	assert.Equal(t, 0, got.ChatModels, "an undeclared entry must not be treated as chat-capable")
}

func TestSummarizeOrcaRouterCatalog_CapsModelCount(t *testing.T) {
	models := make([]orcaRouterModel, 0, orcaRouterMaxModels+50)
	for i := 0; i < orcaRouterMaxModels+50; i++ {
		models = append(models, orcaRouterModel{
			ID:                     fmt.Sprintf("vendor/m-%d", i),
			SupportedEndpointTypes: []string{"openai"},
		})
	}
	got := summarizeOrcaRouterCatalog(models)
	assert.Equal(t, orcaRouterMaxModels, got.TotalModels)
}

func TestParseOrcaRouterCatalog_AcceptsBareArray(t *testing.T) {
	models, err := parseOrcaRouterCatalog([]byte(`[{"id":"orcarouter/auto","supported_endpoint_types":["openai"]}]`))
	require.NoError(t, err)
	require.Len(t, models, 1)
	assert.Equal(t, "orcarouter/auto", models[0].ID)
}

func TestParseOrcaRouterCatalog_RejectsInvalidJSON(t *testing.T) {
	_, err := parseOrcaRouterCatalog([]byte(`not json`))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrModifierParseError))
}

// --- request shape and classification --------------------------------------

func TestOrcaRouterCondition_SendsBearerToModelsEndpoint(t *testing.T) {
	ts := newOrcaTestServer(t, http.StatusOK, orcaMixedCatalog)
	cond := ts.condition(orcaRouterProbeBroad)

	fired, err := cond.Evaluate(context.Background(), orcaTestMatch(orcaTestKey))
	require.NoError(t, err)
	assert.False(t, fired, "5 chat models is below the broad-access threshold")

	assert.Equal(t, 1, int(ts.requests.Load()))
	assert.Equal(t, "GET", ts.lastVerb)
	assert.Equal(t, "/v1/models", ts.lastPath)
	assert.Equal(t, "Bearer "+orcaTestKey, ts.lastAuth)
}

func TestOrcaRouterCondition_Classification(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   map[orcaRouterProbeMode]bool
	}{
		{
			name:   "broad catalog",
			status: http.StatusOK,
			body:   orcaBroadCatalog(),
			want: map[orcaRouterProbeMode]bool{
				orcaRouterProbeBroad: true, orcaRouterProbeLimited: false,
				orcaRouterProbeCyber: false, orcaRouterProbeRevoked: false,
			},
		},
		{
			name:   "narrow catalog",
			status: http.StatusOK,
			body:   orcaMixedCatalog,
			want: map[orcaRouterProbeMode]bool{
				orcaRouterProbeBroad: false, orcaRouterProbeLimited: true,
				orcaRouterProbeCyber: false, orcaRouterProbeRevoked: false,
			},
		},
		{
			name:   "cyber tier reachable",
			status: http.StatusOK,
			body:   orcaCyberCatalog,
			want: map[orcaRouterProbeMode]bool{
				orcaRouterProbeBroad: false, orcaRouterProbeLimited: true,
				orcaRouterProbeCyber: true, orcaRouterProbeRevoked: false,
			},
		},
		{
			name:   "revoked key",
			status: http.StatusUnauthorized,
			body:   `{"error":{"message":"invalid api key"}}`,
			want: map[orcaRouterProbeMode]bool{
				orcaRouterProbeBroad: false, orcaRouterProbeLimited: false,
				orcaRouterProbeCyber: false, orcaRouterProbeRevoked: true,
			},
		},
		{
			name:   "forbidden key",
			status: http.StatusForbidden,
			body:   `{"error":{"message":"forbidden"}}`,
			want: map[orcaRouterProbeMode]bool{
				orcaRouterProbeBroad: false, orcaRouterProbeLimited: false,
				orcaRouterProbeCyber: false, orcaRouterProbeRevoked: true,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newOrcaTestServer(t, tc.status, tc.body)
			for mode, want := range tc.want {
				cond := ts.condition(mode)
				got, err := cond.Evaluate(context.Background(), orcaTestMatch(orcaTestKey))
				require.NoError(t, err, "mode %d", mode)
				assert.Equalf(t, want, got, "mode %d", mode)
			}
		})
	}
}

func TestOrcaRouterCondition_NoKeyDoesNotCallProvider(t *testing.T) {
	ts := newOrcaTestServer(t, http.StatusOK, orcaMixedCatalog)
	cond := ts.condition(orcaRouterProbeBroad)

	fired, err := cond.Evaluate(context.Background(), &types.Match{RuleID: orcaRouterRuleID})
	require.NoError(t, err)
	assert.False(t, fired)
	assert.Equal(t, 0, int(ts.requests.Load()), "no request may be made without a key")
}

// --- error classification ---------------------------------------------------

func TestOrcaRouterCondition_ErrorClassification(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"rate limited", http.StatusTooManyRequests, `{}`, ErrModifierRateLimit},
		{"server error", http.StatusInternalServerError, `oops`, ErrModifierServerError},
		{"moved endpoint", http.StatusNotFound, ``, ErrConditionNotApplicable},
		{"malformed catalog", http.StatusOK, `not json`, ErrModifierParseError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newOrcaTestServer(t, tc.status, tc.body)
			fired, err := ts.condition(orcaRouterProbeBroad).Evaluate(context.Background(), orcaTestMatch(orcaTestKey))
			assert.False(t, fired, "an errored classification must not fire")
			require.Error(t, err)
			assert.Truef(t, errors.Is(err, tc.want), "got %v, want %v", err, tc.want)
		})
	}
}

func TestOrcaRouterCondition_NetworkErrorIsClassified(t *testing.T) {
	ts := newOrcaTestServer(t, http.StatusOK, orcaMixedCatalog)
	cond := ts.condition(orcaRouterProbeBroad)
	ts.Close() // requests now fail at the transport layer

	fired, err := cond.Evaluate(context.Background(), orcaTestMatch(orcaTestKey))
	assert.False(t, fired)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrModifierNetwork), "got %v", err)
}

func TestOrcaRouterCondition_OversizedCatalogIsRejected(t *testing.T) {
	huge := `{"data":[` + strings.Repeat(`{"id":"x"},`, orcaRouterMaxCatalogBytes/10) + `{"id":"y"}]}`
	ts := newOrcaTestServer(t, http.StatusOK, huge)

	fired, err := ts.condition(orcaRouterProbeBroad).Evaluate(context.Background(), orcaTestMatch(orcaTestKey))
	assert.False(t, fired)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrModifierParseError), "got %v", err)
}

func TestOrcaRouterCondition_KeyNeverLeaksIntoErrors(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusNotFound, http.StatusOK} {
		body := `not json`
		ts := newOrcaTestServer(t, status, body)
		_, err := ts.condition(orcaRouterProbeBroad).Evaluate(context.Background(), orcaTestMatch(orcaTestKey))
		require.Error(t, err)
		assert.NotContains(t, err.Error(), orcaTestKey, "error text must not carry the credential")
	}
}

// --- request deduplication --------------------------------------------------

func TestOrcaRouterScorer_OneRequestPerFinding(t *testing.T) {
	ts := newOrcaTestServer(t, http.StatusOK, orcaMixedCatalog)
	scorer := newOrcaRouterScorer(ts.Client(), ts.URL+"/v1/models")

	engine := NewEngine([]*Scorer{scorer}, EngineConfig{ScopeEnabled: true})
	rule := &types.Rule{ID: orcaRouterRuleID, BaseScore: 70}
	match := orcaTestMatch(orcaTestKey)
	finding := &types.Finding{ID: "f1", RuleID: rule.ID}

	engine.Score(context.Background(), finding, []*types.Match{match}, rule)

	assert.Equal(t, 1, int(ts.requests.Load()),
		"all four modifiers must share one catalog request")
}

// --- engine integration -----------------------------------------------------

func TestOrcaRouterScorer_EngineAppliesCapabilitySignals(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		want    int
		applied []string
	}{
		{
			name:    "cyber and broad access",
			status:  http.StatusOK,
			body:    orcaBroadCyberCatalog(),
			want:    90,
			applied: []string{"cyber-model-access", "broad-model-access"},
		},
		{
			name:    "narrow access",
			status:  http.StatusOK,
			body:    orcaMixedCatalog,
			want:    55,
			applied: []string{"limited-model-access"},
		},
		{
			name:    "revoked key",
			status:  http.StatusUnauthorized,
			body:    `{}`,
			want:    5,
			applied: []string{"revoked-key"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newOrcaTestServer(t, tc.status, tc.body)
			engine := NewEngine([]*Scorer{newOrcaRouterScorer(ts.Client(), ts.URL+"/v1/models")}, EngineConfig{ScopeEnabled: true})
			rule := &types.Rule{ID: orcaRouterRuleID, BaseScore: 70}

			score := engine.Score(context.Background(), &types.Finding{ID: "f1", RuleID: rule.ID},
				[]*types.Match{orcaTestMatch(orcaTestKey)}, rule)

			assert.Equal(t, tc.want, score.Final)
			got := make([]string, 0, len(score.Applied))
			for _, a := range score.Applied {
				got = append(got, a.Name)
			}
			assert.ElementsMatch(t, tc.applied, got)
		})
	}
}

// orcaBroadCyberCatalog is a 12-model catalog that also exposes cyber-tier
// models, so the two positive modifiers co-fire.
func orcaBroadCyberCatalog() string {
	body := orcaBroadCatalog()
	return strings.Replace(body, `"data":[`, `"data":[{"id":"orcacyber-ultra-1.0","supported_endpoint_types":["openai"]},`, 1)
}
