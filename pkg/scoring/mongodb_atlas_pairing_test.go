package scoring

import (
	"context"
	"testing"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// atlasMatch builds a match shaped as the matcher produces one: the private key
// is Snippet.Matching, NamedGroups is empty (mongodb.yml has no named capture
// groups), and the public key lives in the surrounding context if anywhere.
// atlasMatch builds a kingfisher.mongodb.1 match the way the MATCHER builds one.
//
// This is deliberately not the obvious shape. Snippet.Matching holds the whole
// matched span -- the rule spans from the mongodb/atlas keyword through the
// private-key label to the UUID -- while Groups[0] holds the captured UUID
// alone. An earlier version of this helper put the bare UUID in Matching, which
// is a state the matcher never produces, and it hid a bug where the entire span
// was returned as the private key.
//
// matched is the text the rule matches; the UUID inside it is the capture.
func atlasMatch(before, matched, after string) *types.Match {
	uuid := atlasPrivateKeyPattern.FindString(matched)
	var groups [][]byte
	if uuid != "" {
		groups = [][]byte{[]byte(uuid)}
	}
	return &types.Match{
		RuleID:      "kingfisher.mongodb.1",
		NamedGroups: map[string][]byte{},
		Groups:      groups,
		Snippet: types.Snippet{
			Before:   []byte(before),
			Matching: []byte(matched),
			After:    []byte(after),
		},
	}
}

const (
	atlasPriv = "2c130c23-e6b6-4da8-a93f-a8bf33218830"
	atlasPub  = "yhltsvan"
)

// The public key sits in the config above the private key -- the common shape.
func TestAtlasDigest_PairsPublicKeyFromContextBefore(t *testing.T) {
	m := atlasMatch("ATLAS_PUBLIC_KEY=yhltsvan\nATLAS_PRIVATE_KEY=", atlasPriv, "\n")
	pub, priv, ok := extractAtlasDigestCredentials(m)
	require.True(t, ok, "should pair the public key from preceding context")
	assert.Equal(t, atlasPub, pub)
	assert.Equal(t, atlasPriv, priv)
}

// ...or below it.
func TestAtlasDigest_PairsPublicKeyFromContextAfter(t *testing.T) {
	m := atlasMatch("atlas_private_key: ", atlasPriv, "\natlas_public_key: yhltsvan\n")
	pub, _, ok := extractAtlasDigestCredentials(m)
	require.True(t, ok)
	assert.Equal(t, atlasPub, pub)
}

// The curl digest form puts both keys adjacent, and is how the Atlas docs
// demonstrate every API call.
func TestAtlasDigest_PairsFromCurlUserForm(t *testing.T) {
	m := atlasMatch(`curl --user "yhltsvan:`, atlasPriv, `" --digest -X GET https://cloud.mongodb.com/api/atlas/v2/groups`)
	pub, _, ok := extractAtlasDigestCredentials(m)
	require.True(t, ok)
	assert.Equal(t, atlasPub, pub)
}

// A bare 8-letter word nearby is not a public key. The patterns must require
// mongodb/atlas/public context, because [a-z]{8} alone matches ordinary prose.
func TestAtlasDigest_DoesNotPairUnrelatedWords(t *testing.T) {
	m := atlasMatch("// deployed absolute controls\nprivate_key = ", atlasPriv, "\n")
	_, _, ok := extractAtlasDigestCredentials(m)
	assert.False(t, ok, "an unanchored 8-letter word must not be taken for a public key")
}

// No public key anywhere: still no credentials, but now that is a real absence
// rather than a mechanism that never worked.
func TestAtlasDigest_NoPublicKeyInContext(t *testing.T) {
	m := atlasMatch("ATLAS_PRIVATE_KEY=", atlasPriv, "\n")
	_, _, ok := extractAtlasDigestCredentials(m)
	assert.False(t, ok)
}

// The shipped scorer's dynamic modifier must be able to obtain credentials from
// a realistic match. This is the check whose absence let the defect ship: the
// digest path returned (false, nil) -- no error, no warning, no stat.
func TestBuiltinAtlasScorer_DigestModifierGetsCredentials(t *testing.T) {
	m := atlasMatch("ATLAS_PUBLIC_KEY=yhltsvan\nATLAS_PRIVATE_KEY=", atlasPriv, "\n")

	var gotAuth, gotPub, gotPriv string
	client := buildAtlasClient(context.Background(), m,
		func(_ context.Context, authType string, creds map[string]string) (atlasAPI, error) {
			gotAuth, gotPub, gotPriv = authType, creds["publicKey"], creds["privateKey"]
			return stubAtlasAPI{}, nil
		})

	require.NotNil(t, client, "digest path must produce a client; nil means credentials were never assembled")
	assert.Equal(t, "digest", gotAuth)
	assert.Equal(t, atlasPub, gotPub)
	assert.Equal(t, atlasPriv, gotPriv)
}

// stubAtlasAPI satisfies atlasAPI without making network calls.
type stubAtlasAPI struct{ atlasAPI }

// The private key is the UUID, not the whole matched span.
//
// The rule's pattern spans from the mongodb/atlas keyword to the UUID, so
// Snippet.Matching contains labels, separators and possibly the public key too.
// Returning it would authenticate with that entire blob as the password.
func TestAtlasDigest_PrivateKeyIsTheUUIDNotTheWholeSpan(t *testing.T) {
	m := atlasMatch("", "ATLAS_PUBLIC_KEY=yhltsvan\nATLAS_PRIVATE_KEY="+atlasPriv, "\n")
	pub, priv, ok := extractAtlasDigestCredentials(m)
	require.True(t, ok)
	assert.Equal(t, atlasPub, pub)
	assert.Equal(t, atlasPriv, priv, "must be the UUID alone, not the matched span")
	assert.NotContains(t, priv, "ATLAS_", "the label must not leak into the credential")
}

// With several pairs in one snippet, the private key must be paired with the
// public key NEAREST it, not the first one in the context.
func TestAtlasDigest_MultiplePairs_PicksNearestPublicKey(t *testing.T) {
	const otherPub = "abcdefgh"
	before := "ATLAS_PUBLIC_KEY=" + otherPub + "\n" +
		"ATLAS_PRIVATE_KEY=11111111-2222-3333-4444-555555555555\n" +
		"ATLAS_PUBLIC_KEY=" + atlasPub + "\n"
	m := atlasMatch(before, "ATLAS_PRIVATE_KEY="+atlasPriv, "\n")

	pub, priv, ok := extractAtlasDigestCredentials(m)
	require.True(t, ok)
	assert.Equal(t, atlasPriv, priv)
	assert.Equal(t, atlasPub, pub, "must pair with the nearest preceding public key, not the first")
	assert.NotEqual(t, otherPub, pub)
}

// End-to-end against the REAL matcher, not a hand-built match.
//
// Every earlier bug in this area survived because fixtures described a match
// the matcher never produces -- NamedGroups["PUBKEY"] populated, or the bare
// UUID in Snippet.Matching. This test takes the shape from the matcher itself,
// so a fixture assumption cannot hide a defect.
func TestAtlasDigest_AgainstRealMatcherOutput(t *testing.T) {
	rules, err := rule.NewLoader().LoadBuiltinRules()
	require.NoError(t, err)
	var atlasRule *types.Rule
	for _, r := range rules {
		if r.ID == "kingfisher.mongodb.1" {
			atlasRule = r
		}
	}
	require.NotNil(t, atlasRule)

	mm, err := matcher.NewPortableRegexp([]*types.Rule{atlasRule}, 3, nil)
	require.NoError(t, err)

	input := "ATLAS_PUBLIC_KEY=" + atlasPub + "\nATLAS_PRIVATE_KEY=" + atlasPriv + "\n"
	matches, err := mm.Match([]byte(input))
	require.NoError(t, err)
	require.NotEmpty(t, matches, "the rule must detect a realistic Atlas key pair")

	pub, priv, ok := extractAtlasDigestCredentials(matches[0])
	require.True(t, ok, "digest credentials must be recoverable from a real match")
	assert.Equal(t, atlasPub, pub)
	assert.Equal(t, atlasPriv, priv)
}
