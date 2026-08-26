package scoring

import (
	"context"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// atlasMatch builds a match shaped as the matcher produces one: the private key
// is Snippet.Matching, NamedGroups is empty (mongodb.yml has no named capture
// groups), and the public key lives in the surrounding context if anywhere.
func atlasMatch(before, priv, after string) *types.Match {
	return &types.Match{
		RuleID:      "kingfisher.mongodb.1",
		NamedGroups: map[string][]byte{},
		Snippet: types.Snippet{
			Before:   []byte(before),
			Matching: []byte(priv),
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
