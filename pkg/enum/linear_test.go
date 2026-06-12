package enum

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinearEnumerator_Construction(t *testing.T) {
	e, err := NewLinearEnumerator(LinearConfig{Token: "lin_api_test"})
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestLinearEnumerator_RequiresToken(t *testing.T) {
	_, err := NewLinearEnumerator(LinearConfig{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestLinearEnumerator_Defaults(t *testing.T) {
	e, err := NewLinearEnumerator(LinearConfig{Token: "lin_api_test"})
	require.NoError(t, err)
	assert.Equal(t, 3, e.config.Concurrency)
	assert.Equal(t, 2.0, e.config.RateLimit)
}

func TestLinearEnumerator_Interface(t *testing.T) {
	e, err := NewLinearEnumerator(LinearConfig{Token: "lin_api_test"})
	require.NoError(t, err)
	var _ Enumerator = e
}

func TestLinearProvenance(t *testing.T) {
	prov := linearProvenance("issue", "ISS-123", "Bug title", "https://linear.app/team/ISS-123", "MyTeam", "MyProject")
	assert.Equal(t, "extended", prov.Kind())
	assert.Equal(t, "linear", prov.Payload["source"])
	assert.Equal(t, "issue", prov.Payload["entityType"])
	assert.Equal(t, "ISS-123", prov.Payload["identifier"])
	assert.Equal(t, "Bug title", prov.Payload["title"])
	assert.Equal(t, "https://linear.app/team/ISS-123", prov.Payload["url"])
	assert.Equal(t, "MyTeam", prov.Payload["team"])
	assert.Equal(t, "MyProject", prov.Payload["project"])
}

// Compile-time assertion that *LinearEnumerator satisfies Enumerator.
var _ Enumerator = (*LinearEnumerator)(nil)

// Ensure types package is referenced so imports stay tidy.
var _ types.Provenance = types.ExtendedProvenance{}
