package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJsonGet_TopLevelField(t *testing.T) {
	data := []byte(`{"login":"octocat","plan":{"name":"enterprise"}}`)
	v, err := jsonGet(data, ".login")
	require.NoError(t, err)
	assert.Equal(t, "octocat", v)
}

func TestJsonGet_NestedField(t *testing.T) {
	data := []byte(`{"plan":{"name":"enterprise"}}`)
	v, err := jsonGet(data, ".plan.name")
	require.NoError(t, err)
	assert.Equal(t, "enterprise", v)
}

func TestJsonGet_RootReturnsTopLevelArray(t *testing.T) {
	data := []byte(`[{"id":1},{"id":2}]`)
	v, err := jsonGet(data, ".")
	require.NoError(t, err)
	arr, ok := v.([]interface{})
	require.True(t, ok, "expected array at root")
	assert.Len(t, arr, 2)
}

func TestJsonGet_MissingFieldReturnsError(t *testing.T) {
	data := []byte(`{"a":1}`)
	_, err := jsonGet(data, ".b")
	assert.Error(t, err)
}

func TestJsonGet_InvalidJSONReturnsError(t *testing.T) {
	_, err := jsonGet([]byte(`not-json`), ".x")
	assert.Error(t, err)
}
