package enum

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAsanaURL_All(t *testing.T) {
	scope, gid, ok := ParseAsanaURL("asana://")
	assert.True(t, ok)
	assert.Equal(t, AsanaScopeAll, scope)
	assert.Equal(t, "", gid)
}

func TestParseAsanaURL_Workspace(t *testing.T) {
	scope, gid, ok := ParseAsanaURL("asana://workspace/123456789")
	assert.True(t, ok)
	assert.Equal(t, AsanaScopeWorkspace, scope)
	assert.Equal(t, "123456789", gid)
}

func TestParseAsanaURL_Team(t *testing.T) {
	scope, gid, ok := ParseAsanaURL("asana://team/987654321")
	assert.True(t, ok)
	assert.Equal(t, AsanaScopeTeam, scope)
	assert.Equal(t, "987654321", gid)
}

func TestParseAsanaURL_Project(t *testing.T) {
	scope, gid, ok := ParseAsanaURL("asana://project/111222333")
	assert.True(t, ok)
	assert.Equal(t, AsanaScopeProject, scope)
	assert.Equal(t, "111222333", gid)
}

func TestParseAsanaURL_NotAsana(t *testing.T) {
	_, _, ok := ParseAsanaURL("https://app.asana.com/0/1/2")
	assert.False(t, ok)

	_, _, ok = ParseAsanaURL("s3://bucket/prefix")
	assert.False(t, ok)

	_, _, ok = ParseAsanaURL("/some/path")
	assert.False(t, ok)

	_, _, ok = ParseAsanaURL("")
	assert.False(t, ok)
}

func TestParseAsanaURL_UnknownKind(t *testing.T) {
	_, _, ok := ParseAsanaURL("asana://user/123")
	assert.False(t, ok)
}

func TestParseAsanaURL_MissingGID(t *testing.T) {
	_, _, ok := ParseAsanaURL("asana://workspace/")
	assert.False(t, ok)

	_, _, ok = ParseAsanaURL("asana://workspace")
	assert.False(t, ok)

	_, _, ok = ParseAsanaURL("asana://team/")
	assert.False(t, ok)

	_, _, ok = ParseAsanaURL("asana://project/")
	assert.False(t, ok)
}

func TestParseAsanaURL_ExtraSegments(t *testing.T) {
	// Extra non-empty path segment after <kind>/<gid> must be rejected.
	_, _, ok := ParseAsanaURL("asana://workspace/123/extra")
	assert.False(t, ok)

	_, _, ok = ParseAsanaURL("asana://team/456/sub/path")
	assert.False(t, ok)

	// Trailing slash produces an empty third segment and must NOT be rejected.
	scope, gid, ok := ParseAsanaURL("asana://project/789/")
	assert.True(t, ok)
	assert.Equal(t, AsanaScopeProject, scope)
	assert.Equal(t, "789", gid)
}
