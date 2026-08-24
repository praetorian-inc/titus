//go:build wasm || !cgo || !vectorscan

package matcher

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestHyperscanDatabaseUnavailableWithoutVectorscan(t *testing.T) {
	rules := []*types.Rule{{ID: "test", Pattern: "test"}}

	_, err := HyperscanDatabaseFilename(rules)
	assert.ErrorIs(t, err, ErrHyperscanDatabaseUnavailable)

	_, err = CompileHyperscanDatabase(rules)
	assert.ErrorIs(t, err, ErrHyperscanDatabaseUnavailable)

	_, err = WriteHyperscanDatabase(t.TempDir(), rules)
	assert.ErrorIs(t, err, ErrHyperscanDatabaseUnavailable)
}
