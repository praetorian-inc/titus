// pkg/validator/exa_cassette_test.go
//
// VCR replay tests for the exa-api-key validator (LAB-4068).
// These tests skip gracefully when cassettes have not been recorded yet.
//
// To record:
//
//	SECRET_PLAINTEXT=<exa_api_key> RECORD=1 make record-fixtures SVC=exa
package validator

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

func Test_exa_Valid(t *testing.T) {
	runCassetteCase(t, "exa.yaml", "kingfisher.exa.1", "testdata/exa/valid", types.StatusValid)
}

func Test_exa_Invalid(t *testing.T) {
	runCassetteCase(t, "exa.yaml", "kingfisher.exa.1", "testdata/exa/invalid", types.StatusInvalid)
}
