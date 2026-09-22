// pkg/validator/recaptcha_cassette_test.go
//
// VCR replay tests for the recaptcha-secret-key validator (LAB-4051).
// These tests skip gracefully when cassettes have not been recorded yet.
//
// To record:
//
//	SECRET_PLAINTEXT=<recaptcha_secret_key> RECORD=1 make record-fixtures SVC=recaptcha
package validator

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

func Test_recaptcha_Valid(t *testing.T) {
	runCassetteCase(t, "recaptcha.yaml", "kingfisher.recaptcha.1", "testdata/recaptcha/valid", types.StatusValid)
}

func Test_recaptcha_Invalid(t *testing.T) {
	runCassetteCase(t, "recaptcha.yaml", "kingfisher.recaptcha.1", "testdata/recaptcha/invalid", types.StatusInvalid)
}
