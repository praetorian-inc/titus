// pkg/validator/huggingface_cassette_test.go
//
// VCR replay tests for the huggingface-token validator (LAB-4074).
// These tests skip gracefully when cassettes have not been recorded yet.
//
// To record:
//
//	SECRET_PLAINTEXT=<hf_token> RECORD=1 make record-fixtures SVC=huggingface
package validator

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

func Test_huggingface_Valid(t *testing.T) {
	runCassetteCase(t, "huggingface.yaml", "np.huggingface.1", "testdata/huggingface/valid", types.StatusValid)
}

func Test_huggingface_Invalid(t *testing.T) {
	runCassetteCase(t, "huggingface.yaml", "np.huggingface.1", "testdata/huggingface/invalid", types.StatusInvalid)
}
