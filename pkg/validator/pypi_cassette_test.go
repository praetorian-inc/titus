// pkg/validator/pypi_cassette_test.go
//
// VCR replay tests for the pypi-upload-token validator (np.pypi.1).
//
// Regression coverage for the false-positive bug: the validator previously
// hit GET https://pypi.org/simple/ (the public package index), which returns
// HTTP 200 for any request, so every detected token was reported "valid".
// The fix POSTs to https://upload.pypi.org/legacy/, where a bad token is
// rejected with 403 and a valid token passes auth (400 on payload).
//
// To re-record with a throwaway token:
//
//	SECRET_PLAINTEXT=<pypi_upload_token> RECORD=1 make record-fixtures SVC=pypi
package validator

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

func Test_pypi_Valid(t *testing.T) {
	runCassetteCase(t, "pypi.yaml", "np.pypi.1", "testdata/pypi/valid", types.StatusValid)
}

func Test_pypi_Invalid(t *testing.T) {
	runCassetteCase(t, "pypi.yaml", "np.pypi.1", "testdata/pypi/invalid", types.StatusInvalid)
}
