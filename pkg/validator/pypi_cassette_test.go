// pkg/validator/pypi_cassette_test.go
//
// VCR replay tests for the pypi-upload-token validator (np.pypi.1).
//
// The previous definition validated tokens against https://pypi.org/simple/,
// the PUBLIC package index, which answers 200 to any anonymous client. That
// meant every np.pypi.1 match was reported valid regardless of whether the
// token was real. The current definition instead POSTs to
// https://upload.pypi.org/legacy/ and keys rejection on the response BODY
// ("Invalid or non-existent authentication information") rather than on the
// 403 status code, because warehouse also returns 403 for tokens that are
// perfectly valid but whose owner lacks 2FA or a verified email -- those must
// fall through to undetermined, not be reported invalid. Test 3
// (Test_pypi_LiveTokenWithoutTwoFactor) is the guard for that distinction.
//
// These tests skip gracefully when cassettes have not been recorded yet.
//
// To record:
//
//	SECRET_PLAINTEXT=<pypi_token> RECORD=1 make record-fixtures SVC=pypi
package validator

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

func Test_pypi_Invalid(t *testing.T) {
	runCassetteCase(t, "pypi.yaml", "np.pypi.1", "testdata/pypi/invalid", types.StatusInvalid)
}

func Test_pypi_Valid(t *testing.T) {
	runCassetteCase(t, "pypi.yaml", "np.pypi.1", "testdata/pypi/valid", types.StatusValid)
}

func Test_pypi_LiveTokenWithoutTwoFactor(t *testing.T) {
	runCassetteCase(t, "pypi.yaml", "np.pypi.1", "testdata/pypi/live_token_without_2fa", types.StatusUndetermined)
}
