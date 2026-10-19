// pkg/validator/posthog_cassette_test.go
//
// VCR replay tests for the PostHog validators (LAB-4063).
// These tests skip gracefully when cassettes have not been recorded yet.
//
// To record project API key:
//
//	SECRET_PLAINTEXT=<phc_token> RECORD=1 make record-fixtures SVC=posthog
//
// To record personal API key:
//
//	SECRET_PLAINTEXT=<phx_token> RECORD=1 make record-fixtures SVC=posthog
package validator

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

func Test_posthog_project_Valid(t *testing.T) {
	runCassetteCase(t, "posthog.yaml", "kingfisher.posthog.1", "testdata/posthog/project_valid", types.StatusValid)
}

func Test_posthog_project_Invalid(t *testing.T) {
	runCassetteCase(t, "posthog.yaml", "kingfisher.posthog.1", "testdata/posthog/project_invalid", types.StatusInvalid)
}

func Test_posthog_personal_Valid(t *testing.T) {
	runCassetteCase(t, "posthog.yaml", "kingfisher.posthog.2", "testdata/posthog/personal_valid", types.StatusValid)
}

func Test_posthog_personal_Invalid(t *testing.T) {
	runCassetteCase(t, "posthog.yaml", "kingfisher.posthog.2", "testdata/posthog/personal_invalid", types.StatusInvalid)
}
