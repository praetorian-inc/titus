package rule

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCloudinaryURL_Detection verifies the kingfisher.cloudinary.1 rule detects
// Cloudinary environment URLs (cloudinary://<api_key>:<api_secret>@<cloud_name>)
// and ignores public delivery URLs and placeholder values.
func TestCloudinaryURL_Detection(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	var cloudinaryRule *types.Rule
	for _, r := range rules {
		if r.ID == "kingfisher.cloudinary.1" {
			cloudinaryRule = r
			break
		}
	}
	require.NotNil(t, cloudinaryRule, "kingfisher.cloudinary.1 rule should exist")

	m, err := matcher.NewPortableRegexp([]*types.Rule{cloudinaryRule}, 0, nil)
	require.NoError(t, err)

	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		{
			name:        "valid CLOUDINARY_URL env assignment",
			input:       `CLOUDINARY_URL=cloudinary://874837483274837:abcd1234EFGH5678ijkl9012MNO@demo-media`,
			shouldMatch: true,
		},
		{
			name:        "valid quoted URL",
			input:       `CLOUDINARY_URL="cloudinary://123456789012345:Xy7Kp2Lm9Qr4Vn1Bc6Dg3Fh8Js0@my-company"`,
			shouldMatch: true,
		},
		{
			name:        "valid JSON value",
			input:       `{"cloudinary_url":"cloudinary://509182734650918:9zAq2Wsx3Edc4Rfv5Tgb6Yhn7Uj@prod-assets"}`,
			shouldMatch: true,
		},
		{
			name:        "invalid - secret too short",
			input:       `cloudinary://874837483274837:tooShortSecret@demo-media`,
			shouldMatch: false,
		},
		{
			name:        "invalid - api key not 15 digits",
			input:       `cloudinary://12345:abcd1234EFGH5678ijkl9012MNO@demo-media`,
			shouldMatch: false,
		},
		{
			name:        "invalid - public delivery URL",
			input:       `https://res.cloudinary.com/demo/image/upload/v1234567890/sample.jpg`,
			shouldMatch: false,
		},
		{
			name:        "invalid - placeholder value",
			input:       `CLOUDINARY_URL=cloudinary://<your_api_key>:<your_api_secret>@<cloud_name>`,
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tc.input))
			require.NoError(t, err)

			if tc.shouldMatch {
				assert.NotEmpty(t, matches, "expected match for: %s", tc.input)
			} else {
				assert.Empty(t, matches, "expected no match for: %s", tc.input)
			}
		})
	}
}
