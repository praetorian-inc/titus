package enum

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseS3URL(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantBucket string
		wantPrefix string
		wantOK     bool
	}{
		{"bucket with prefix", "s3://my-bucket/path/to/data", "my-bucket", "path/to/data", true},
		{"bucket with trailing slash", "s3://my-bucket/", "my-bucket", "", true},
		{"bucket only", "s3://my-bucket", "my-bucket", "", true},
		{"local path", "/local/path", "", "", false},
		{"https URL", "https://s3.amazonaws.com/bucket", "", "", false},
		{"empty bucket", "s3://", "", "", false},
		{"empty string", "", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket, prefix, ok := ParseS3URL(tt.input)
			assert.Equal(t, tt.wantOK, ok, "ok mismatch")
			assert.Equal(t, tt.wantBucket, bucket, "bucket mismatch")
			assert.Equal(t, tt.wantPrefix, prefix, "prefix mismatch")
		})
	}
}
