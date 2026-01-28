package types

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeBlobID(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		expected string
	}{
		{
			name:    "empty content",
			content: []byte(""),
			// Git: echo -n "" | git hash-object --stdin
			expected: "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
		},
		{
			name:    "hello world",
			content: []byte("hello world"),
			// Git computes: SHA-1("blob 11\0hello world")
			expected: "95d09f2b10159347eece71399a7e2e907ea3df4f",
		},
		{
			name:    "test content",
			content: []byte("test content\n"),
			// Git: echo "test content" | git hash-object --stdin
			expected: "d670460b4b4aece5915caf5c68d12f560a9fe3e4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := ComputeBlobID(tt.content)
			assert.Equal(t, tt.expected, id.Hex())
		})
	}
}

func TestBlobID_Hex(t *testing.T) {
	id := BlobID{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78}

	expected := "123456789abcdef0123456789abcdef012345678"
	assert.Equal(t, expected, id.Hex())
}

func TestBlobID_String(t *testing.T) {
	id := BlobID{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78}

	expected := "123456789abcdef0123456789abcdef012345678"
	assert.Equal(t, expected, id.String())
}

func TestParseBlobID(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
	}{
		{
			name:      "valid hex",
			input:     "123456789abcdef0123456789abcdef012345678",
			expectErr: false,
		},
		{
			name:      "too short",
			input:     "123456789abcdef0123456789abcdef01234567",
			expectErr: true,
		},
		{
			name:      "too long",
			input:     "123456789abcdef0123456789abcdef0123456789",
			expectErr: true,
		},
		{
			name:      "invalid hex",
			input:     "zzz456789abcdef0123456789abcdef012345678",
			expectErr: true,
		},
		{
			name:      "uppercase valid",
			input:     "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := ParseBlobID(tt.input)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				// Verify round-trip (Hex() returns lowercase)
				assert.Equal(t, strings.ToLower(tt.input), id.Hex())
			}
		})
	}
}

func TestBlobID_MarshalJSON(t *testing.T) {
	id := BlobID{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78}

	data, err := id.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, `"123456789abcdef0123456789abcdef012345678"`, string(data))
}

func TestBlobID_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
	}{
		{
			name:      "valid",
			input:     `"123456789abcdef0123456789abcdef012345678"`,
			expectErr: false,
		},
		{
			name:      "invalid hex",
			input:     `"invalid"`,
			expectErr: true,
		},
		{
			name:      "not a string",
			input:     `123`,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var id BlobID
			err := id.UnmarshalJSON([]byte(tt.input))

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, "123456789abcdef0123456789abcdef012345678", id.Hex())
			}
		})
	}
}
