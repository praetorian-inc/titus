package types

import (
	"crypto/sha1"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// BlobID is a Git-style SHA-1 content hash (20 bytes).
type BlobID [20]byte

// ComputeBlobID computes Git-style blob ID: SHA-1("blob {len}\0{content}").
func ComputeBlobID(content []byte) BlobID {
	header := fmt.Sprintf("blob %d\x00", len(content))
	h := sha1.New()
	h.Write([]byte(header))
	h.Write(content)

	var id BlobID
	copy(id[:], h.Sum(nil))
	return id
}

// Hex returns 40-character hex string.
func (id BlobID) Hex() string {
	return hex.EncodeToString(id[:])
}

// String implements Stringer (returns Hex()).
func (id BlobID) String() string {
	return id.Hex()
}

// ParseBlobID parses 40-char hex string to BlobID.
func ParseBlobID(hexStr string) (BlobID, error) {
	if len(hexStr) != 40 {
		return BlobID{}, fmt.Errorf("invalid blob ID length: expected 40, got %d", len(hexStr))
	}

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return BlobID{}, fmt.Errorf("invalid hex string: %w", err)
	}

	var id BlobID
	copy(id[:], decoded)
	return id, nil
}

// MarshalJSON implements json.Marshaler.
func (id BlobID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.Hex())
}

// UnmarshalJSON implements json.Unmarshaler.
func (id *BlobID) UnmarshalJSON(data []byte) error {
	var hexStr string
	if err := json.Unmarshal(data, &hexStr); err != nil {
		return err
	}

	parsed, err := ParseBlobID(hexStr)
	if err != nil {
		return err
	}

	*id = parsed
	return nil
}

// Value implements driver.Valuer for SQL serialization.
func (id BlobID) Value() (driver.Value, error) {
	return id.Hex(), nil
}

// Scan implements sql.Scanner for SQL deserialization.
func (id *BlobID) Scan(value interface{}) error {
	if value == nil {
		return fmt.Errorf("cannot scan nil into BlobID")
	}

	var hexStr string
	switch v := value.(type) {
	case string:
		hexStr = v
	case []byte:
		hexStr = string(v)
	default:
		return fmt.Errorf("cannot scan type %T into BlobID", value)
	}

	parsed, err := ParseBlobID(hexStr)
	if err != nil {
		return err
	}

	*id = parsed
	return nil
}
