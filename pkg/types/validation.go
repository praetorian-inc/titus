// pkg/types/validation.go
package types

// ValidationStatus represents the outcome of secret validation.
type ValidationStatus string

const (
	StatusValid        ValidationStatus = "valid"
	StatusInvalid      ValidationStatus = "invalid"
	StatusUndetermined ValidationStatus = "undetermined"
)
