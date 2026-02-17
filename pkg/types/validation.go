// pkg/types/validation.go
package types

import "time"

// ValidationStatus represents the outcome of secret validation.
type ValidationStatus string

const (
	StatusValid        ValidationStatus = "valid"
	StatusInvalid      ValidationStatus = "invalid"
	StatusUndetermined ValidationStatus = "undetermined"
)

// ValidationResult represents the outcome of validating a secret.
type ValidationResult struct {
	Status      ValidationStatus  `json:"status"`
	Confidence  float64           `json:"confidence"`
	Message     string            `json:"message"`
	ValidatedAt time.Time         `json:"validated_at"`
	Details     map[string]string `json:"details,omitempty"` // Extended validation details
}

// NewValidationResult creates a result with current timestamp.
func NewValidationResult(status ValidationStatus, confidence float64, message string) *ValidationResult {
	return &ValidationResult{
		Status:      status,
		Confidence:  confidence,
		Message:     message,
		ValidatedAt: time.Now(),
		Details:     make(map[string]string),
	}
}
