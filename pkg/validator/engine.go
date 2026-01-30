// pkg/validator/engine.go
package validator

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Engine coordinates validation across multiple validators with caching.
type Engine struct {
	validators []Validator
	cache      *ValidationCache
	workers    int
	sem        chan struct{} // semaphore for bounded concurrency
}

// NewEngine creates a validation engine with registered validators.
func NewEngine(workers int, validators ...Validator) *Engine {
	if workers <= 0 {
		workers = 4
	}
	return &Engine{
		validators: validators,
		cache:      NewValidationCache(),
		workers:    workers,
		sem:        make(chan struct{}, workers),
	}
}

// ValidateMatch validates a match using the appropriate validator.
// Checks cache first, then finds and invokes matching validator.
func (e *Engine) ValidateMatch(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract secret value from match
	secret := extractSecret(match)
	if len(secret) == 0 {
		return types.NewValidationResult(types.StatusUndetermined, 0, "no secret value found in match"), nil
	}

	// Check cache first
	if cached := e.cache.Get(secret); cached != nil {
		return cached, nil
	}

	// Find appropriate validator
	for _, v := range e.validators {
		if v.CanValidate(match.RuleID) {
			result, err := v.Validate(ctx, match)
			if err != nil {
				return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("validation error: %v", err)), nil
			}
			e.cache.Set(secret, result)
			return result, nil
		}
	}

	// No validator found
	return types.NewValidationResult(types.StatusUndetermined, 0, "no validator available for this secret type"), nil
}

// extractSecret extracts the secret value from a match.
// Prefers first capture group, falls back to matching snippet.
func extractSecret(match *types.Match) []byte {
	if len(match.Groups) > 0 && len(match.Groups[0]) > 0 {
		return match.Groups[0]
	}
	return match.Snippet.Matching
}
