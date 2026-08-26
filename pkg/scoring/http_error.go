package scoring

import (
	"errors"
	"fmt"
	"net/http"
)

// httpModifierError categories match the design doc taxonomy.
// The engine uses these to decide retry vs skip behavior.

var (
	ErrModifierTimeout     = errors.New("modifier http: deadline exceeded")
	ErrModifierRateLimit   = errors.New("modifier http: rate limited (429)")
	ErrModifierServerError = errors.New("modifier http: server error (5xx)")
	ErrModifierNetwork     = errors.New("modifier http: network error")
	ErrModifierParseError  = errors.New("modifier http: response parse error")

	// ErrConditionNotApplicable marks a fires_when condition that could not be
	// evaluated against the response it received -- typically a json_path leaf
	// looking for a field that an error body does not carry. It is only used for
	// non-success responses, where it is expected rather than noteworthy: a dead
	// credential returns an error body no scope condition was ever going to match.
	// The engine skips the warning for this error alone. The same failure against
	// a 2xx response stays a warning, because there it usually means the scorer
	// names a field that does not exist.
	ErrConditionNotApplicable = errors.New("modifier condition not applicable to response")
)

// classifyHTTPError maps an HTTP status code (or nil for network err) to a
// sentinel error. Callers use errors.Is to check type.
func classifyHTTPError(statusCode int, networkErr error) error {
	if networkErr != nil {
		return fmt.Errorf("%w: %v", ErrModifierNetwork, networkErr)
	}
	switch {
	case statusCode == http.StatusTooManyRequests:
		return ErrModifierRateLimit
	case statusCode >= 500 && statusCode < 600:
		return ErrModifierServerError
	default:
		return nil // not an error
	}
}

// HTTPModifierStats tracks aggregate HTTP modifier outcomes per scan.
// Embedded in Engine; reset to zero at engine construction.
type HTTPModifierStats struct {
	Timeouts      int
	RateLimited   int
	NetworkErrors int
	ServerErrors  int
}

// Any reports whether any modifier errors occurred during the scan.
func (s HTTPModifierStats) Any() bool {
	return s.Timeouts > 0 || s.RateLimited > 0 || s.NetworkErrors > 0 || s.ServerErrors > 0
}

