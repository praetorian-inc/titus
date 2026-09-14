package validator

import (
	"golang.org/x/time/rate"
)

// SetRateLimit configures the engine to throttle validation requests to at
// most reqsPerSec requests per second. Passing a value <= 0 disables rate
// limiting (the default).
func (e *Engine) SetRateLimit(reqsPerSec float64) {
	if reqsPerSec <= 0 {
		e.limiter = nil
		return
	}
	e.limiter = rate.NewLimiter(rate.Limit(reqsPerSec), 1)
}

// SetBackoff configures the engine's adaptive backoff controller and wraps
// registered validators' HTTP clients so 429/5xx/connection errors retry
// through RetryHTTPClient. Passing nil disables backoff wrapping.
func (e *Engine) SetBackoff(bc *BackoffController) {
	e.backoff = bc
	if bc == nil {
		return
	}
	for _, v := range e.validators {
		wrapValidatorHTTP(v, bc)
	}
}

func wrapValidatorHTTP(v Validator, bc *BackoffController) {
	switch tv := v.(type) {
	case *HTTPValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *JenkinsValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *PubNubValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *TrueNASValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *CypressValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *MattermostValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *KeenIOValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *ShopifyValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *BranchIOValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *HelpScoutValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *ZendeskValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *GitHubAppTokenValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *WPEngineValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *ConfluentValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *RabbitMQValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *TwilioValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *BrowserStackValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *SentryDSNValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *SauceLabsValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *AtlassianValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	case *AmplitudeValidator:
		tv.client = WrapHTTPClient(tv.client, bc)
	}
}
