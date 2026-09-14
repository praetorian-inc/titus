package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const defaultAnthropicURL = "https://api.anthropic.com"

type anthropicClient struct {
	apiKey  string
	model   string
	baseURL string
	client  *http.Client
	retries int
}

func newAnthropicClient(apiKey, model string, cfg clientConfig) (Client, error) {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultAnthropicURL
	}
	return &anthropicClient{
		apiKey:  apiKey,
		model:   model,
		baseURL: baseURL,
		client:  &http.Client{Timeout: cfg.Timeout},
		retries: cfg.MaxRetries,
	}, nil
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Model string `json:"model"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// retryableError marks errors from doRequest that should trigger a retry
// (e.g. HTTP 429/529) rather than being returned immediately to the caller.
type retryableError struct {
	err error
}

func (r *retryableError) Error() string { return r.err.Error() }
func (r *retryableError) Unwrap() error { return r.err }

func (c *anthropicClient) Complete(ctx context.Context, req *Request) (*Response, error) {
	msgs := make([]anthropicMessage, len(req.Messages))
	for i, m := range req.Messages {
		msgs[i] = anthropicMessage{Role: m.Role, Content: m.Content}
	}

	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 256
	}

	body := anthropicRequest{
		Model:     c.model,
		MaxTokens: maxTokens,
		System:    req.System,
		Messages:  msgs,
	}

	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		resp, err := c.doRequest(ctx, body)
		if err == nil {
			return resp, nil
		}
		lastErr = err

		if !isRetryable(err) {
			return nil, lastErr
		}

		// If context is already done, stop retrying.
		if ctx.Err() != nil {
			return nil, lastErr
		}
	}
	return nil, lastErr
}

func isRetryable(err error) bool {
	var re *retryableError
	for e := err; e != nil; {
		if r, ok := e.(*retryableError); ok {
			re = r
			break
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			break
		}
		e = u.Unwrap()
	}
	return re != nil
}

func (c *anthropicClient) doRequest(ctx context.Context, body anthropicRequest) (*Response, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/messages", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 529 {
		delay := time.Second
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, err := strconv.Atoi(ra); err == nil && secs >= 0 {
				delay = time.Duration(secs) * time.Second
				if delay > 30*time.Second {
					delay = 30 * time.Second
				}
			}
		}
		if delay > 0 {
			t := time.NewTimer(delay)
			defer t.Stop()
			select {
			case <-t.C:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return nil, &retryableError{err: fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var ar anthropicResponse
	if err := json.Unmarshal(respBody, &ar); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	var content string
	for _, part := range ar.Content {
		if part.Type == "text" {
			content = part.Text
			break
		}
	}

	return &Response{
		Content: content,
		Model:   ar.Model,
		Usage: Usage{
			InputTokens:  ar.Usage.InputTokens,
			OutputTokens: ar.Usage.OutputTokens,
		},
	}, nil
}
