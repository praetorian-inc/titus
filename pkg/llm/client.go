package llm

import (
	"context"
	"fmt"
	"time"
)

type Client interface {
	Complete(ctx context.Context, req *Request) (*Response, error)
}

type Request struct {
	System    string
	Messages  []Message
	MaxTokens int
}

type Message struct {
	Role    string
	Content string
}

type Response struct {
	Content string
	Model   string
	Usage   Usage
}

type Usage struct {
	InputTokens  int
	OutputTokens int
}

type Option func(*clientConfig)

type clientConfig struct {
	Timeout    time.Duration
	MaxRetries int
	BaseURL    string
}

func WithTimeout(d time.Duration) Option {
	return func(c *clientConfig) { c.Timeout = d }
}

func WithMaxRetries(n int) Option {
	return func(c *clientConfig) { c.MaxRetries = n }
}

func WithBaseURL(url string) Option {
	return func(c *clientConfig) { c.BaseURL = url }
}

func NewClient(provider, apiKey, model string, opts ...Option) (Client, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}

	cfg := clientConfig{
		Timeout:    15 * time.Second,
		MaxRetries: 1,
	}
	for _, o := range opts {
		o(&cfg)
	}

	switch provider {
	case "anthropic":
		return newAnthropicClient(apiKey, model, cfg)
	default:
		return nil, fmt.Errorf("unsupported provider: %q", provider)
	}
}
