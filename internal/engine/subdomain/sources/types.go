package sources

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/0x3n0/lesgo/internal/shared"
)

// Source is the interface that all passive sources implement.
type Source interface {
	Name() string
	NeedsKey() bool
	Query(ctx context.Context, domain string, session *Session) (chan string, error)
}

// Session provides shared infrastructure for sources.
type Session struct {
	Client      *HTTPClient
	RateLimiter *shared.RateLimiter
	Timeout     time.Duration
}

// HTTPClient is a simple HTTP client for sources.
type HTTPClient struct {
	timeout time.Duration
}

// NewHTTPClient creates a new HTTP client.
func NewHTTPClient(timeout time.Duration) *HTTPClient {
	return &HTTPClient{timeout: timeout}
}

// Get performs a simple GET request with proper headers.
func (c *HTTPClient) Get(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	client := &http.Client{Timeout: c.timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
