package shared

import (
	"context"
	"time"

	"github.com/projectdiscovery/ratelimit"
)

// RateLimiter wraps token bucket rate limiting.
type RateLimiter struct {
	limiter *ratelimit.Limiter
}

// NewRateLimiter creates a rate limiter.
// If rate is 0, returns an unlimited limiter.
func NewRateLimiter(ratePerSecond uint) *RateLimiter {
	if ratePerSecond == 0 {
		return &RateLimiter{
			limiter: ratelimit.NewUnlimited(context.Background()),
		}
	}
	return &RateLimiter{
		limiter: ratelimit.New(context.Background(), ratePerSecond, time.Second),
	}
}

// NewRateLimiterPerMinute creates a per-minute rate limiter.
func NewRateLimiterPerMinute(rate uint) *RateLimiter {
	return &RateLimiter{
		limiter: ratelimit.New(context.Background(), rate, time.Minute),
	}
}

// Take blocks until a token is available.
func (r *RateLimiter) Take() {
	r.limiter.Take()
}

// Stop stops the rate limiter.
func (r *RateLimiter) Stop() {
	r.limiter.Stop()
}
