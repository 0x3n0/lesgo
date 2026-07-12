package subdomain

import "github.com/0x3n0/lesgo/internal/shared"

// Options configures the subdomain engine.
type Options struct {
	Sources         []string
	ExcludeSources  []string
	AllSources      bool
	FastSources     bool
	OnlyRecursive   bool
	Timeout         int
	MaxEnumTime     int
	Resolvers       []string
	RateLimiter     *shared.RateLimiter
	CaptureSources  bool
	ExcludeIPs      bool
	MatchSubdomain  []string
	FilterSubdomain []string
	ActiveSubdomain bool
}

// Result holds a discovered subdomain with optional source attribution.
type Result struct {
	Name    string
	Sources []string
}
