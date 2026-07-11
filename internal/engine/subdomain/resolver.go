package subdomain

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
)

// Resolver validates discovered subdomains by resolving them via DNS.
type Resolver struct {
	resolvers []string
	timeout   time.Duration
}

// NewResolver creates a DNS resolver for validation.
func NewResolver(customResolvers []string, timeout time.Duration) *Resolver {
	r := &Resolver{
		timeout: timeout,
	}

	if len(customResolvers) > 0 {
		for _, res := range customResolvers {
			r.resolvers = append(r.resolvers, ensurePort53(res))
		}
	} else {
		// Use system resolvers
		r.resolvers = []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"}
	}

	return r
}

// Resolve validates subdomains by resolving their A records.
func (r *Resolver) Resolve(ctx context.Context, subs []string) []string {
	var valid []string
	var mu sync.Mutex

	sem := make(chan struct{}, 50) // 50 concurrent resolvers
	var wg sync.WaitGroup

	for _, sub := range subs {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(s string) {
			defer wg.Done()
			defer func() { <-sem }()

			if r.resolveHost(s) {
				mu.Lock()
				valid = append(valid, s)
				mu.Unlock()
			}
		}(sub)
	}

	wg.Wait()
	return valid
}

func (r *Resolver) resolveHost(host string) bool {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: r.timeout}
			// Use first resolver
			return d.DialContext(ctx, "udp", r.resolvers[0])
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	ips, err := resolver.LookupHost(ctx, host)
	if err != nil {
		gologger.Debug().Msgf("Resolve failed for %s: %v\n", host, err)
		return false
	}

	return len(ips) > 0
}

func ensurePort53(server string) string {
	if _, _, err := net.SplitHostPort(server); err != nil {
		return net.JoinHostPort(server, "53")
	}
	return server
}
