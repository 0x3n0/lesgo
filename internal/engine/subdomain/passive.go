package subdomain

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"

	"github.com/0x3n0/lesgo/internal/engine/subdomain/sources"
)

// Engine performs passive subdomain discovery.
type Engine struct {
	opts    Options
	srcs    []sources.Source
	session *sources.Session
}

// New creates a new subdomain engine.
func New(opts Options) (*Engine, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 30
	}

	session := &sources.Session{
		Client:      sources.NewHTTPClient(time.Duration(opts.Timeout) * time.Second),
		RateLimiter: opts.RateLimiter,
		Timeout:     time.Duration(opts.Timeout) * time.Second,
	}

	// Register all available sources
	allSources := []sources.Source{
		sources.NewCrtsh(),
		sources.NewAlienVault(),
		sources.NewURLScan(),
		sources.NewCertSpotter(),
		sources.NewHackerTarget(),
		sources.NewThreatCrowd(),
		sources.NewWaybackArchive(),
		sources.NewCommonCrawl(),
		sources.NewAnubis(),
		sources.NewBufferOver(),
		sources.NewDNSDumpster(),
		sources.NewRapidDNS(),
		sources.NewRiddler(),
		sources.NewSiteDossier(),
		sources.NewThreatMiner(),
	}

	// Filter sources based on options
	var selectedSources []sources.Source

	specifiedSources := make(map[string]struct{})
	for _, s := range opts.Sources {
		specifiedSources[strings.ToLower(s)] = struct{}{}
	}

	excludedSources := make(map[string]struct{})
	for _, s := range opts.ExcludeSources {
		excludedSources[strings.ToLower(s)] = struct{}{}
	}

	for _, source := range allSources {
		name := strings.ToLower(source.Name())

		if _, ok := excludedSources[name]; ok {
			continue
		}

		if len(specifiedSources) > 0 {
			if _, ok := specifiedSources[name]; ok {
				selectedSources = append(selectedSources, source)
			}
		} else if opts.AllSources {
			selectedSources = append(selectedSources, source)
		} else {
			if !source.NeedsKey() {
				selectedSources = append(selectedSources, source)
			}
		}
	}

	return &Engine{
		opts:    opts,
		srcs:    selectedSources,
		session: session,
	}, nil
}

// Run performs subdomain discovery for a domain.
// Returns discovered subdomains and optionally a map of subdomain -> sources.
func (e *Engine) Run(ctx context.Context, domain string) ([]string, map[string][]string, error) {
	return e.runWithRecursion(ctx, domain)
}

// runWithRecursion performs discovery and optionally recursive discovery.
func (e *Engine) runWithRecursion(ctx context.Context, domain string) ([]string, map[string][]string, error) {
	if len(e.srcs) == 0 {
		return nil, nil, fmt.Errorf("no sources configured")
	}

	domain = normalizeDomain(domain)

	if e.opts.MaxEnumTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(e.opts.MaxEnumTime)*time.Minute)
		defer cancel()
	}

	// Initial discovery pass
	allResults, err := e.runDiscovery(ctx, domain)
	if err != nil {
		return nil, nil, err
	}

	buildFinal := func(results map[string]map[string]struct{}) ([]string, map[string][]string) {
		matchSet := makeSet(e.opts.MatchSubdomain)
		filterSet := makeSet(e.opts.FilterSubdomain)
		var final []string
		sourceMap := make(map[string][]string)
		for sub, srcs := range results {
			if e.opts.ExcludeIPs && isIPLiteral(sub) {
				continue
			}
			if len(matchSet) > 0 && !matchesAny(sub, matchSet) {
				continue
			}
			if len(filterSet) > 0 && matchesAny(sub, filterSet) {
				continue
			}
			final = append(final, sub)
			for s := range srcs {
				sourceMap[sub] = append(sourceMap[sub], s)
			}
		}
		return final, sourceMap
	}

	final, sourceMap := buildFinal(allResults)

	// Recursive subdomain discovery on newly discovered parent zones
	if e.opts.OnlyRecursive && len(final) > 0 {
		parentSeen := make(map[string]struct{})
		var parents []string
		for _, sub := range final {
			parent := extractParentDomain(sub, domain)
			if parent != "" && parent != domain {
				if _, ok := parentSeen[parent]; !ok {
					parentSeen[parent] = struct{}{}
					parents = append(parents, parent)
				}
			}
		}

		if len(parents) > 0 {
			gologger.Info().Msgf("Recursive discovery on %d parent domains\n", len(parents))
			var recMu sync.Mutex
			var recWg sync.WaitGroup
			for _, parent := range parents {
				recWg.Add(1)
				go func(p string) {
					defer recWg.Done()
					recResults, err := e.runDiscovery(ctx, p)
					if err != nil {
						return
					}
					recMu.Lock()
					for sub, srcs := range recResults {
						if _, ok := allResults[sub]; !ok {
							allResults[sub] = make(map[string]struct{})
						}
						for s := range srcs {
							allResults[sub][s] = struct{}{}
						}
					}
					recMu.Unlock()
				}(parent)
			}
			recWg.Wait()
			final, sourceMap = buildFinal(allResults)
		}
	}

	gologger.Info().Msgf("Found %d subdomains for %s\n", len(final), domain)
	return final, sourceMap, nil
}

// runDiscovery queries all sources for the given domain and returns raw results.
func (e *Engine) runDiscovery(ctx context.Context, domain string) (map[string]map[string]struct{}, error) {
	domain = normalizeDomain(domain)

	gologger.Info().Msgf("Discovering subdomains for %s using %d sources\n", domain, len(e.srcs))

	type namedSub struct {
		sub    string
		source string
	}
	raw := make(chan namedSub, 10000)
	allResults := make(map[string]map[string]struct{})
	var mu sync.Mutex

	var wg sync.WaitGroup
	for _, source := range e.srcs {
		wg.Add(1)
		go func(s sources.Source) {
			defer wg.Done()
			gologger.Verbose().Msgf("Querying source: %s\n", s.Name())

			subs, err := s.Query(ctx, domain, e.session)
			if err != nil {
				gologger.Debug().Msgf("Source %s error: %v\n", s.Name(), err)
				return
			}

			for sub := range subs {
				sub = strings.TrimSpace(sub)
				sub = strings.ToLower(sub)
				if sub == "" {
					continue
				}
				select {
				case raw <- namedSub{sub, s.Name()}:
				case <-ctx.Done():
					return
				}
			}
		}(source)
	}

	go func() {
		wg.Wait()
		close(raw)
	}()

	for ns := range raw {
		mu.Lock()
		if _, ok := allResults[ns.sub]; !ok {
			allResults[ns.sub] = make(map[string]struct{})
		}
		allResults[ns.sub][ns.source] = struct{}{}
		mu.Unlock()
	}

	return allResults, nil
}

// normalizeDomain strips scheme, path, and trailing slash from a domain string.
func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	return domain
}

// extractParentDomain returns the immediate parent domain of sub that
// is still deeper than the original root. For sub="x.y.example.com"
// and root="example.com", returns "y.example.com". For sub="y.example.com"
// and root="example.com", returns "" (no intermediate parent).
func extractParentDomain(sub, root string) string {
	sub = strings.TrimSuffix(sub, ".")
	root = strings.TrimSuffix(root, ".")
	if sub == root || !strings.HasSuffix(sub, "."+root) {
		return ""
	}
	// Count extra labels
	subLabels := strings.Split(sub, ".")
	rootLabels := strings.Split(root, ".")
	extra := len(subLabels) - len(rootLabels)
	if extra <= 1 {
		return "" // no intermediate parent to recurse into
	}
	// Return the immediate parent: remove the first label
	// e.g. x.y.example.com -> y.example.com
	return strings.Join(subLabels[1:], ".")
}

// makeSet converts a string slice to a set for O(1) lookups.
func makeSet(items []string) map[string]struct{} {
	s := make(map[string]struct{})
	for _, item := range items {
		s[strings.ToLower(item)] = struct{}{}
	}
	return s
}

// matchesAny checks if subdomain matches any item in the set.
func matchesAny(sub string, items map[string]struct{}) bool {
	sub = strings.ToLower(strings.TrimSpace(sub))
	if _, ok := items[sub]; ok {
		return true
	}
	// Also check if sub ends with .item (wildcard match)
	for item := range items {
		if strings.HasSuffix(sub, "."+item) || sub == item {
			return true
		}
	}
	return false
}

// isIPLiteral returns true if the subdomain is an IP address.
func isIPLiteral(sub string) bool {
	return net.ParseIP(sub) != nil
}

// ListSources returns the names of all available sources.
func (e *Engine) ListSources() []string {
	allSources := []sources.Source{
		sources.NewCrtsh(),
		sources.NewAlienVault(),
		sources.NewURLScan(),
		sources.NewCertSpotter(),
		sources.NewHackerTarget(),
		sources.NewThreatCrowd(),
		sources.NewWaybackArchive(),
		sources.NewCommonCrawl(),
		sources.NewAnubis(),
		sources.NewBufferOver(),
		sources.NewDNSDumpster(),
		sources.NewRapidDNS(),
		sources.NewRiddler(),
		sources.NewSiteDossier(),
		sources.NewThreatMiner(),
	}

	var names []string
	for _, s := range allSources {
		key := ""
		if s.NeedsKey() {
			key = " *"
		}
		names = append(names, s.Name()+key)
	}
	return names
}

// Close cleans up resources.
func (e *Engine) Close() {
	// Nothing to clean up
}
