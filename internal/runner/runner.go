package runner

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/clistats"
	"github.com/projectdiscovery/gologger"

	"github.com/0x3n0/lesgo/internal/engine/dns"
	"github.com/0x3n0/lesgo/internal/engine/http"
	"github.com/0x3n0/lesgo/internal/engine/subdomain"
	"github.com/0x3n0/lesgo/internal/engine/takeover"
	"github.com/0x3n0/lesgo/internal/shared"
)

// Runner orchestrates the entire recon process.
type Runner struct {
	options         *Options
	dnsEngine       *dns.Engine
	httpEngine      *http.Engine
	subdomainEngine *subdomain.Engine
	takeoverEngine  *takeover.Engine
	outputWriter    *OutputWriter
	dedup           *shared.Dedup
	stats           clistats.StatisticsClient
	rateLimiter     *shared.RateLimiter
	interruptCh     chan struct{}
	seenDups        map[string]bool
	dupsMu          sync.Mutex
}

// New creates a new Runner.
func New(opts *Options) (*Runner, error) {
	r := &Runner{
		options:     opts,
		interruptCh: make(chan struct{}),
	}

	// Initialize dedup
	var err error
	r.dedup, err = shared.NewDedup()
	if err != nil {
		return nil, fmt.Errorf("could not create dedup: %w", err)
	}

	// Initialize output writer
	r.outputWriter, err = NewOutputWriter(opts)
	if err != nil {
		return nil, fmt.Errorf("could not create output writer: %w", err)
	}

	// Initialize rate limiter
	if opts.RateLimitMinute > 0 {
		r.rateLimiter = shared.NewRateLimiterPerMinute(uint(opts.RateLimitMinute))
	} else {
		r.rateLimiter = shared.NewRateLimiter(uint(opts.RateLimit))
	}

	// Initialize statistics
	if opts.ShowStats {
		r.stats, err = clistats.New()
		if err != nil {
			return nil, fmt.Errorf("could not create stats: %w", err)
		}
	}

	// Initialize DNS engine
	if opts.RunDNS() {
		dnsOpts := dns.Options{
			RecordTypes:        opts.DNSRecordTypes(),
			Resolvers:          opts.Resolvers,
			Retries:            opts.DNSRetry,
			Timeout:            opts.DNSTimeout,
			HostsFile:          opts.HostsFile,
			Trace:              opts.DNSTrace,
			TraceMaxRecursion:  opts.TraceMaxRecursion,
			WildcardThreshold:  opts.WildcardThreshold,
			WildcardDomain:     opts.WildcardDomain,
			Raw:                opts.DNSRaw,
			Resp:               opts.Resp,
			RespOnly:           opts.RespOnly,
			RCode:              opts.RCode,
			ResponseTypeFilter: opts.RespTypeFilter,
			CDN:               opts.CDN || opts.OutputCDN == "true",
			ASN:               opts.ASN,
			RateLimiter:       r.rateLimiter,
		}
		r.dnsEngine, err = dns.New(dnsOpts)
		if err != nil {
			return nil, fmt.Errorf("could not create DNS engine: %w", err)
		}
	}

	// Initialize HTTP engine
	if opts.RunHTTP() {
		httpOpts := http.Options{
			Threads:             opts.Threads,
			Timeout:             opts.HTTPTimeout,
			Retries:             opts.HTTPRetries,
			Proxy:               opts.GetProxy(),
			CustomHeaders:       opts.GetCustomHeadersMap(),
			RandomAgent:         opts.RandomAgent,
			AutoReferer:         opts.AutoReferer,
			Unsafe:              opts.Unsafe,
			NoFallback:          opts.NoFallback,
			NoFallbackScheme:    opts.NoFallbackScheme,
			Favicon:             opts.Favicon,
		JARM:                opts.JARM,
			TLSGrab:             opts.TLSGrab,
			TLSProbe:            opts.TLSProbe,
			CSPProbe:            opts.CSPProbe,
			VHost:               opts.VHost,
			Pipeline:            opts.Pipeline,
			HTTP2Probe:          opts.HTTP2Probe,
			SniName:             opts.SniName,
			FollowRedirects:     opts.FollowRedirects,
			MaxRedirects:        opts.MaxRedirects,
			FollowHostRedirects: opts.FollowHostRedirects,
			NoDecode:            opts.NoDecode,
			LeaveDefaultPorts:   opts.LeaveDefaultPorts,
			RequestMethods:      opts.RequestMethods,
			RequestBody:         opts.RequestBody,
			RequestPaths:        opts.RequestPaths,
			CustomPorts:         opts.CustomPorts,
			Delay:               opts.Delay,
			RateLimiter:         r.rateLimiter,
			BodyPreviewSize:     opts.BodyPreview,
			OutputCDN:           opts.OutputCDN,
			Hashes:              opts.Hashes,
			ExtractRegex:        opts.ExtractRegex,
			ExtractPreset:       opts.ExtractPreset,
			Probe:               opts.ProbeStatus,
		}
		r.httpEngine, err = http.New(httpOpts)
		if err != nil {
			return nil, fmt.Errorf("could not create HTTP engine: %w", err)
		}
	}

	// Initialize subdomain engine
	if opts.RunSubdomain() {
		sdOpts := subdomain.Options{
			Sources:         opts.Sources,
			ExcludeSources:  opts.ExcludeSources,
			AllSources:      opts.AllSources,
			FastSources:     opts.FastSources,
			OnlyRecursive:   opts.OnlyRecursive,
			Timeout:         opts.SubdomainTimeout,
			MaxEnumTime:     opts.MaxEnumTime,
			Resolvers:       opts.Resolvers,
			RateLimiter:     r.rateLimiter,
			CaptureSources:  opts.CaptureSources,
			ExcludeIPs:      opts.ExcludeIPs,
			MatchSubdomain:  opts.MatchSubdomain,
			FilterSubdomain: opts.FilterSubdomain,
			ActiveSubdomain: opts.ActiveSubdomain,
		}
		r.subdomainEngine, err = subdomain.New(sdOpts)
		if err != nil {
			return nil, fmt.Errorf("could not create subdomain engine: %w", err)
		}
	}

	// Initialize takeover engine
	if opts.RunTakeover() {
		tkOpts := takeover.Options{
			Threads:     opts.Threads,
			Timeout:     opts.HTTPTimeout,
			AllServices: opts.TakeoverAll || opts.Takeover,
			CheckCNAME:  opts.TakeoverCheckCNAME || opts.TakeoverAll || opts.Takeover,
			CheckNS:     opts.TakeoverCheckNS || opts.TakeoverAll || opts.Takeover,
			CheckHTTP:   opts.TakeoverCheckHTTP || opts.TakeoverAll || opts.Takeover,
			DNSServers:  toStringSlice(opts.Resolvers),
		}
		r.takeoverEngine, err = takeover.New(tkOpts)
		if err != nil {
			return nil, fmt.Errorf("could not create takeover engine: %w", err)
		}
	}

	return r, nil
}

// Interrupt signals the runner to stop.
func (r *Runner) Interrupt() {
	select {
	case <-r.interruptCh:
	default:
		close(r.interruptCh)
	}
}

// IsInterrupted reports whether the runner was interrupted.
func (r *Runner) IsInterrupted() bool {
	select {
	case <-r.interruptCh:
		return true
	default:
		return false
	}
}

// Run starts the enumeration based on selected mode.
func (r *Runner) Run() error {
	// Set up signal handling
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		gologger.Info().Msg("CTRL+C pressed: Exiting\n")
		r.Interrupt()
		<-c
		gologger.Info().Msg("Forcing exit\n")
		os.Exit(1)
	}()

	// Start statistics
	r.startStats()

	// Collect input targets
	targets := r.collectTargets()

	// Run selected engines
	if r.options.RunSubdomain() && r.subdomainEngine != nil && len(targets) > 0 {
		gologger.Info().Msgf("[Phase] Subdomain Discovery...")
		discoveryTargets := append([]string(nil), targets...)
		for _, domain := range discoveryTargets {
			subs, sourceMap, err := r.subdomainEngine.Run(context.Background(), domain)
			if err == nil {
				for _, sub := range subs {
					// Active subdomain check: resolve and skip if no IPs
					if r.options.ActiveSubdomain {
						ips, lookupErr := net.LookupHost(sub)
						if lookupErr != nil || len(ips) == 0 {
							continue
						}
					}

					if !r.options.SkipDedupe && r.dedup != nil {
						if !r.dedup.TestAndSet(sub) {
							continue
						}
					}
					targets = append(targets, sub)
					// Write subdomain result to output
					result := &Result{
						Timestamp: time.Now(),
						Input:     domain,
						Host:      sub,
						URL:       sub,
					}
					result.SetStr(sub)

					// Include source attribution if -cs is set
					if r.options.CaptureSources {
						if srcs, ok := sourceMap[sub]; ok {
							result.Extracts = map[string][]string{"source": srcs}
						}
					}

					// When HTTP probe engine will run, skip plain subdomain output
					// to avoid duplicate results — the HTTP engine will emit enriched
					// output (tech-detect, status-code, etc.) for each subdomain.
					if !r.options.RunHTTP() {
						if !r.options.HasMatcherFilter() || r.shouldInclude(result) {
							r.outputWriter.Write(result)
						}
					}
				}
			}
		}
	}

	if r.options.RunDNS() && r.dnsEngine != nil {
		gologger.Info().Msgf("Running DNS engine on %d targets", len(targets))
		r.runDNS(targets)
	}

	if r.options.RunHTTP() && r.httpEngine != nil {
		gologger.Info().Msgf("Running HTTP engine on %d targets", len(targets))
		r.runHTTP(targets)
	}

	if r.options.RunTakeover() && r.takeoverEngine != nil {
		r.runTakeover(targets)
	}

	return nil
}

func (r *Runner) collectTargets() []string {
	var allTargets []string
	seen := make(map[string]struct{})

	add := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" {
			return
		}
		if r.dedup != nil && !r.options.SkipDedupe {
			if !r.dedup.TestAndSet(t) {
				return
			}
		} else {
			if _, ok := seen[t]; ok {
				return
			}
			seen[t] = struct{}{}
		}
		allTargets = append(allTargets, t)
	}

	// Domains from -d flag
	for _, d := range r.options.Domains {
		add(d)
	}

	// Targets from -u flag
	for _, u := range r.options.InputTargets {
		add(u)
	}

	// Input file
	if r.options.InputFile != "" {
		ch, err := shared.ReadTargets(r.options.InputFile, nil, "")
		if err == nil {
			for t := range ch {
				add(t)
			}
		}
	}

	// Stdin
	if r.options.Stdin {
		ch, _ := shared.ReadTargets("", nil, "")
		for t := range ch {
			add(t)
		}
	}

	return allTargets
}

func (r *Runner) runDNS(targets []string) error {
	var wg sync.WaitGroup
	sem := make(chan struct{}, r.options.Threads)
	output := make(chan *Result, 1000)

	// Output worker
	go func() {
		for result := range output {
			if r.options.HasMatcherFilter() && !r.shouldInclude(result) {
				continue
			}
			r.outputWriter.Write(result)
		}
	}()

	// Pre-detect wildcard IPs if wildcard domain is set
	var wildcardIPs []string
	if r.options.WildcardDomain != "" && r.dnsEngine != nil {
		wildcardIPs = r.dnsEngine.DetectWildcardIPs(r.options.WildcardDomain)
		if len(wildcardIPs) > 0 {
			gologger.Debug().Msgf("Detected wildcard IPs: %v", wildcardIPs)
		}
	}

	for _, target := range targets {
		if r.IsInterrupted() {
			break
		}

		// Wordlist + domain bruteforce
		if r.options.WordList != "" {
			words := r.readWordlist()
			for _, word := range words {
				for _, domain := range r.options.Domains {
					host := strings.TrimSpace(word) + "." + domain
					wg.Add(1)
					sem <- struct{}{}
					go func(h string) {
						defer wg.Done()
						defer func() { <-sem }()
						result := r.dnsEngine.Query(h)
						if result != nil {
							// Wildcard filtering
							if len(wildcardIPs) > 0 && isWildcardResult(result, wildcardIPs) {
								return
							}
							// DNS trace
							if r.options.DNSTrace {
								if td, err := r.dnsEngine.Trace(h); err == nil {
									result.TraceData = td
								}
							}
							if cr := r.convertDNSResult(result); cr != nil {
								output <- cr
							}
						}
					}(host)
				}
			}
		} else {
			wg.Add(1)
			sem <- struct{}{}
			go func(t string) {
				defer wg.Done()
				defer func() { <-sem }()
				result := r.dnsEngine.Query(t)
				if result != nil {
					// Wildcard filtering
					if len(wildcardIPs) > 0 && isWildcardResult(result, wildcardIPs) {
						return
					}
					// DNS trace
					if r.options.DNSTrace {
						if td, err := r.dnsEngine.Trace(t); err == nil {
							result.TraceData = td
						}
					}
					if cr := r.convertDNSResult(result); cr != nil {
						output <- cr
					}
				}
			}(target)
		}
	}

	wg.Wait()

	// AXFR zone transfer attempt
	if r.options.AXFR {
		for _, target := range targets {
			if r.IsInterrupted() {
				break
			}
			result, err := r.dnsEngine.AXFR(target)
			if err != nil {
				failedResult := &Result{
					Timestamp: time.Now(),
					Input:     target,
					Host:      target,
					URL:       target,
					ErrorStr:  fmt.Sprintf("AXFR failed: %v", err),
					Failed:    true,
				}
				failedResult.SetStr(fmt.Sprintf("%s [AXFR failed: %v]", target, err))
				output <- failedResult
				continue
			}
			if result != nil {
				axfrResult := &Result{
					Timestamp: time.Now(),
					Input:     target,
					Host:      target,
					URL:       target,
					A:         result.A,
					AAAA:      result.AAAA,
					CNAME:     result.CNAME,
					MX:        result.MX,
					NS:        result.NS,
					TXT:       result.TXT,
					SOA:       result.SOA,
					PTR:       result.PTR,
					CAA:       result.CAA,
					SRV:       result.SRV,
				}
				if len(result.A)+len(result.AAAA)+len(result.CNAME)+len(result.MX)+
					len(result.NS)+len(result.TXT)+len(result.SOA)+len(result.PTR)+
					len(result.CAA)+len(result.SRV) > 0 {
					axfrResult.IP = strings.Join(result.A, ",")
					var parts []string
					if len(result.A) > 0 {
						parts = append(parts, strings.Join(result.A, ", "))
					}
					if len(result.AAAA) > 0 {
						parts = append(parts, strings.Join(result.AAAA, ", "))
					}
					if len(result.CNAME) > 0 {
						parts = append(parts, "cname: "+strings.Join(result.CNAME, ", "))
					}
					if len(result.MX) > 0 {
						parts = append(parts, "mx: "+strings.Join(result.MX, ", "))
					}
					if len(result.NS) > 0 {
						parts = append(parts, "ns: "+strings.Join(result.NS, ", "))
					}
					if len(result.TXT) > 0 {
						parts = append(parts, "txt: "+strings.Join(result.TXT, ", "))
					}
					axfrResult.SetStr(fmt.Sprintf("%s [%s]", target, strings.Join(parts, ", ")))
				} else {
					axfrResult.SetStr(fmt.Sprintf("%s [AXFR: no records returned]", target))
				}
				output <- axfrResult
			}
		}
	}

	close(output)
	// Give output worker time to finish
	time.Sleep(500 * time.Millisecond)

	return nil
}

func (r *Runner) runHTTP(targets []string) error {
	var wg sync.WaitGroup
	sem := make(chan struct{}, r.options.Threads)
	output := make(chan *Result, 1000)

	go func() {
		for result := range output {
			if r.options.HasMatcherFilter() && !r.shouldInclude(result) {
				continue
			}
			r.outputWriter.Write(result)
		}
	}()

	for _, target := range targets {
		if r.IsInterrupted() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			results := r.httpEngine.Probe(t)
			for _, result := range results {
				if result != nil && result.StatusCode > 0 {
					output <- r.convertHTTPResult(result)
				}
			}
		}(target)
	}

	wg.Wait()
	close(output)
	time.Sleep(100 * time.Millisecond)

	return nil
}

func (r *Runner) runSubdomain(targets []string) error {
	for _, target := range targets {
		if r.IsInterrupted() {
			break
		}
		subs, sourceMap, err := r.subdomainEngine.Run(context.Background(), target)
		if err != nil {
			continue
		}
		for _, sub := range subs {
			// Active subdomain check: resolve and skip if no IPs
			if r.options.ActiveSubdomain {
				ips, lookupErr := net.LookupHost(sub)
				if lookupErr != nil || len(ips) == 0 {
					continue
				}
			}

			result := &Result{
				Timestamp: time.Now(),
				Input:     target,
				Host:      sub,
				URL:       sub,
			}
			result.SetStr(sub)

			// Include source attribution if -cs is set
			if r.options.CaptureSources {
				if srcs, ok := sourceMap[sub]; ok {
					result.Extracts = map[string][]string{"source": srcs}
				}
			}

			r.outputWriter.Write(result)
		}
	}

	return nil
}

func (r *Runner) runAll(targets []string) error {
	gologger.Info().Msgf("Running all engines on %d targets\n", len(targets))

	// First run subdomain discovery
	if r.subdomainEngine != nil && len(r.options.Domains) > 0 {
		gologger.Info().Msg("[Phase 1/3] Subdomain Discovery...")
		for _, domain := range r.options.Domains {
			subs, _, err := r.subdomainEngine.Run(context.Background(), domain)
			if err == nil {
				for _, sub := range subs {
					// Active subdomain check: resolve and skip if no IPs
					if r.options.ActiveSubdomain {
						ips, lookupErr := net.LookupHost(sub)
						if lookupErr != nil || len(ips) == 0 {
							continue
						}
					}

					if !r.options.SkipDedupe {
						r.dedup.Set(sub)
					}
					targets = append(targets, sub)
				}
			}
		}
	}

	// Dedup the combined list
	var unique []string
	seen := make(map[string]struct{})
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if _, ok := seen[t]; ok || t == "" {
			continue
		}
		seen[t] = struct{}{}
		unique = append(unique, t)
	}

	// DNS on all targets
	if r.dnsEngine != nil {
		gologger.Info().Msgf("[Phase 2/3] DNS Resolution on %d targets...", len(unique))
		r.runDNS(unique)
	}

	// HTTP on all targets
	if r.httpEngine != nil {
		gologger.Info().Msgf("[Phase 3/3] HTTP Probing on %d targets...", len(unique))
		r.runHTTP(unique)
	}

	return nil
}

func (r *Runner) runTakeover(targets []string) error {
	gologger.Info().Msgf("[Phase] Subdomain Takeover Detection on %d targets...", len(targets))

	results := r.takeoverEngine.Run(context.Background(), targets)

	for _, tkResult := range results {
		if tkResult == nil {
			continue
		}
		result := convertTakeoverResult(tkResult)
		if result != nil {
			r.outputWriter.Write(result)
		}
	}

	gologger.Info().Msgf("Takeover detection complete: %d results, %d vulnerable",
		len(results), countVulnerable(results))

	return nil
}

func countVulnerable(results []*takeover.Result) int {
	count := 0
	for _, r := range results {
		if r.Vulnerable {
			count++
		}
	}
	return count
}

func convertTakeoverResult(tr *takeover.Result) *Result {
	result := &Result{
		Timestamp:  tr.Timestamp,
		Input:      tr.Host,
		Host:       tr.Host,
		URL:        tr.Host,
		A:          tr.A,
		CNAME:      tr.CNAME,
		NS:         tr.NS,
		StatusCode: tr.StatusCode,
		CDNName:    tr.CDNName,
		IsCDN:      tr.IsCDN,
		Vulnerable: tr.Vulnerable,
		Service:    tr.Service,
		Evidence:   tr.Evidence,
	}

	// Build string representation
	var sb strings.Builder
	if tr.Vulnerable {
		sb.WriteString(fmt.Sprintf("[VULNERABLE] %s", tr.Host))
		if tr.Service != "" {
			sb.WriteString(fmt.Sprintf(" [service: %s]", tr.Service))
		}
		if tr.Evidence != "" {
			sb.WriteString(fmt.Sprintf(" [evidence: %s]", tr.Evidence))
		}
	} else {
		sb.WriteString(tr.Host)
		if tr.Service != "" {
			sb.WriteString(fmt.Sprintf(" [service: %s]", tr.Service))
		}
	}
	if len(tr.CNAME) > 0 {
		sb.WriteString(fmt.Sprintf(" [cname: %s]", strings.Join(tr.CNAME, ", ")))
	}
	if tr.StatusCode > 0 {
		sb.WriteString(fmt.Sprintf(" [%d]", tr.StatusCode))
	}

	result.SetStr(sb.String())
	return result
}

// toStringSlice converts goflags.StringSlice to []string.
func toStringSlice(ss []string) []string {
	if ss == nil {
		return nil
	}
	return ss
}

func (r *Runner) readWordlist() []string {
	if r.options.WordList == "" {
		return nil
	}
	ch, err := shared.ReadTargets(r.options.WordList, nil, "")
	if err != nil {
		return nil
	}
	var words []string
	for w := range ch {
		words = append(words, strings.TrimSpace(w))
	}
	return words
}

func (r *Runner) startStats() {
	if r.stats == nil {
		return
	}
	r.stats.AddStatic("startedAt", time.Now())
	r.stats.AddCounter("requests", 0)
	r.stats.AddDynamic("summary", func(stats clistats.StatisticsClient) interface{} {
		startedAt, _ := stats.GetStatic("startedAt")
		duration := time.Since(startedAt.(time.Time))
		requests, _ := stats.GetCounter("requests")
		return fmt.Sprintf("[%s] | Requests: %d | RPS: %d",
			fmtDuration(duration), requests,
			uint64(float64(requests)/duration.Seconds()))
	})
	r.stats.Start()
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

// shouldInclude checks if a result passes all configured matchers and filters.
func (r *Runner) shouldInclude(result *Result) bool {
	o := r.options

	// Apply matchers (include only matching)
	if o.MatchStatusCode != "" {
		if !matchInt(result.StatusCode, o.MatchStatusCode) {
			return false
		}
	}
	if o.MatchContentLength != "" {
		if !matchInt(result.ContentLength, o.MatchContentLength) {
			return false
		}
	}
	if len(o.MatchString) > 0 {
		found := false
		for _, s := range o.MatchString {
			if strings.Contains(result.ResponseBody, s) || strings.Contains(result.str, s) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(o.MatchRegex) > 0 {
		found := false
		for _, pattern := range o.MatchRegex {
			if matched, _ := regexp.MatchString(pattern, result.ResponseBody+result.str); matched {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(o.MatchCDN) > 0 {
		found := false
		for _, cdn := range o.MatchCDN {
			if strings.EqualFold(result.CDNName, cdn) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Apply filters (exclude matching)
	if o.FilterStatusCode != "" {
		if matchInt(result.StatusCode, o.FilterStatusCode) {
			return false
		}
	}
	if o.FilterContentLength != "" {
		if matchInt(result.ContentLength, o.FilterContentLength) {
			return false
		}
	}
	if len(o.FilterString) > 0 {
		for _, s := range o.FilterString {
			if strings.Contains(result.ResponseBody, s) || strings.Contains(result.str, s) {
				return false
			}
		}
	}
	if len(o.FilterRegex) > 0 {
		for _, pattern := range o.FilterRegex {
			if matched, _ := regexp.MatchString(pattern, result.ResponseBody+result.str); matched {
				return false
			}
		}
	}
	if len(o.FilterCDN) > 0 {
		for _, cdn := range o.FilterCDN {
			if strings.EqualFold(result.CDNName, cdn) {
				return false
			}
		}
	}

	// Apply response time matcher (-mrt)
	if o.MatchResponseTime != "" {
		if !matchResponseTime(result.ResponseTime, o.MatchResponseTime) {
			return false
		}
	}

	// Apply response time filter (-frt)
	if o.FilterResponseTime != "" {
		if matchResponseTime(result.ResponseTime, o.FilterResponseTime) {
			return false
		}
	}

	// Apply condition matcher (-mdc)
	if o.MatchCondition != "" {
		if !matchCondition(result, o.MatchCondition) {
			return false
		}
	}

	// Apply condition filter (-fdc)
	if o.FilterCondition != "" {
		if matchCondition(result, o.FilterCondition) {
			return false
		}
	}

	// Apply duplicate filter (-fd)
	if o.FilterDuplicates {
		sig := fmt.Sprintf("%d|%d|%s|%s", result.StatusCode, result.ContentLength, result.Title, result.ContentType)
		r.dupsMu.Lock()
		if r.seenDups == nil {
			r.seenDups = make(map[string]bool)
		}
		if r.seenDups[sig] {
			r.dupsMu.Unlock()
			return false
		}
		r.seenDups[sig] = true
		r.dupsMu.Unlock()
	}

	return true
}

func matchInt(value int, spec string) bool {
	for _, s := range strings.Split(spec, ",") {
		s = strings.TrimSpace(s)
		if expected, err := strconv.Atoi(s); err == nil && value == expected {
			return true
		}
	}
	return false
}

// matchResponseTime parses a spec like "< 1", "> 500ms", or "= 1.5s"
// and compares it against the result's response time string.
func matchResponseTime(responseTime, spec string) bool {
	if responseTime == "" {
		return false
	}
	parts := strings.Fields(spec)
	if len(parts) < 2 {
		return false
	}
	op := parts[0]
	valStr := parts[1]
	target, err := time.ParseDuration(valStr)
	if err != nil {
		if seconds, err2 := strconv.ParseFloat(valStr, 64); err2 == nil {
			target = time.Duration(seconds * float64(time.Second))
		} else {
			return false
		}
	}
	actual, err := time.ParseDuration(responseTime)
	if err != nil {
		return false
	}
	switch op {
	case "<":
		return actual < target
	case ">":
		return actual > target
	case "=", "==":
		return actual == target
	case "<=":
		return actual <= target
	case ">=":
		return actual >= target
	default:
		return false
	}
}

// matchCondition evaluates a simple DSL expression against a result.
func matchCondition(result *Result, expr string) bool {
	ops := []string{"!contains", "contains", ">=", "<=", "==", "!=", ">", "<"}
	var field, op, value string
	remainder := strings.TrimSpace(expr)
	for _, candidateOp := range ops {
		idx := strings.Index(remainder, candidateOp)
		if idx > 0 {
			field = strings.TrimSpace(remainder[:idx])
			op = candidateOp
			value = strings.TrimSpace(remainder[idx+len(candidateOp):])
			value = strings.Trim(value, `"`)
			break
		}
	}
	if field == "" || op == "" {
		return false
	}
	var fieldValue string
	switch strings.ToLower(field) {
	case "status_code", "status-code", "statuscode":
		fieldValue = strconv.Itoa(result.StatusCode)
	case "content_length", "content-length", "contentlength":
		fieldValue = strconv.Itoa(result.ContentLength)
	case "content_type", "content-type", "contenttype":
		fieldValue = result.ContentType
	case "title":
		fieldValue = result.Title
	case "server":
		fieldValue = result.Server
	case "location":
		fieldValue = result.Location
	case "response_time", "response-time", "responsetime", "resp_time", "resp-time":
		fieldValue = result.ResponseTime
	case "body":
		fieldValue = result.ResponseBody
	case "host":
		fieldValue = result.Host
	case "url":
		fieldValue = result.URL
	case "method":
		fieldValue = result.Method
	case "ip":
		fieldValue = result.IP
	default:
		return false
	}
	switch op {
	case "==":
		switch strings.ToLower(field) {
		case "status_code", "status-code", "statuscode", "content_length", "content-length", "contentlength":
			if val, err := strconv.Atoi(fieldValue); err == nil {
				if target, err := strconv.Atoi(value); err == nil {
					return val == target
				}
			}
		case "response_time", "response-time", "responsetime", "resp_time", "resp-time":
			return matchResponseTime(fieldValue, "== "+value)
		}
		return strings.EqualFold(fieldValue, value)
	case "!=":
		switch strings.ToLower(field) {
		case "status_code", "status-code", "statuscode", "content_length", "content-length", "contentlength":
			if val, err := strconv.Atoi(fieldValue); err == nil {
				if target, err := strconv.Atoi(value); err == nil {
					return val != target
				}
			}
		case "response_time", "response-time", "responsetime", "resp_time", "resp-time":
			return !matchResponseTime(fieldValue, "== "+value)
		}
		return !strings.EqualFold(fieldValue, value)
	case ">":
		switch strings.ToLower(field) {
		case "status_code", "status-code", "statuscode", "content_length", "content-length", "contentlength":
			if val, err := strconv.Atoi(fieldValue); err == nil {
				if target, err := strconv.Atoi(value); err == nil {
					return val > target
				}
			}
		case "response_time", "response-time", "responsetime", "resp_time", "resp-time":
			return matchResponseTime(fieldValue, "> "+value)
		}
		return fieldValue > value
	case "<":
		switch strings.ToLower(field) {
		case "status_code", "status-code", "statuscode", "content_length", "content-length", "contentlength":
			if val, err := strconv.Atoi(fieldValue); err == nil {
				if target, err := strconv.Atoi(value); err == nil {
					return val < target
				}
			}
		case "response_time", "response-time", "responsetime", "resp_time", "resp-time":
			return matchResponseTime(fieldValue, "< "+value)
		}
		return fieldValue < value
	case ">=":
		switch strings.ToLower(field) {
		case "status_code", "status-code", "statuscode", "content_length", "content-length", "contentlength":
			if val, err := strconv.Atoi(fieldValue); err == nil {
				if target, err := strconv.Atoi(value); err == nil {
					return val >= target
				}
			}
		case "response_time", "response-time", "responsetime", "resp_time", "resp-time":
			return matchResponseTime(fieldValue, ">= "+value)
		}
		return fieldValue >= value
	case "<=":
		switch strings.ToLower(field) {
		case "status_code", "status-code", "statuscode", "content_length", "content-length", "contentlength":
			if val, err := strconv.Atoi(fieldValue); err == nil {
				if target, err := strconv.Atoi(value); err == nil {
					return val <= target
				}
			}
		case "response_time", "response-time", "responsetime", "resp_time", "resp-time":
			return matchResponseTime(fieldValue, "<= "+value)
		}
		return fieldValue <= value
	case "contains":
		return strings.Contains(strings.ToLower(fieldValue), strings.ToLower(value))
	case "!contains":
		return !strings.Contains(strings.ToLower(fieldValue), strings.ToLower(value))
	}
	return false
}

// Close cleans up resources.
func (r *Runner) Close() {
	if r.dnsEngine != nil {
		r.dnsEngine.Close()
	}
	if r.httpEngine != nil {
		r.httpEngine.Close()
	}
	if r.subdomainEngine != nil {
		r.subdomainEngine.Close()
	}
	if r.takeoverEngine != nil {
		r.takeoverEngine.Close()
	}
	if r.outputWriter != nil {
		r.outputWriter.Close()
	}
	if r.dedup != nil {
		r.dedup.Close()
	}
	if r.rateLimiter != nil {
		r.rateLimiter.Stop()
	}
	if r.stats != nil {
		r.stats.Stop()
	}
}

// isWildcardResult checks if any A record IP matches a known wildcard IP.
func isWildcardResult(result *dns.Result, wildcardIPs []string) bool {
	if len(wildcardIPs) == 0 {
		return false
	}
	for _, ip := range result.A {
		for _, wip := range wildcardIPs {
			if ip == wip {
				return true
			}
		}
	}
	return false
}

// Conversion functions from engine types to runner Result
func (run *Runner) convertDNSResult(dr *dns.Result) *Result {
	// Skip results that have no records at all (unresolvable),
	// UNLESS the user explicitly filtered by RCODE (-rc) — in that case
	// preserve NXDOMAIN/SERVFAIL/REFUSED etc. so they are visible.
	noRecords := len(dr.A) == 0 && len(dr.AAAA) == 0 && len(dr.CNAME) == 0 &&
		len(dr.MX) == 0 && len(dr.NS) == 0 && len(dr.TXT) == 0 &&
		len(dr.SOA) == 0 && len(dr.PTR) == 0 && len(dr.CAA) == 0 && len(dr.SRV) == 0
	if noRecords {
		if dr.RCode == "" || dr.RCode == "NOERROR" {
			return nil
		}
		// RCODE is a non-success — user explicitly asked to see it with -rc
	}

	result := &Result{
		Timestamp:     time.Now(),
		Input:         dr.Host,
		Host:          dr.Host,
		URL:           dr.Host,
		IP:            strings.Join(dr.A, ","),
		A:             dr.A,
		AAAA:          dr.AAAA,
		CNAME:         dr.CNAME,
		MX:            dr.MX,
		NS:            dr.NS,
		TXT:           dr.TXT,
		SOA:           dr.SOA,
		PTR:           dr.PTR,
		CAA:           dr.CAA,
		SRV:           dr.SRV,
		RCode:         dr.RCode,
		StatusCodeRaw: dr.StatusCode,
		CDNName:       dr.CDNName,
		IsCDN:         dr.IsCDN,
		RawDNS:        dr.Raw,
	}

	if dr.ASN != nil {
		result.ASN = &ASNInfo{
			AsNumber:  dr.ASN.AsNumber,
			AsName:    dr.ASN.AsName,
			AsCountry: dr.ASN.AsCountry,
			AsRange:   dr.ASN.AsRange,
		}
	}

	if dr.TraceData != nil {
		var servers []TraceServer
		for _, s := range dr.TraceData.Servers {
			servers = append(servers, TraceServer{
				Server:    s.Server,
				QueryType: s.QueryType,
				Response:  s.Response,
			})
		}
		result.TraceData = &TraceInfo{
			Host:    dr.TraceData.Host,
			Servers: servers,
		}
	}

	// Build string representation
	var sb strings.Builder

	recordPairs := []struct {
		rtype string
		vals  []string
	}{
		{"A", dr.A}, {"AAAA", dr.AAAA}, {"CNAME", dr.CNAME},
		{"MX", dr.MX}, {"NS", dr.NS}, {"TXT", dr.TXT},
		{"SOA", dr.SOA}, {"PTR", dr.PTR}, {"CAA", dr.CAA}, {"SRV", dr.SRV},
	}

	respOnly := run.options.RespOnly
	showResp := run.options.Resp

	if respOnly {
		// -ro mode: show only record values, no hostname
		for _, p := range recordPairs {
			for _, v := range p.vals {
				sb.WriteString(v)
				if dr.CDNName != "" {
					sb.WriteString(fmt.Sprintf(" [%s]", dr.CDNName))
				}
				sb.WriteString("\n")
			}
		}
	} else if showResp {
		// -re mode: show host [type] [value]
		for _, p := range recordPairs {
			for _, v := range p.vals {
				sb.WriteString(fmt.Sprintf("%s [%s] [%s]", dr.Host, p.rtype, v))
				if dr.CDNName != "" {
					sb.WriteString(fmt.Sprintf(" [%s]", dr.CDNName))
				}
				sb.WriteString("\n")
			}
		}
	} else {
		// Default: show host [main IPs] for A/AAAA, or [type] [value] for other records
		o := run.options
		hasOther := o.CNAME || o.NS || o.TXT || o.SRV || o.PTR || o.MX || o.SOA || o.ANY || o.AXFR || o.CAA || o.QueryAll
		if hasOther {
			for _, p := range recordPairs {
				if !o.hasRecordType(p.rtype) {
					continue
				}
				for _, v := range p.vals {
					var line string
					if dr.CDNName != "" {
						line = fmt.Sprintf("%s [%s] [%s] [%s]", dr.Host, p.rtype, v, dr.CDNName)
					} else {
						line = fmt.Sprintf("%s [%s] [%s]", dr.Host, p.rtype, v)
					}
					if sb.Len() > 0 {
						sb.WriteString("\n")
					}
					sb.WriteString(line)
				}
			}
		} else {
			// Only A/AAAA: show host [IPs]
			sb.WriteString(dr.Host)
			allIPs := append([]string{}, dr.A...)
			allIPs = append(allIPs, dr.AAAA...)
			if len(allIPs) > 0 {
				sb.WriteString(fmt.Sprintf(" [%s]", strings.Join(allIPs, ", ")))
			}
			if dr.CDNName != "" {
				sb.WriteString(fmt.Sprintf(" [%s]", dr.CDNName))
			}
			if result.ASN != nil {
				sb.WriteString(" " + result.ASN.String())
			}
		}

		// DNS trace data
		if result.TraceData != nil {
			sb.WriteString("\n[Trace]")
			for _, s := range result.TraceData.Servers {
				sb.WriteString(fmt.Sprintf("\n  %s (%s) → %s", s.Server, s.QueryType, s.Response))
			}
		}

		// Raw DNS response
		if result.RawDNS != "" {
			sb.WriteString("\n[Raw DNS Response]\n")
			sb.WriteString(result.RawDNS)
		}
	}

	result.SetStr(strings.TrimSpace(sb.String()))
	return result
}

func (run *Runner) convertHTTPResult(hr *http.Result) *Result {
	r := &Result{
		Timestamp:     time.Now(),
		Input:         hr.Input,
		URL:           hr.URL,
		Host:          hr.Host,
		IP:            hr.IP,
		StatusCode:    hr.StatusCode,
		ContentLength: hr.ContentLength,
		ContentType:   hr.ContentType,
		Title:         hr.Title,
		Server:        hr.Server,
		Location:      hr.Location,
		ResponseTime:  hr.ResponseTime,
		Lines:         hr.Lines,
		Words:         hr.Words,
		Method:        hr.Method,
		ProbeStatus:   hr.ProbeStatus,
		FavIconMMH3:   hr.FavIconMMH3,
		JARM:          hr.JARM,
		Hash:          hr.Hashes,
		WebSocket:     hr.WebSocket,
		HTTP2:         hr.HTTP2,
		Pipeline:      hr.Pipeline,
		VHost:         hr.VHost,
		TechDetect:    hr.TechDetect,
		CNAME:         hr.CNAMEs,
		CDNName:       hr.CDNName,
		IsCDN:         hr.IsCDN,
		A:             hr.IPs,
		Extracts:      hr.Extracts,
		Err:           hr.Err,
	}
	r.ResponseBody = hr.Body
	if run != nil && run.options != nil && run.options.BodyPreview > 0 && hr.Body != "" {
		r.BodyPreview = truncateString(hr.Body, run.options.BodyPreview)
	}

	if hr.TLSData != nil {
		r.TLSData = &TLSInfo{
			SubjectCN: hr.TLSData.SubjectCN,
			SubjectAN: hr.TLSData.SubjectAN,
			Issuer:    hr.TLSData.Issuer,
			NotBefore: hr.TLSData.NotBefore,
			NotAfter:  hr.TLSData.NotAfter,
		}
	}

	// Build string — show only fields the user explicitly requested
	var sb strings.Builder
	sb.WriteString(hr.URL)

	o := run.options

	// Status code — shown only when -sc is set
	if o.StatusCode && hr.StatusCode > 0 {
		sb.WriteString(fmt.Sprintf(" [%d]", hr.StatusCode))
	}
	// Conditional fields — shown only when their specific flag is set
	if o.ExtractTitle && hr.Title != "" {
		sb.WriteString(fmt.Sprintf(" [%s]", hr.Title))
	}
	if o.WebServer && hr.Server != "" {
		sb.WriteString(fmt.Sprintf(" [%s]", hr.Server))
	}
	if o.ContentLength && hr.ContentLength > 0 {
		sb.WriteString(fmt.Sprintf(" [%d]", hr.ContentLength))
	}
	if o.OutputIP && hr.IP != "" {
		sb.WriteString(fmt.Sprintf(" [%s]", hr.IP))
	}
	if (o.OutputCDN != "" || o.CDN) && hr.CDNName != "" {
		sb.WriteString(fmt.Sprintf(" [%s]", hr.CDNName))
	}
	if o.HTTPMethod && hr.Method != "" {
		sb.WriteString(fmt.Sprintf(" [%s]", hr.Method))
	}
	if o.Favicon && hr.FavIconMMH3 != "" {
		sb.WriteString(fmt.Sprintf(" [fav:%s]", hr.FavIconMMH3))
	}
	if o.JARM && hr.JARM != "" {
		sb.WriteString(fmt.Sprintf(" [jarm:%s]", hr.JARM))
	}
	if o.Hashes != "" && len(hr.Hashes) > 0 {
		hashTypes := strings.Split(o.Hashes, ",")
		for _, ht := range hashTypes {
			ht = strings.TrimSpace(ht)
			if h, ok := hr.Hashes[ht]; ok && h != "" {
				sb.WriteString(fmt.Sprintf(" [%s:%s]", ht, h))
			}
		}
	}
	if o.ResponseTime && hr.ResponseTime != "" {
		sb.WriteString(fmt.Sprintf(" [%s]", hr.ResponseTime))
	}
	if o.LineCount && hr.Lines > 0 {
		sb.WriteString(fmt.Sprintf(" [%d]", hr.Lines))
	}
	if o.WordCount && hr.Words > 0 {
		sb.WriteString(fmt.Sprintf(" [%d]", hr.Words))
	}
	if o.Location && hr.Location != "" {
		sb.WriteString(fmt.Sprintf(" [%s]", hr.Location))
	}
	if o.ContentType && hr.ContentType != "" {
		sb.WriteString(fmt.Sprintf(" [%s]", hr.ContentType))
	}
	if o.TechDetect && len(hr.TechDetect) > 0 {
		for _, t := range hr.TechDetect {
			if t != "" {
				sb.WriteString(fmt.Sprintf(" [%s]", t))
			}
		}
	}
	if o.WebSocket && hr.WebSocket {
		sb.WriteString(" [ws]")
	}
	if o.HTTP2Probe && hr.HTTP2 {
		sb.WriteString(" [h2]")
	}
	if o.Pipeline && hr.Pipeline {
		sb.WriteString(" [pipe]")
	}
	if o.VHost && hr.VHost {
		sb.WriteString(" [vhost]")
	}
	if o.ProbeStatus && hr.ProbeStatus {
		sb.WriteString(" [alive]")
	}
	// Extracts from -er (extract-regex) and -ep (extract-preset)
	if len(hr.Extracts) > 0 {
		for key, values := range hr.Extracts {
			for _, v := range values {
				if v != "" {
					sb.WriteString(fmt.Sprintf(" [%s:%s]", key, v))
				}
			}
		}
	}
	// TLS certificate data
	if o.TLSGrab && r.TLSData != nil {
		if r.TLSData.SubjectCN != "" {
			sb.WriteString(fmt.Sprintf(" [tls-cn:%s]", r.TLSData.SubjectCN))
		}
		if len(r.TLSData.SubjectAN) > 0 {
			sb.WriteString(fmt.Sprintf(" [tls-san:%s]", strings.Join(r.TLSData.SubjectAN, ",")))
		}
		if r.TLSData.Issuer != "" {
			sb.WriteString(fmt.Sprintf(" [tls-issuer:%s]", r.TLSData.Issuer))
		}
	}

	r.SetStr(sb.String())
	return r
}

func truncateString(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n]
}
