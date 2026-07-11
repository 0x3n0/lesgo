package takeover

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"

	"github.com/0x3n0/lesgo/internal/shared"
)

// Engine performs subdomain takeover detection.
type Engine struct {
	opts      Options
	client    *retryablehttp.Client
	dnsClient *dns.Client
}

// New creates a new takeover engine.
func New(opts Options) (*Engine, error) {
	if opts.Threads <= 0 {
		opts.Threads = 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10
	}
	if !opts.CheckCNAME && !opts.CheckNS && !opts.CheckHTTP {
		opts.CheckCNAME = true
		opts.CheckNS = true
		opts.CheckHTTP = true
	}
	opts.DNSServers = normalizeResolvers(opts.DNSServers)

	e := &Engine{opts: opts}

	// Create HTTP client with retries and TLS skip verify
	retryClient := retryablehttp.NewClient(retryablehttp.Options{
		Timeout: time.Duration(opts.Timeout) * time.Second,
	})
	retryClient.HTTPClient = &http.Client{
		Timeout: time.Duration(opts.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:    100,
			IdleConnTimeout: 30 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	e.client = retryClient

	// Create DNS client
	e.dnsClient = &dns.Client{
		Timeout: 5 * time.Second,
	}

	return e, nil
}

// Run executes takeover detection on the given subdomains.
func (e *Engine) Run(ctx context.Context, subdomains []string) []*Result {
	var (
		wg      sync.WaitGroup
		sem     = make(chan struct{}, e.opts.Threads)
		output  = make(chan *Result, 1000)
		results []*Result
	)

	// Output collector
	done := make(chan struct{})
	go func() {
		for r := range output {
			results = append(results, r)
		}
		close(done)
	}()

	for _, subdomain := range subdomains {
		if ctx.Err() != nil {
			break
		}

		subdomain = strings.TrimSpace(subdomain)
		if subdomain == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			result := e.checkHost(host)
			if result != nil {
				output <- result
			}
		}(subdomain)
	}

	wg.Wait()
	close(output)
	<-done

	return results
}

// CheckSingle probes a single host for takeover vulnerabilities.
func (e *Engine) CheckSingle(host string) *Result {
	return e.checkHost(host)
}

func (e *Engine) checkHost(host string) *Result {
	host = strings.TrimSpace(strings.ToLower(host))
	// Strip protocol prefix
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimSuffix(host, "/")

	result := &Result{
		Host:      host,
		Timestamp: time.Now(),
	}

	var cnames []string
	if e.opts.CheckCNAME {
		cnames = e.resolveCNAME(host)
	}
	result.CNAME = cnames

	var ns []string
	if e.opts.CheckNS {
		ns = e.resolveNS(host)
	}
	result.NS = ns

	aRecords := e.resolveA(host)
	result.A = aRecords

	var matchedCNAME []*ServiceFingerprint
	if e.opts.CheckCNAME {
		matchedCNAME = e.matchCNAME(cnames)
	}
	var matchedNS []*ServiceFingerprint
	if e.opts.CheckNS {
		matchedNS = e.matchNS(ns)
	}

	httpOnly := e.opts.CheckHTTP && !e.opts.CheckCNAME && !e.opts.CheckNS
	if e.opts.CheckHTTP && (httpOnly || len(cnames) > 0 || len(ns) > 0 || len(aRecords) == 0) {
		e.httpProbe(host, result)
	}

	if httpOnly {
		if fp := e.matchHTTPFingerprint(result, allFingerprints()); fp != nil {
			result.Vulnerable = true
			result.Service = fp.Name
		}
	} else {
		result.Vulnerable = e.determineVulnerability(result, matchedCNAME, matchedNS)
	}

	// Set service name from CNAME or NS match (whether vulnerable or not)
	if result.Service != "" {
		// Service already set by an HTTP-only fingerprint match.
	} else if len(matchedCNAME) > 0 {
		result.Service = matchedCNAME[0].Name
	} else if len(matchedNS) > 0 {
		result.Service = matchedNS[0].Name
	}

	// Only return results that are vulnerable or have CNAMEs pointing to known services
	if result.Vulnerable || len(matchedCNAME) > 0 || len(matchedNS) > 0 {
		return result
	}

	// If no CNAME but domain doesn't resolve at all, check HTTP
	if len(aRecords) == 0 && len(cnames) == 0 && len(ns) == 0 {
		return nil
	}

	// Return nil for non-interesting results (skip non-vulnerable resolved hosts)
	if !result.Vulnerable && len(matchedCNAME) == 0 && len(matchedNS) == 0 {
		return nil
	}

	return result
}

func (e *Engine) resolveCNAME(host string) []string {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(host), dns.TypeCNAME)
	m.RecursionDesired = true

	resp, _, err := e.dnsClient.Exchange(m, e.getResolver())
	if err != nil {
		return nil
	}

	var cnames []string
	for _, ans := range resp.Answer {
		if cname, ok := ans.(*dns.CNAME); ok {
			cnames = append(cnames, strings.TrimSuffix(cname.Target, "."))
		}
	}
	return cnames
}

func (e *Engine) resolveNS(host string) []string {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(host), dns.TypeNS)
	m.RecursionDesired = true

	resp, _, err := e.dnsClient.Exchange(m, e.getResolver())
	if err != nil {
		return nil
	}

	var ns []string
	for _, ans := range resp.Answer {
		if nsRR, ok := ans.(*dns.NS); ok {
			ns = append(ns, strings.TrimSuffix(nsRR.Ns, "."))
		}
	}
	return ns
}

func (e *Engine) resolveA(host string) []string {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	resp, _, err := e.dnsClient.Exchange(m, e.getResolver())
	if err != nil {
		return nil
	}

	var ips []string
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	return ips
}

func (e *Engine) getResolver() string {
	if len(e.opts.DNSServers) > 0 {
		return e.opts.DNSServers[0]
	}
	return "8.8.8.8:53"
}

func normalizeResolvers(resolvers []string) []string {
	var normalized []string
	for _, resolver := range resolvers {
		if rr := shared.PrepareResolver(resolver); rr != "" {
			normalized = append(normalized, rr)
		}
	}
	return normalized
}

func (e *Engine) matchCNAME(cnames []string) []*ServiceFingerprint {
	var matches []*ServiceFingerprint
	cnameSeen := make(map[*ServiceFingerprint]bool)

	for _, cname := range cnames {
		cname = strings.ToLower(cname)
		for i := range Fingerprints {
			fp := &Fingerprints[i]
			for _, pattern := range fp.CNAMEPatterns {
				if strings.Contains(cname, strings.ToLower(pattern)) {
					if !cnameSeen[fp] {
						matches = append(matches, fp)
						cnameSeen[fp] = true
					}
				}
			}
		}
	}
	return matches
}

func (e *Engine) matchNS(nsRecords []string) []*ServiceFingerprint {
	var matches []*ServiceFingerprint
	nsSeen := make(map[*ServiceFingerprint]bool)

	for _, ns := range nsRecords {
		ns = strings.ToLower(ns)
		for i := range Fingerprints {
			fp := &Fingerprints[i]
			for _, pattern := range fp.NSPatterns {
				if strings.Contains(ns, strings.ToLower(pattern)) {
					if !nsSeen[fp] {
						matches = append(matches, fp)
						nsSeen[fp] = true
					}
				}
			}
		}
	}
	return matches
}

func (e *Engine) httpProbe(host string, result *Result) {
	// Try HTTPS first
	urls := []string{
		fmt.Sprintf("https://%s", host),
		fmt.Sprintf("http://%s", host),
	}

	for _, url := range urls {
		resp, err := e.client.Get(url)
		if err != nil {
			result.Error = err.Error()
			continue
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}

		result.StatusCode = resp.StatusCode
		result.Response = string(bodyBytes)

		// Check for CDN
		cdnName := detectCDN(resp)
		if cdnName != "" {
			result.IsCDN = true
			result.CDNName = cdnName
		}

		// If we got a valid HTTP response, we're done probing
		break
	}
}

func (e *Engine) determineVulnerability(result *Result, cnameMatches []*ServiceFingerprint, nsMatches []*ServiceFingerprint) bool {
	allMatches := append(cnameMatches, nsMatches...)

	if fp := e.matchHTTPFingerprint(result, allMatches); fp != nil {
		return true
	}

	for _, fp := range allMatches {
		// If CNAME matches but HTTP didn't get a specific response,
		// check if the host doesn't resolve (NXDOMAIN) which is a strong indicator
		if len(result.CNAME) > 0 && result.Error != "" {
			// CNAME exists but host is unreachable - potential dangling record
			gologger.Debug().Msgf("[takeover] Dangling CNAME for %s: %v (service: %s)\n",
				result.Host, result.CNAME, fp.Name)
		}
	}

	// Check for NXDOMAIN with NS takeover
	// Only flag if: NS matches a provider AND domain has NO A records AND NO CNAME records
	// (a CNAME that resolves means the domain is not dangling)
	if len(nsMatches) > 0 && len(result.A) == 0 && len(result.CNAME) == 0 {
		// NS points to provider but domain doesn't resolve at all - high risk
		return true
	}

	return false
}

func (e *Engine) matchHTTPFingerprint(result *Result, fingerprints []*ServiceFingerprint) *ServiceFingerprint {
	for _, fp := range fingerprints {
		for i := range fp.HTTPPatterns {
			pat := &fp.HTTPPatterns[i]
			if pat.StatusCode > 0 && result.StatusCode != pat.StatusCode {
				continue
			}

			bodyMatched := len(pat.BodyContains) == 0
			for _, s := range pat.BodyContains {
				if strings.Contains(strings.ToLower(result.Response), strings.ToLower(s)) {
					bodyMatched = true
					result.Evidence = s
					break
				}
			}

			regexMatched := len(pat.BodyRegex) == 0
			for _, reStr := range pat.BodyRegex {
				if matched, _ := regexp.MatchString(reStr, result.Response); matched {
					regexMatched = true
					result.Evidence = reStr
					break
				}
			}

			if bodyMatched && regexMatched {
				return fp
			}
		}
	}
	return nil
}

func allFingerprints() []*ServiceFingerprint {
	matches := make([]*ServiceFingerprint, 0, len(Fingerprints))
	for i := range Fingerprints {
		matches = append(matches, &Fingerprints[i])
	}
	return matches
}

// detectCDN checks response headers for known CDN signatures.
func detectCDN(resp *http.Response) string {
	cdns := map[string]string{
		"cloudflare":       "cloudflare",
		"cloudfront":       "cloudfront",
		"akamai":           "akamai",
		"fastly":           "fastly",
		"sucuri":           "sucuri",
		"stackpath":        "stackpath",
		"incapsula":        "incapsula",
		"maxcdn":           "maxcdn",
		"keycdn":           "keycdn",
		"bunnycdn":         "bunnycdn",
		"cdn77":            "cdn77",
		"azure cdn":        "azure",
		"google cloud cdn": "gcp",
	}

	checkHeaders := []string{
		"Server",
		"X-CDN",
		"X-Cache",
		"CF-Ray",
		"X-Amz-Cf-Id",
		"X-Served-By",
		"X-Cache-Status",
		"X-Backend",
	}

	for _, header := range checkHeaders {
		val := resp.Header.Get(header)
		if val == "" {
			continue
		}
		valLower := strings.ToLower(val)
		for keyword, name := range cdns {
			if strings.Contains(valLower, keyword) {
				return name
			}
		}
	}

	return ""
}

// Close cleans up resources.
func (e *Engine) Close() {
	if e.client != nil && e.client.HTTPClient != nil {
		if transport, ok := e.client.HTTPClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
}
