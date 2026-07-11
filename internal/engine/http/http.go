package http

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/retryablehttp-go"

	"github.com/0x3n0/lesgo/internal/shared"
)

// Engine is the HTTP probe engine.
type Engine struct {
	opts       Options
	client     *retryablehttp.Client
	transport  *http.Transport
	cdnClient  *cdncheck.Client
	userAgents []string
	proxyURL   *url.URL
}

// New creates a new HTTP Engine.
func New(opts Options) (*Engine, error) {
	e := &Engine{
		opts: opts,
		userAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
		},
	}

	if opts.Timeout <= 0 {
		opts.Timeout = 10
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = 10
	}

	// Configure transport
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(opts.Timeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	if opts.SniName != "" {
		transport.TLSClientConfig.ServerName = opts.SniName
	}

	if opts.NoDecode {
		transport.DisableCompression = true
	}

	// Configure proxy
	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err == nil {
			e.proxyURL = proxyURL
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	e.transport = transport

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if !opts.FollowRedirects && !opts.FollowHostRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= opts.MaxRedirects {
			return http.ErrUseLastResponse
		}
		if opts.FollowHostRedirects && len(via) > 0 && !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
			return http.ErrUseLastResponse
		}
		return nil
	}

	// Create retryablehttp client
	e.client = retryablehttp.NewClient(retryablehttp.Options{
		RetryMax: opts.Retries,
		Timeout:  time.Duration(opts.Timeout) * time.Second,
		HttpClient: &http.Client{
			Transport:     transport,
			CheckRedirect: checkRedirect,
		},
	})

	// CDN check client
	if opts.OutputCDN == "true" {
		e.cdnClient = cdncheck.New()
	}

	return e, nil
}

// Probe probes a single target with all configured options.
// Returns a slice of results to support multi-result features like
// -path (multiple paths), -tls-probe (TLS SAN domains), -csp-probe (CSP domains).
func (e *Engine) Probe(target string) []*Result {
	target = strings.TrimSpace(target)

	var targetURL *url.URL
	if e.opts.Unsafe {
		// Handle plain hostnames by defaulting to http:// scheme
		if !strings.Contains(target, "://") {
			target = "http://" + target
		}
		targetURL, _ = url.Parse(target)
		if targetURL == nil || targetURL.Host == "" {
			return []*Result{{Input: target, Err: fmt.Errorf("invalid target: %s", target)}}
		}
	} else {
		targetURL = e.normalizeTarget(target)
		if targetURL == nil {
			return []*Result{{Input: target, Err: fmt.Errorf("invalid target: %s", target)}}
		}
	}

	// Determine protocols
	protocols := []string{"https"}
	if e.opts.Unsafe {
		// In unsafe mode, use the exact scheme from the provided URL
		scheme := targetURL.Scheme
		if scheme == "" {
			scheme = "http"
		}
		protocols = []string{scheme}
	} else if e.opts.NoFallback {
		protocols = []string{"https", "http"}
	} else if e.opts.NoFallbackScheme && strings.HasPrefix(target, "http://") {
		protocols = []string{"http"}
	}

	// Determine methods
	methods := []string{"GET"}
	if e.opts.RequestMethods != "" {
		if strings.ToLower(e.opts.RequestMethods) == "all" {
			methods = AllHTTPMethods()
		} else {
			methods = shared.SplitByCharAndTrimSpace(e.opts.RequestMethods, ",")
		}
	}

	// Determine paths to probe
	paths := e.getRequestPaths()
	if len(paths) == 0 {
		paths = []string{""} // default root path
	}

	// Determine URLs to probe
	var baseURLs []string
	if e.opts.CustomPorts != "" {
		ports := e.parsePorts(e.opts.CustomPorts)
		for proto, portList := range ports {
			for _, port := range portList {
				u := *targetURL
				u.Scheme = proto
				u.Host = fmt.Sprintf("%s:%d", targetURL.Hostname(), port)
				baseURLs = append(baseURLs, u.String())
			}
		}
	} else {
		for _, proto := range protocols {
			u := *targetURL
			u.Scheme = proto
			if e.opts.LeaveDefaultPorts {
				if _, _, err := net.SplitHostPort(u.Host); err != nil {
					defaultPort := "443"
					if proto == "http" {
						defaultPort = "80"
					}
					u.Host = net.JoinHostPort(u.Host, defaultPort)
				}
			}
			baseURLs = append(baseURLs, u.String())
		}
	}

	if len(baseURLs) == 0 {
		baseURLs = append(baseURLs, targetURL.String())
	}

	// Expand URLs with paths
	var urls []string
	for _, base := range baseURLs {
		for _, p := range paths {
			u := e.joinPath(base, p)
			urls = append(urls, u)
		}
	}

	// Probe each URL + method (concurrent for multiple methods)
	type probeJob struct {
		url    string
		method string
	}

	var jobs []probeJob
	for _, probedURL := range urls {
		for _, method := range methods {
			jobs = append(jobs, probeJob{probedURL, method})
		}
	}

	// Concurrent probing
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // max 10 concurrent
	results := make(chan *Result, len(jobs))

	for _, job := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j probeJob) {
			defer wg.Done()
			defer func() { <-sem }()
			if r := e.probeURL(j.url, j.method); r != nil {
				results <- r
			}
		}(job)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results - return first successful, else last attempted
	var probeResults []*Result
	var firstSuccess, lastResult *Result
	for pr := range results {
		lastResult = pr
		if pr.Err == nil && firstSuccess == nil {
			firstSuccess = pr
		}
	}

	if firstSuccess != nil {
		probeResults = append(probeResults, firstSuccess)
	} else if lastResult != nil {
		// Try fallback protocol
		if lastResult.Err != nil && !e.opts.NoFallback {
			for _, probedURL := range baseURLs {
				fallbackURL := e.switchProtocol(probedURL)
				if r := e.probeURL(fallbackURL, methods[0]); r != nil && r.Err == nil {
					probeResults = append(probeResults, r)
					firstSuccess = r
					break
				}
			}
			if len(probeResults) == 0 {
				probeResults = append(probeResults, lastResult)
			}
		} else {
			probeResults = append(probeResults, lastResult)
		}
	} else {
		probeResults = append(probeResults, &Result{Input: target, Err: fmt.Errorf("no probe results for %s", target)})
	}

	// TLS probe: extract SAN DNS names from the TLS certificate and probe them
	if e.opts.TLSProbe && firstSuccess != nil && firstSuccess.TLSData != nil {
		seen := make(map[string]bool)
		seen[targetURL.Hostname()] = true
		for _, dnsName := range firstSuccess.TLSData.SubjectAN {
			dnsName = strings.TrimSpace(dnsName)
			if dnsName == "" || seen[dnsName] || strings.HasPrefix(dnsName, "*") {
				continue
			}
			seen[dnsName] = true
			if r := e.probeURL("https://"+dnsName, "GET"); r != nil {
				probeResults = append(probeResults, r)
			}
		}
	}

	// CSP probe: extract domains from CSP header and probe them
	if e.opts.CSPProbe && firstSuccess != nil {
		seen := make(map[string]bool)
		seen[targetURL.Hostname()] = true
		cspDomains := e.extractCSPDomains(firstSuccess)
		for _, domain := range cspDomains {
			if domain == "" || seen[domain] {
				continue
			}
			seen[domain] = true
			if r := e.probeURL("https://"+domain, "GET"); r != nil {
				probeResults = append(probeResults, r)
			}
		}
	}

	return probeResults
}

func (e *Engine) probeURL(rawURL string, method string) *Result {
	if e.opts.RateLimiter != nil {
		e.opts.RateLimiter.Take()
	}
	if e.opts.Delay > 0 {
		time.Sleep(e.opts.Delay)
	}

	result := &Result{
		Input: rawURL,
		URL:   rawURL,
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		result.Err = err
		return result
	}

	result.Host = parsed.Hostname()
	start := time.Now()

	req, err := retryablehttp.NewRequest(method, rawURL, nil)
	if err != nil {
		result.Err = err
		return result
	}

	if e.opts.RandomAgent {
		req.Header.Set("User-Agent", e.randomUA())
	}
	if e.opts.AutoReferer {
		req.Header.Set("Referer", rawURL)
	}
	for k, v := range e.opts.CustomHeaders {
		req.Header.Set(k, v)
	}

	if e.opts.RequestBody != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		req.Body = io.NopCloser(strings.NewReader(e.opts.RequestBody))
		req.ContentLength = int64(len(e.opts.RequestBody))
	}

	resp, err := e.client.Do(req)
	result.ResponseTime = time.Since(start).Round(time.Millisecond).String()

	if err != nil {
		result.Err = err
		return result
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err == nil {
		result.Body = string(bodyBytes)
	}

	result.StatusCode = resp.StatusCode
	result.ContentLength = int(resp.ContentLength)
	// For chunked responses resp.ContentLength is -1; use actual body length
	if result.ContentLength <= 0 && len(result.Body) > 0 {
		result.ContentLength = len(result.Body)
	}
	result.ContentType = resp.Header.Get("Content-Type")
	result.Server = resp.Header.Get("Server")
	result.Location = resp.Header.Get("Location")
	result.Headers = resp.Header

	result.Title = ExtractTitle(result.Body)
	result.Lines = len(strings.Split(result.Body, "\n"))
	result.Words = len(strings.Fields(result.Body))

	ips, cnames, _ := e.resolveHost(result.Host)
	result.IPs = ips
	result.CNAMEs = cnames
	if len(ips) > 0 {
		result.IP = ips[0]
	}

	// Check all resolved IPs for CDN (first match wins)
	if e.cdnClient != nil && len(result.IPs) > 0 {
		for _, ip := range result.IPs {
			if matched, name, _, err := e.cdnClient.Check(net.ParseIP(ip)); err == nil && matched {
				result.IsCDN = true
				result.CDNName = name
				break
			}
		}
	}

	result.WebSocket = checkWebSocket(resp)

	if len(result.Body) > 0 {
		result.TechDetect = detectTech(resp, result.Body)
	}

	if e.opts.Hashes != "" {
		result.Hashes = make(map[string]string)
		for _, ht := range strings.Split(e.opts.Hashes, ",") {
			ht = strings.TrimSpace(ht)
			if ht != "" {
				result.Hashes[ht] = shared.GetHash(ht, result.Body)
			}
		}
	}

	if len(e.opts.ExtractRegex) > 0 {
		result.Extracts = make(map[string][]string)
		for _, er := range e.opts.ExtractRegex {
			result.Extracts[er] = ExtractWithRegex(result.Body, er)
		}
	}
	if len(e.opts.ExtractPreset) > 0 {
		if result.Extracts == nil {
			result.Extracts = make(map[string][]string)
		}
		for _, ep := range e.opts.ExtractPreset {
			if extractor, ok := PresetExtractors[ep]; ok {
				result.Extracts[ep] = extractor(result.Body)
			}
		}
	}

	// HTTP method used
	result.Method = method
	result.ProbeStatus = true

	// Favicon mmh3 hash
	if e.opts.Favicon {
		result.FavIconMMH3 = e.fetchFavicon(parsed)
	}

	// HTTP/2 support check
	if e.opts.HTTP2Probe {
		result.HTTP2 = e.CheckHTTP2(result.Host)
	}

	// HTTP/1.1 pipelining check
	if e.opts.Pipeline {
		result.Pipeline = e.CheckPipeline(result.Host)
	}

	// Virtual host check
	if e.opts.VHost {
		result.VHost = e.CheckVirtualHost(result.Host, result.Host)
	}

	// TLS certificate grab (also needed for TLS probe or JARM)
	if e.opts.TLSGrab || e.opts.TLSProbe || e.opts.JARM {
		result.TLSData = e.GrabTLS(result.Host)
	}

	// JARM fingerprint
	if e.opts.JARM {
		result.JARM = e.JARM(result.Host)
	}

	return result
}

func (e *Engine) resolveHost(host string) ([]string, []string, error) {
	ips, err := net.LookupHost(host)
	if err != nil {
		return nil, nil, err
	}
	cname, _ := net.LookupCNAME(host)
	var cnames []string
	if cname != "" && cname != host+"." {
		cnames = append(cnames, strings.TrimSuffix(cname, "."))
	}
	return ips, cnames, nil
}

func (e *Engine) normalizeTarget(target string) *url.URL {
	target = strings.TrimSpace(target)
	target = shared.TrimProtocol(target)

	if !strings.Contains(target, "://") {
		target = "https://" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil
	}

	if u.Host == "" {
		u, _ = url.Parse("https://" + target)
	}

	return u
}

func (e *Engine) switchProtocol(rawURL string) string {
	if strings.HasPrefix(rawURL, "https://") {
		return strings.Replace(rawURL, "https://", "http://", 1)
	}
	return strings.Replace(rawURL, "http://", "https://", 1)
}

func (e *Engine) parsePorts(portsSpec string) map[string][]int {
	result := make(map[string][]int)
	parts := strings.Split(portsSpec, ",")
	currentProto := "http"
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, ":") {
			kv := strings.SplitN(part, ":", 2)
			currentProto = strings.TrimSpace(kv[0])
			part = strings.TrimSpace(kv[1])
		}
		// Check for nmap-style range: "2-10"
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			var start, end int
			if _, err := fmt.Sscanf(strings.TrimSpace(rangeParts[0]), "%d", &start); err == nil {
				if _, err := fmt.Sscanf(strings.TrimSpace(rangeParts[1]), "%d", &end); err == nil && end >= start {
					if start < 1 || end > 65535 { continue }
					for p := start; p <= end; p++ {
						result[currentProto] = append(result[currentProto], p)
					}
				}
			}
		} else {
			var port int
			if _, err := fmt.Sscanf(part, "%d", &port); err == nil {
				if port >= 1 && port <= 65535 {
					result[currentProto] = append(result[currentProto], port)
				}
			}
		}
	}
	return result
}

func (e *Engine) randomUA() string {
	return e.userAgents[time.Now().UnixNano()%int64(len(e.userAgents))]
}

// getRequestPaths parses the RequestPaths option. It supports:
// - Comma-separated paths: "/admin,/api"
// - File paths: "/tmp/paths.txt" (one path per line)
func (e *Engine) getRequestPaths() []string {
	if e.opts.RequestPaths == "" {
		return nil
	}

	// Try reading as a file first
	if data, err := os.ReadFile(e.opts.RequestPaths); err == nil {
		var paths []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				paths = append(paths, line)
			}
		}
		if len(paths) > 0 {
			return paths
		}
	}

	// Fallback: split by comma
	return shared.SplitByCharAndTrimSpace(e.opts.RequestPaths, ",")
}

// joinPath joins a base URL with a relative path.
// It handles leading slashes and empty paths correctly.
func (e *Engine) joinPath(baseURL, path string) string {
	if path == "" {
		return baseURL
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Remove existing path from base URL
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return baseURL + path
	}

	parsed.Path = path
	parsed.RawPath = ""
	return parsed.String()
}

// extractCSPDomains parses Content-Security-Policy header from the result
// and returns a list of unique hostnames.
func (e *Engine) extractCSPDomains(result *Result) []string {
	var domains []string
	seen := make(map[string]bool)

	for header, values := range result.Headers {
		if !strings.EqualFold(header, "Content-Security-Policy") {
			continue
		}
		for _, value := range values {
			// CSP format: "default-src 'self' https://example.com; script-src https://cdn.example.com"
			directives := strings.Split(value, ";")
			for _, directive := range directives {
				parts := strings.Fields(directive)
				for _, part := range parts {
					if strings.HasPrefix(part, "'") {
						continue
					}
					if strings.HasPrefix(part, "http://") || strings.HasPrefix(part, "https://") {
						// Extract hostname from URL
						clean := strings.TrimPrefix(part, "http://")
						clean = strings.TrimPrefix(clean, "https://")
						// Remove trailing slash
						clean = strings.TrimSuffix(clean, "/")
						// Remove port if present
						if h, _, err := net.SplitHostPort(clean); err == nil {
							clean = h
						}
						if clean != "" && !seen[clean] {
							seen[clean] = true
							domains = append(domains, clean)
						}
					}
				}
			}
		}
	}

	return domains
}

// Close cleans up resources.
func (e *Engine) Close() {
	if e.transport != nil {
		e.transport.CloseIdleConnections()
	}
}

// AllHTTPMethods returns all HTTP methods.
func AllHTTPMethods() []string {
	return []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "CONNECT", "TRACE"}
}

func checkWebSocket(resp *http.Response) bool {
	return strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		strings.EqualFold(resp.Header.Get("Connection"), "upgrade")
}
