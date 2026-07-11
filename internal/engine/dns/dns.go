package dns

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/cdncheck"

	"github.com/0x3n0/lesgo/internal/shared"
)

// Engine is the DNS query engine.
type Engine struct {
	opts      Options
	client    *dns.Client
	cdnClient *cdncheck.Client
	rcodes    map[int]struct{}
	rtFilter  map[string]struct{}
	resolvers []string
	mu        sync.Mutex
}

// New creates a new DNS Engine.
func New(opts Options) (*Engine, error) {
	e := &Engine{
		opts: opts,
		client: &dns.Client{
			Timeout: opts.Timeout,
		},
		rcodes: make(map[int]struct{}),
	}

	// Parse RCODE filter
	e.parseRCodes(opts.RCode)

	// Parse response type filter
	if opts.ResponseTypeFilter != "" {
		e.rtFilter = make(map[string]struct{})
		for _, rt := range strings.Split(opts.ResponseTypeFilter, ",") {
			rt = strings.TrimSpace(strings.ToUpper(rt))
			if rt != "" {
				e.rtFilter[rt] = struct{}{}
			}
		}
	}

	// Load system resolvers or custom ones
	if len(opts.Resolvers) > 0 {
		for _, r := range opts.Resolvers {
			if rr := shared.PrepareResolver(r); rr != "" {
				e.resolvers = append(e.resolvers, rr)
			}
		}
	} else {
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err == nil {
			for _, s := range config.Servers {
				if rr := shared.PrepareResolver(s); rr != "" {
					e.resolvers = append(e.resolvers, rr)
				}
			}
		}
	}
	if len(e.resolvers) == 0 {
		e.resolvers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}

	// Initialize CDN check
	if opts.CDN {
		e.cdnClient = cdncheck.New()
	}

	// If no record types set, default to A
	if len(opts.RecordTypes) == 0 {
		opts.RecordTypes = []string{"A"}
	}

	return e, nil
}

func (e *Engine) parseRCodes(rcode string) {
	if rcode == "" {
		return
	}
	for _, rc := range strings.Split(rcode, ",") {
		rc = strings.TrimSpace(rc)
		switch strings.ToLower(rc) {
		case "noerror":
			e.rcodes[0] = struct{}{}
		case "formerr":
			e.rcodes[1] = struct{}{}
		case "servfail":
			e.rcodes[2] = struct{}{}
		case "nxdomain":
			e.rcodes[3] = struct{}{}
		case "notimp":
			e.rcodes[4] = struct{}{}
		case "refused":
			e.rcodes[5] = struct{}{}
		default:
			var code int
			if _, err := fmt.Sscanf(rc, "%d", &code); err == nil {
				e.rcodes[code] = struct{}{}
			}
		}
	}
}

// Query queries all configured record types for a host.
func (e *Engine) Query(host string) *Result {
	if e.opts.RateLimiter != nil {
		e.opts.RateLimiter.Take()
	}

	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = shared.ExtractDomain(host)

	result := &Result{
		Host:      host,
		Timestamp: time.Now(),
	}

	// Use hosts file
	if e.opts.HostsFile {
		if ips := e.lookupHostsFile(host); len(ips) > 0 {
			result.A = ips
			result.RCode = "NOERROR"
			result.HostsFile = true
			return result
		}
	}

	var allRaw strings.Builder

	for _, rtype := range e.opts.RecordTypes {
		dnsType := dns.StringToType[strings.ToUpper(rtype)]
		if dnsType == 0 {
			continue
		}

		// Skip AXFR in standard query — zone transfers use AXFR() method
		if dnsType == dns.TypeAXFR {
			continue
		}

		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), dnsType)
		m.RecursionDesired = true
		m.SetEdns0(4096, true)

		var resp *dns.Msg
		var err error
		for attempt := 0; attempt <= e.opts.Retries; attempt++ {
			resolver := e.resolvers[attempt%len(e.resolvers)]
			resp, _, err = e.client.Exchange(m, resolver)
			if err == nil {
				break
			}
		}

		if err != nil || resp == nil {
			continue
		}

		if len(e.rcodes) > 0 {
			if _, ok := e.rcodes[resp.Rcode]; !ok {
				continue
			}
		}

		if resp.Rcode != dns.RcodeSuccess && len(e.rcodes) == 0 {
			result.StatusCode = resp.Rcode
			result.RCode = dns.RcodeToString[resp.Rcode]
			continue
		}

		result.StatusCode = resp.Rcode
		result.RCode = dns.RcodeToString[resp.Rcode]

		if e.opts.Raw {
			allRaw.WriteString(resp.String())
			allRaw.WriteString("\n")
		}

		for _, ans := range resp.Answer {
			switch r := ans.(type) {
			case *dns.A:
				result.A = append(result.A, r.A.String())
			case *dns.AAAA:
				result.AAAA = append(result.AAAA, r.AAAA.String())
			case *dns.CNAME:
				result.CNAME = append(result.CNAME, r.Target)
			case *dns.MX:
				result.MX = append(result.MX, fmt.Sprintf("%s [%d]", r.Mx, r.Preference))
			case *dns.NS:
				result.NS = append(result.NS, r.Ns)
			case *dns.TXT:
				result.TXT = append(result.TXT, strings.Join(r.Txt, " "))
			case *dns.SOA:
				result.SOA = append(result.SOA, r.Ns, r.Mbox)
			case *dns.PTR:
				result.PTR = append(result.PTR, r.Ptr)
			case *dns.CAA:
				result.CAA = append(result.CAA, fmt.Sprintf("%d %s \"%s\"", r.Flag, r.Tag, r.Value))
			case *dns.SRV:
				result.SRV = append(result.SRV, fmt.Sprintf("%s:%d [%d %d]", r.Target, r.Port, r.Priority, r.Weight))
			}
		}

		if rtype == "NS" {
			for _, ns := range resp.Ns {
				if nsRec, ok := ns.(*dns.NS); ok {
					if !contains(result.NS, nsRec.Ns) {
						result.NS = append(result.NS, nsRec.Ns)
					}
				}
			}
		}
	}

	if e.opts.Raw {
		result.Raw = allRaw.String()
	}

	// CDN check
	if e.opts.CDN && e.cdnClient != nil {
		for _, ip := range result.A {
			if matched, name, _, err := e.cdnClient.Check(net.ParseIP(ip)); err == nil && matched {
				result.IsCDN = true
				result.CDNName = name
				break
			}
		}
	}

	// ASN lookup
	if e.opts.ASN && len(result.A) > 0 {
		results, err := asnmap.DefaultClient.GetData(result.A[0])
		if err == nil && len(results) > 0 {
			var cidrs []string
			ipnets, _ := asnmap.GetCIDR(results)
			for _, ipnet := range ipnets {
				cidrs = append(cidrs, ipnet.String())
			}
			result.ASN = &ASNResult{
				AsNumber:  fmt.Sprintf("AS%v", results[0].ASN),
				AsName:    results[0].Org,
				AsCountry: results[0].Country,
				AsRange:   cidrs,
			}
		}
	}

	// Apply response type filter at the very end
	e.filterResult(result)

	return result
}

// AXFR performs a zone transfer.
func (e *Engine) AXFR(host string) (*Result, error) {
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(host))

	transferTimeout := e.opts.Timeout
	if transferTimeout == 0 {
		transferTimeout = 3 * time.Second
	}

	for _, resolver := range e.resolvers {
		transfer := &dns.Transfer{}

		// Run in goroutine with timeout since In() blocks without a context parameter
		type axfrResult struct {
			env <-chan *dns.Envelope
			err error
		}
		ch := make(chan axfrResult, 1)
		go func() {
			env, err := transfer.In(m, resolver)
			ch <- axfrResult{env, err}
		}()

		var env <-chan *dns.Envelope
		var err error
		select {
		case res := <-ch:
			env, err = res.env, res.err
		case <-time.After(transferTimeout):
			err = fmt.Errorf("AXFR timeout after %v", transferTimeout)
		}

		if err != nil {
			continue
		}

		result := &Result{
			Host:      host,
			Timestamp: time.Now(),
		}

		for r := range env {
			if r.Error != nil {
				continue
			}
			for _, ans := range r.RR {
				switch rr := ans.(type) {
				case *dns.A:
					result.A = append(result.A, rr.A.String())
				case *dns.AAAA:
					result.AAAA = append(result.AAAA, rr.AAAA.String())
				case *dns.CNAME:
					result.CNAME = append(result.CNAME, rr.Target)
				case *dns.MX:
					result.MX = append(result.MX, rr.Mx)
				case *dns.NS:
					result.NS = append(result.NS, rr.Ns)
				}
			}
		}

		return result, nil
	}

	return nil, fmt.Errorf("AXFR failed for %s", host)
}

// Lookup performs a simple host lookup (A/AAAA records).
func (e *Engine) Lookup(host string) ([]string, error) {
	result := e.QueryHost(host, dns.TypeA)
	var ips []string
	for _, a := range result.A {
		ips = append(ips, a)
	}
	for _, aaaa := range result.AAAA {
		ips = append(ips, aaaa)
	}
	return ips, nil
}

// QueryHost queries a specific record type.
func (e *Engine) QueryHost(host string, dnsType uint16) *Result {
	result := &Result{
		Host:      host,
		Timestamp: time.Now(),
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dnsType)
	m.RecursionDesired = true

	for _, resolver := range e.resolvers {
		resp, _, err := e.client.Exchange(m, resolver)
		if err != nil || resp == nil {
			continue
		}

		for _, ans := range resp.Answer {
			switch r := ans.(type) {
			case *dns.A:
				result.A = append(result.A, r.A.String())
			case *dns.AAAA:
				result.AAAA = append(result.AAAA, r.AAAA.String())
			}
		}
		break
	}

	return result
}

func (e *Engine) lookupHostsFile(host string) []string {
	data, err := net.LookupHost(host)
	if err != nil {
		return nil
	}
	return data
}

// Close cleans up resources.
func (e *Engine) Close() {}

// Generate random domain for wildcard detection
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	ret := make([]byte, n)
	for i := range ret {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		ret[i] = letters[num.Int64()]
	}
	return string(ret)
}

// filterResult applies the response type filter to a result, clearing fields
// whose record types are not in the filter set.
func (e *Engine) filterResult(result *Result) {
	if len(e.rtFilter) == 0 {
		return
	}
	if _, ok := e.rtFilter["A"]; !ok {
		result.A = nil
	}
	if _, ok := e.rtFilter["AAAA"]; !ok {
		result.AAAA = nil
	}
	if _, ok := e.rtFilter["CNAME"]; !ok {
		result.CNAME = nil
	}
	if _, ok := e.rtFilter["MX"]; !ok {
		result.MX = nil
	}
	if _, ok := e.rtFilter["NS"]; !ok {
		result.NS = nil
	}
	if _, ok := e.rtFilter["TXT"]; !ok {
		result.TXT = nil
	}
	if _, ok := e.rtFilter["SOA"]; !ok {
		result.SOA = nil
	}
	if _, ok := e.rtFilter["PTR"]; !ok {
		result.PTR = nil
	}
	if _, ok := e.rtFilter["CAA"]; !ok {
		result.CAA = nil
	}
	if _, ok := e.rtFilter["SRV"]; !ok {
		result.SRV = nil
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
