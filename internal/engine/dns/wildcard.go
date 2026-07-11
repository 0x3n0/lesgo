package dns

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// IsWildcard checks whether a domain returns wildcard DNS responses.
func (e *Engine) IsWildcard(domain string) bool {
	if e.opts.WildcardThreshold <= 0 {
		e.opts.WildcardThreshold = 5
	}

	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")

	ips := make(map[string]int)
	for i := 0; i < e.opts.WildcardThreshold; i++ {
		randomSub := fmt.Sprintf("%s.%s", randomString(10), domain)
		result := e.QueryHost(randomSub, dns.TypeA)

		if len(result.A) == 0 {
			continue
		}

		for _, ip := range result.A {
			ips[ip]++
		}
	}

	for _, count := range ips {
		if count > e.opts.WildcardThreshold/2 {
			return true
		}
	}

	return false
}

// DetectWildcardIPs returns the resolved IPs that are wildcard candidates.
func (e *Engine) DetectWildcardIPs(domain string) []string {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")

	ips := make(map[string]int)
	var candidates []string
	threshold := e.opts.WildcardThreshold
	if threshold <= 0 {
		threshold = 5
	}

	for i := 0; i < threshold; i++ {
		randomSub := fmt.Sprintf("%s.%s", randomString(10), domain)
		result := e.QueryHost(randomSub, dns.TypeA)

		for _, ip := range result.A {
			ips[ip]++
		}
	}

	for ip, count := range ips {
		if count >= 2 {
			candidates = append(candidates, ip)
		}
	}

	return candidates
}

// FilterWildcard filters out wildcard subdomains from the results.
func (e *Engine) FilterWildcard(domain string, subs []string) []string {
	wildcardIPs := e.DetectWildcardIPs(domain)
	if len(wildcardIPs) == 0 {
		return subs
	}

	wildcardSet := make(map[string]struct{})
	for _, ip := range wildcardIPs {
		wildcardSet[ip] = struct{}{}
	}

	var filtered []string
	for _, sub := range subs {
		result := e.Query(sub)
		isWildcard := false
		for _, ip := range result.A {
			if _, ok := wildcardSet[ip]; ok {
				isWildcard = true
				break
			}
		}
		if !isWildcard {
			filtered = append(filtered, sub)
		}
	}

	return filtered
}

// ManualWildcardCheck checks a specific domain for wildcard against a base domain.
func (e *Engine) ManualWildcardCheck(host, baseDomain string) (bool, error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	baseDomain = strings.TrimSuffix(strings.TrimSpace(baseDomain), ".")

	randomA := fmt.Sprintf("%s.%s", randomString(12), baseDomain)
	randomB := fmt.Sprintf("%s.%s", randomString(12), baseDomain)

	resA := e.QueryHost(randomA, dns.TypeA)
	resB := e.QueryHost(randomB, dns.TypeA)
	resHost := e.QueryHost(host, dns.TypeA)

	for _, ipA := range resA.A {
		for _, ipB := range resB.A {
			if ipA == ipB {
				for _, ipH := range resHost.A {
					if ipH == ipA {
						return true, nil
					}
				}
			}
		}
	}

	return false, nil
}

// LookupIP performs a simple A record lookup for a host and returns IPs.
func (e *Engine) LookupIP(host string) []net.IP {
	result := e.QueryHost(host, dns.TypeA)
	var ips []net.IP
	for _, a := range result.A {
		if ip := net.ParseIP(a); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}
