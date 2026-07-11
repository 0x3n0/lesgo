package shared

import (
	"net"
	"strings"
)

// IsIPv4 checks if IP is v4.
func IsIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}

// IsIPv6 checks if IP is v6.
func IsIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

// IsIP checks if the string is a valid IP address.
func IsIP(s string) bool {
	return net.ParseIP(s) != nil
}

// IsValidResolver checks if a resolver address is usable.
func IsValidResolver(resolver string) bool {
	// Remove port if present
	host := resolver
	if h, _, err := net.SplitHostPort(resolver); err == nil {
		host = h
	}
	// Remove IPv6 scope ID
	if idx := strings.Index(host, "%"); idx != -1 {
		return false // Skip link-local with scope IDs
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true // Hostname resolver, assume valid
	}
	if ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.IsLoopback() {
		return true // localhost is fine
	}
	return true
}

// PrepareResolver ensures resolver address has port 53 if missing.
// Returns empty string if the resolver is invalid and should be skipped.
func PrepareResolver(resolver string) string {
	resolver = strings.TrimSpace(resolver)
	if resolver == "" {
		return ""
	}
	if !IsValidResolver(resolver) {
		return ""
	}
	if _, _, err := net.SplitHostPort(resolver); err != nil {
		return net.JoinHostPort(resolver, "53")
	}
	return resolver
}
