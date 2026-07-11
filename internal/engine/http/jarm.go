package http

import (
	"crypto/tls"
	"net"
	"strings"
	"time"
)

// jarmCipherSets defines the 10 TLS cipher suite configurations for JARM fingerprinting.
// Each config presents ciphers in a specific order to observe server selection behavior.
var jarmCipherSets = [10][]uint16{
	// 0: TLS 1.3 ciphers, standard order
	{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256},
	// 1: TLS 1.3 ciphers, reversed order
	{tls.TLS_AES_256_GCM_SHA384, tls.TLS_AES_128_GCM_SHA256, tls.TLS_CHACHA20_POLY1305_SHA256},
	// 2: Only AES-128-GCM
	{tls.TLS_AES_128_GCM_SHA256},
	// 3: Only AES-256-GCM
	{tls.TLS_AES_256_GCM_SHA384},
	// 4: Only CHACHA20
	{tls.TLS_CHACHA20_POLY1305_SHA256},
	// 5: ECDHE ECDSA + AES-GCM
	{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
	// 6: ECDHE RSA + AES-GCM
	{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
	// 7: RSA key exchange + AES-GCM
	{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384},
	// 8: CHACHA20 variants
	{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305},
	// 9: Broad ECDHE mix
	{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
}

// jarmAlphabet is the 64-character alphabet used for JARM fingerprint encoding.
const jarmAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/+"

// jarmFingerprint performs JARM-like TLS fingerprinting.
// Returns a compact fingerprint string derived from server TLS responses.
func (e *Engine) jarmFingerprint(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = extractHost(host)
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "443")
	}

	var parts [10]byte

	for i, ciphers := range jarmCipherSets {
		val := e.jarmProbe(host, ciphers)
		parts[i] = jarmAlphabet[val%64]
	}

	return string(parts[:])
}

// jarmProbe connects with a specific cipher config and returns a fingerprint value.
func (e *Engine) jarmProbe(host string, ciphers []uint16) int {
	config := &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites:       ciphers,
		MinVersion:         tls.VersionTLS12,
		ServerName:         extractHost(host),
	}

	dialer := &net.Dialer{
		Timeout: time.Duration(e.opts.Timeout) * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", host, config)
	if err != nil {
		return 0
	}
	defer conn.Close()

	state := conn.ConnectionState()
	cs := state.CipherSuite
	version := state.Version

	// Fingerprint value combines cipher suite and version
	switch {
	case version == tls.VersionTLS13:
		return 1000 + jarmCipherValue(cs)
	case version == tls.VersionTLS12:
		return 2000 + jarmCipherValue(cs)
	default:
		return 3000 + jarmCipherValue(cs)
	}
}

// jarmCipherValue maps a cipher suite to a stable value for fingerprinting.
func jarmCipherValue(cs uint16) int {
	switch cs {
	case tls.TLS_AES_128_GCM_SHA256:
		return 1
	case tls.TLS_AES_256_GCM_SHA384:
		return 2
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return 3
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return 4
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return 5
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return 6
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return 7
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return 8
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		return 9
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return 10
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return 11
	default:
		return 0
	}
}

// JARM returns the JARM fingerprint for a target host.
// This is the public interface for JARM fingerprinting.
func (e *Engine) JARM(host string) string {
	fp := e.jarmFingerprint(host)
	if fp == "0000000000" {
		return ""
	}
	return fp
}
