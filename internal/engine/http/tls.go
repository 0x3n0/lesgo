package http

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// GrabTLS performs TLS handshake and extracts certificate data.
func (e *Engine) GrabTLS(host string) *TLSData {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = extractHost(host)

	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "443")
	}

	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	if e.opts.SniName != "" {
		config.ServerName = e.opts.SniName
	}

	dialer := &net.Dialer{
		Timeout: time.Duration(e.opts.Timeout) * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", host, config)
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	cert := certs[0]

	tlsData := &TLSData{
		SubjectCN: cert.Subject.CommonName,
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore.Format(time.RFC3339),
		NotAfter:  cert.NotAfter.Format(time.RFC3339),
		Version:   fmt.Sprintf("%d", cert.Version),
	}

	for _, san := range cert.DNSNames {
		tlsData.SubjectAN = append(tlsData.SubjectAN, san)
	}

	for _, san := range cert.IPAddresses {
		tlsData.SubjectAN = append(tlsData.SubjectAN, san.String())
	}

	return tlsData
}

// extractHost removes the port from host:port.
func extractHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
