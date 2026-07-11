package http

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

// CheckHTTP2 checks if a server supports HTTP/2.
func (e *Engine) CheckHTTP2(host string) bool {
	host = ensurePort(host, "443")

	config := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	dialer := &net.Dialer{
		Timeout: time.Duration(e.opts.Timeout) * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", host, config)
	if err != nil {
		return false
	}
	defer conn.Close()

	protocol := conn.ConnectionState().NegotiatedProtocol
	return protocol == "h2"
}

// CheckPipeline checks if a server supports HTTP/1.1 pipelining.
func (e *Engine) CheckPipeline(host string) bool {
	host = ensurePort(host, "80")

	conn, err := net.DialTimeout("tcp", host, time.Duration(e.opts.Timeout)*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Send two pipelined requests
	request1 := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", strings.Split(host, ":")[0])
	request2 := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", strings.Split(host, ":")[0])

	conn.SetDeadline(time.Now().Add(time.Duration(e.opts.Timeout) * time.Second))
	_, err = conn.Write([]byte(request1 + request2))
	if err != nil {
		return false
	}

	// Try to read both responses
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 10 {
		return false
	}

	// Check if we got at least one HTTP response
	response := string(buf[:n])
	return strings.Count(response, "HTTP/1.") >= 2
}

// CheckVirtualHost checks if a VHOST exists for a given hostname.
func (e *Engine) CheckVirtualHost(host, vhost string) bool {
	host = ensurePort(host, "443")

	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         vhost,
	}

	dialer := &net.Dialer{
		Timeout: time.Duration(e.opts.Timeout) * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", host, config)
	if err != nil {
		gologger.Debug().Msgf("VHOST check failed for %s on %s: %v", vhost, host, err)
		return false
	}
	defer conn.Close()

	return conn.ConnectionState().ServerName == vhost
}

func ensurePort(host, defaultPort string) string {
	if _, _, err := net.SplitHostPort(host); err != nil {
		return net.JoinHostPort(host, defaultPort)
	}
	return host
}
