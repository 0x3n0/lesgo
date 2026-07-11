package http

import (
	nethttp "net/http"
	"net/http/httptest"
	"testing"
)

func TestCSPProbeEndToEnd(t *testing.T) {
	// Server that returns CSP headers
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src https://example.com https://example.org; img-src https://example.net")
		w.WriteHeader(nethttp.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	engine, err := New(Options{
		Timeout:          5,
		CSPProbe:         true,
		NoFallbackScheme: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	results := engine.Probe(server.URL)

	// Should have original result PLUS 3 CSP probe results
	if len(results) < 2 {
		t.Fatalf("expected at least 2 results (original + CSP probes), got %d", len(results))
	}

	// First result should be the original
	if results[0].Err != nil {
		t.Fatalf("original probe failed: %v", results[0].Err)
	}

	// Collect hostnames
	hosts := make(map[string]bool)
	for _, r := range results {
		hosts[r.Host] = true
		t.Logf("Result: host=%s status=%d err=%v", r.Host, r.StatusCode, r.Err)
	}

	// Should include example.com, example.org, example.net
	expected := []string{"example.com", "example.org", "example.net"}
	for _, h := range expected {
		if !hosts[h] {
			t.Errorf("missing CSP probe result for %s", h)
		}
	}
}

func TestCSPProbeWithoutFlag(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src https://example.com")
		w.WriteHeader(nethttp.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	engine, err := New(Options{
		Timeout:          5,
		CSPProbe:         false, // CSP probe disabled
		NoFallbackScheme: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	results := engine.Probe(server.URL)

	// Without CSPProbe, should only return the original result
	if len(results) != 1 {
		t.Fatalf("expected 1 result without CSPProbe, got %d", len(results))
	}
}
