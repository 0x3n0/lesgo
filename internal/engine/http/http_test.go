package http

import (
	nethttp "net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeDoesNotFollowRedirectsByDefault(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		switch r.URL.Path {
		case "/":
			nethttp.Redirect(w, r, "/final", nethttp.StatusFound)
		case "/final":
			w.WriteHeader(nethttp.StatusOK)
			_, _ = w.Write([]byte("final"))
		}
	}))
	defer server.Close()

	engine, err := New(Options{Timeout: 2, NoFallbackScheme: true})
	if err != nil {
		t.Fatal(err)
	}

	results := engine.Probe(server.URL)
	if len(results) == 0 {
		t.Fatal("no results returned")
	}
	if results[0].Err != nil {
		t.Fatal(results[0].Err)
	}
	if results[0].StatusCode != nethttp.StatusFound {
		t.Fatalf("expected redirect status without following redirects, got %d", results[0].StatusCode)
	}
}

func TestProbeFollowsRedirectsWhenEnabled(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		switch r.URL.Path {
		case "/":
			nethttp.Redirect(w, r, "/final", nethttp.StatusFound)
		case "/final":
			w.WriteHeader(nethttp.StatusOK)
			_, _ = w.Write([]byte("final"))
		}
	}))
	defer server.Close()

	engine, err := New(Options{
		Timeout:          2,
		NoFallbackScheme: true,
		FollowRedirects:  true,
		MaxRedirects:     5,
	})
	if err != nil {
		t.Fatal(err)
	}

	results := engine.Probe(server.URL)
	if len(results) == 0 {
		t.Fatal("no results returned")
	}
	if results[0].Err != nil {
		t.Fatal(results[0].Err)
	}
	if results[0].StatusCode != nethttp.StatusOK {
		t.Fatalf("expected final status when following redirects, got %d", results[0].StatusCode)
	}
}

func TestCSPDomainExtraction(t *testing.T) {
	engine := &Engine{}
	result := &Result{
		Host: "example.com",
		Headers: map[string][]string{
			"Content-Security-Policy": {
				"default-src 'self'; script-src https://cdn.example.com https://analytics.google.com; img-src https://images.example.com",
			},
		},
	}

	domains := engine.extractCSPDomains(result)
	expected := map[string]bool{
		"cdn.example.com":      true,
		"analytics.google.com": true,
		"images.example.com":   true,
	}

	for _, d := range domains {
		if expected[d] {
			t.Logf("Found: %s", d)
			delete(expected, d)
		} else {
			t.Errorf("Unexpected domain: %s", d)
		}
	}
	for d := range expected {
		t.Errorf("Missing domain: %s", d)
	}
}

func TestCSPDomainExtractionNoHeader(t *testing.T) {
	engine := &Engine{}
	result := &Result{
		Host:    "example.com",
		Headers: map[string][]string{},
	}

	domains := engine.extractCSPDomains(result)
	if len(domains) != 0 {
		t.Errorf("expected no domains, got %d: %v", len(domains), domains)
	}
}

func TestCSPDomainExtractionMultiplePolicies(t *testing.T) {
	engine := &Engine{}
	result := &Result{
		Host: "example.com",
		Headers: map[string][]string{
			"Content-Security-Policy": {
				"default-src https://a.example.com; script-src https://b.example.com",
				"img-src https://c.example.com; font-src https://d.example.com",
			},
		},
	}

	domains := engine.extractCSPDomains(result)
	expected := map[string]bool{
		"a.example.com": true,
		"b.example.com": true,
		"c.example.com": true,
		"d.example.com": true,
	}

	for _, d := range domains {
		if expected[d] {
			t.Logf("Found: %s", d)
			delete(expected, d)
		} else {
			t.Errorf("Unexpected domain: %s", d)
		}
	}
	for d := range expected {
		t.Errorf("Missing domain: %s", d)
	}
}

func TestParsePortsSingle(t *testing.T) {
	engine := &Engine{}
	ports := engine.parsePorts("80,443,8080")
	if len(ports["http"]) != 3 {
		t.Fatalf("expected 3 ports, got %d: %v", len(ports["http"]), ports)
	}
	expected := []int{80, 443, 8080}
	for i, p := range expected {
		if ports["http"][i] != p {
			t.Errorf("port[%d]: expected %d, got %d", i, p, ports["http"][i])
		}
	}
}

func TestParsePortsRange(t *testing.T) {
	engine := &Engine{}
	ports := engine.parsePorts("80-85")
	if len(ports["http"]) != 6 {
		t.Fatalf("expected 6 ports (80-85), got %d: %v", len(ports["http"]), ports)
	}
	expected := []int{80, 81, 82, 83, 84, 85}
	for i, p := range expected {
		if ports["http"][i] != p {
			t.Errorf("port[%d]: expected %d, got %d", i, p, ports["http"][i])
		}
	}
}

func TestParsePortsMixedRange(t *testing.T) {
	engine := &Engine{}
	ports := engine.parsePorts("80,443,8000-8002,9000")
	if len(ports["http"]) != 6 {
		t.Fatalf("expected 6 ports, got %d: %v", len(ports["http"]), ports)
	}
}

func TestParsePortsWithProto(t *testing.T) {
	engine := &Engine{}
	ports := engine.parsePorts("http:80,443,https:443,8443")
	if len(ports["http"]) != 2 {
		t.Errorf("expected 2 http ports, got %d: %v", len(ports["http"]), ports["http"])
	}
	if len(ports["https"]) != 2 {
		t.Errorf("expected 2 https ports, got %d: %v", len(ports["https"]), ports["https"])
	}
}
