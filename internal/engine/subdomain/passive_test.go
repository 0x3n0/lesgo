package subdomain

import (
	"context"
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"http://example.com", "example.com"},
		{"https://example.com", "example.com"},
		{"example.com/", "example.com"},
		{"https://example.com/path?q=1", "example.com"},
		{"  example.com  ", "example.com"},
		{"https://sub.example.com/", "sub.example.com"},
	}
	for _, tc := range tests {
		got := normalizeDomain(tc.input)
		if got != tc.expected {
			t.Errorf("normalizeDomain(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestExtractParentDomain(t *testing.T) {
	tests := []struct {
		sub      string
		root     string
		expected string
	}{
		// x.y.example.com -> y.example.com
		{"x.y.example.com", "example.com", "y.example.com"},
		// a.b.c.example.com -> b.c.example.com
		{"a.b.c.example.com", "example.com", "b.c.example.com"},
		// y.example.com -> "" (only one extra label, no intermediate parent)
		{"y.example.com", "example.com", ""},
		// same as root -> ""
		{"example.com", "example.com", ""},
		// different root -> ""
		{"x.other.com", "example.com", ""},
		// with trailing dots
		{"x.y.example.com.", "example.com.", "y.example.com"},
		// single label extra
		{"sub.example.com", "example.com", ""},
	}
	for _, tc := range tests {
		got := extractParentDomain(tc.sub, tc.root)
		if got != tc.expected {
			t.Errorf("extractParentDomain(%q, %q) = %q, want %q",
				tc.sub, tc.root, got, tc.expected)
		}
	}
}

func TestMakeSet(t *testing.T) {
	items := []string{"Example.COM", "API.Test.COM", "sub"}
	s := makeSet(items)
	if len(s) != 3 {
		t.Errorf("makeSet should have 3 items, got %d", len(s))
	}
	if _, ok := s["example.com"]; !ok {
		t.Error("makeSet should lowercase keys")
	}
	if _, ok := s["api.test.com"]; !ok {
		t.Error("makeSet should lowercase keys")
	}
}

func TestMatchesAny(t *testing.T) {
	items := makeSet([]string{"example.com", "api.test.com"})

	tests := []struct {
		sub      string
		expected bool
	}{
		{"example.com", true},
		{"EXAMPLE.COM", true},
		{"sub.example.com", true},    // suffix match
		{"api.test.com", true},
		{"deep.api.test.com", true},  // suffix match
		{"other.com", false},
		{"notmatched.org", false},
	}
	for _, tc := range tests {
		got := matchesAny(tc.sub, items)
		if got != tc.expected {
			t.Errorf("matchesAny(%q) = %v, want %v", tc.sub, got, tc.expected)
		}
	}
}

func TestMatchesAnyEmptySet(t *testing.T) {
	items := makeSet([]string{})
	if matchesAny("anything.com", items) {
		t.Error("matchesAny should return false for empty set")
	}
}

func TestIsIPLiteral(t *testing.T) {
	tests := []struct {
		sub      string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"example.com", false},
		{"sub.example.com", false},
		{"", false},
	}
	for _, tc := range tests {
		got := isIPLiteral(tc.sub)
		if got != tc.expected {
			t.Errorf("isIPLiteral(%q) = %v, want %v", tc.sub, got, tc.expected)
		}
	}
}

// TestRunWithNoSources verifies the engine returns an error when no sources are configured.
func TestRunWithNoSources(t *testing.T) {
	opts := Options{
		Sources: []string{"nonexistent-source"},
		Timeout: 5,
	}
	engine, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = engine.Run(context.Background(), "example.com")
	if err == nil {
		t.Error("expected error for no sources configured")
	}
}

// TestMatchesAnyEdgeCases tests boundary conditions.
func TestMatchesAnyEdgeCases(t *testing.T) {
	// suffix matching should not match partial labels
	items := makeSet([]string{"ample.com"})
	if matchesAny("example.com", items) {
		t.Error("matchesAny should not match partial labels ('ample.com' should not match 'example.com')")
	}

	// empty subdomain
	if matchesAny("", makeSet([]string{"test"})) {
		t.Error("matchesAny should return false for empty subdomain")
	}
}

// TestExtractParentDomainEdgeCases tests boundary conditions.
func TestExtractParentDomainEdgeCases(t *testing.T) {
	// very deep subdomain
	got := extractParentDomain("a.b.c.d.e.example.com", "example.com")
	expected := "b.c.d.e.example.com"
	if got != expected {
		t.Errorf("extractParentDomain deep = %q, want %q", got, expected)
	}

	// root has multiple labels; sub.api.example.co.uk has 2 extra labels (sub.api)
	// the immediate parent should be api.example.co.uk
	got = extractParentDomain("sub.api.example.co.uk", "example.co.uk")
	expected = "api.example.co.uk"
	if got != expected {
		t.Errorf("extractParentDomain multi-label root = %q, want %q", got, expected)
	}

	// one extra label with multi-label root -> no intermediate parent
	got = extractParentDomain("sub.example.co.uk", "example.co.uk")
	expected = ""
	if got != expected {
		t.Errorf("extractParentDomain single extra on multi-root = %q, want %q", got, expected)
	}
}

// TestMakeSetEmpty verifies empty input produces empty set.
func TestMakeSetEmpty(t *testing.T) {
	s := makeSet(nil)
	if len(s) != 0 {
		t.Errorf("makeSet(nil) should be empty, got %d", len(s))
	}
	s = makeSet([]string{})
	if len(s) != 0 {
		t.Errorf("makeSet([]) should be empty, got %d", len(s))
	}
}

// TestListSources verifies ListSources returns names without error.
func TestListSources(t *testing.T) {
	opts := Options{Timeout: 5, AllSources: true}
	engine, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	names := engine.ListSources()
	if len(names) == 0 {
		t.Error("ListSources should return at least one source")
	}
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			t.Error("ListSources should not contain empty names")
		}
	}
}
