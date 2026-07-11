package dns

import (
	"testing"
)

func TestNewParsesResponseTypeFilter(t *testing.T) {
	opts := Options{
		ResponseTypeFilter: "A,CNAME",
	}
	engine, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}

	if len(engine.rtFilter) != 2 {
		t.Fatalf("expected 2 entries in rtFilter, got %d", len(engine.rtFilter))
	}

	if _, ok := engine.rtFilter["A"]; !ok {
		t.Error("expected 'A' in rtFilter")
	}
	if _, ok := engine.rtFilter["CNAME"]; !ok {
		t.Error("expected 'CNAME' in rtFilter")
	}
}

func TestNewParsesResponseTypeFilterEmpty(t *testing.T) {
	opts := Options{}
	engine, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}

	if engine.rtFilter != nil {
		t.Error("expected nil rtFilter when ResponseTypeFilter is empty")
	}
}

func TestNewParsesResponseTypeFilterSingle(t *testing.T) {
	opts := Options{
		ResponseTypeFilter: "AAAA",
	}
	engine, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}

	if len(engine.rtFilter) != 1 {
		t.Fatalf("expected 1 entry in rtFilter, got %d", len(engine.rtFilter))
	}
	if _, ok := engine.rtFilter["AAAA"]; !ok {
		t.Error("expected 'AAAA' in rtFilter")
	}
}

func TestNewParsesResponseTypeFilterTrimsSpaces(t *testing.T) {
	opts := Options{
		ResponseTypeFilter: " MX , NS ",
	}
	engine, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}

	if len(engine.rtFilter) != 2 {
		t.Fatalf("expected 2 entries in rtFilter, got %d", len(engine.rtFilter))
	}
	if _, ok := engine.rtFilter["MX"]; !ok {
		t.Error("expected 'MX' in rtFilter")
	}
	if _, ok := engine.rtFilter["NS"]; !ok {
		t.Error("expected 'NS' in rtFilter")
	}
}

func TestFilterResultClearsUnmatchedFields(t *testing.T) {
	engine, _ := New(Options{
		ResponseTypeFilter: "A",
	})

	result := &Result{
		A:     []string{"1.2.3.4"},
		AAAA:  []string{"::1"},
		CNAME: []string{"target.example.com"},
		MX:    []string{"mail.example.com"},
		NS:    []string{"ns1.example.com"},
		TXT:   []string{"v=spf1"},
		SOA:   []string{"ns1.example.com", "hostmaster.example.com"},
		PTR:   []string{"ptr.example.com"},
		CAA:   []string{"0 issue \"letsencrypt.org\""},
		SRV:   []string{"sip.example.com:5060"},
	}

	engine.filterResult(result)

	if len(result.A) == 0 {
		t.Error("A records should be preserved when filter includes A")
	}
	if result.AAAA != nil {
		t.Error("AAAA should be nil when filter excludes AAAA")
	}
	if result.CNAME != nil {
		t.Error("CNAME should be nil when filter excludes CNAME")
	}
	if result.MX != nil {
		t.Error("MX should be nil when filter excludes MX")
	}
	if result.NS != nil {
		t.Error("NS should be nil when filter excludes NS")
	}
	if result.TXT != nil {
		t.Error("TXT should be nil when filter excludes TXT")
	}
	if result.SOA != nil {
		t.Error("SOA should be nil when filter excludes SOA")
	}
	if result.PTR != nil {
		t.Error("PTR should be nil when filter excludes PTR")
	}
	if result.CAA != nil {
		t.Error("CAA should be nil when filter excludes CAA")
	}
	if result.SRV != nil {
		t.Error("SRV should be nil when filter excludes SRV")
	}
}

func TestFilterResultPreservesMultipleTypes(t *testing.T) {
	engine, _ := New(Options{
		ResponseTypeFilter: "A,MX,NS",
	})

	result := &Result{
		A:   []string{"1.2.3.4"},
		MX:  []string{"mail.example.com"},
		NS:  []string{"ns1.example.com"},
		TXT: []string{"v=spf1"},
	}

	engine.filterResult(result)

	if len(result.A) == 0 {
		t.Error("A records should be preserved")
	}
	if len(result.MX) == 0 {
		t.Error("MX records should be preserved")
	}
	if len(result.NS) == 0 {
		t.Error("NS records should be preserved")
	}
	if result.TXT != nil {
		t.Error("TXT should be nil when filter excludes TXT")
	}
}

func TestFilterResultNoopWhenFilterEmpty(t *testing.T) {
	engine, _ := New(Options{})

	result := &Result{
		A:    []string{"1.2.3.4"},
		AAAA: []string{"::1"},
	}

	engine.filterResult(result)

	if len(result.A) == 0 {
		t.Error("A records should be preserved when no filter set")
	}
	if len(result.AAAA) == 0 {
		t.Error("AAAA records should be preserved when no filter set")
	}
}

func TestEngineHasTraceOption(t *testing.T) {
	engine, err := New(Options{
		Trace:             true,
		TraceMaxRecursion: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !engine.opts.Trace {
		t.Error("Trace option should be set on engine")
	}
	if engine.opts.TraceMaxRecursion != 2 {
		t.Errorf("TraceMaxRecursion should be 2, got %d", engine.opts.TraceMaxRecursion)
	}
}

func TestEngineHasWildcardOptions(t *testing.T) {
	engine, err := New(Options{
		WildcardDomain:    "example.com",
		WildcardThreshold: 3,
	})
	if err != nil {
		t.Fatal(err)
	}

	if engine.opts.WildcardDomain != "example.com" {
		t.Errorf("WildcardDomain should be 'example.com', got '%s'", engine.opts.WildcardDomain)
	}
	if engine.opts.WildcardThreshold != 3 {
		t.Errorf("WildcardThreshold should be 3, got %d", engine.opts.WildcardThreshold)
	}
}
