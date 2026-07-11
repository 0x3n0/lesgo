package runner

import (
	"testing"

	"github.com/0x3n0/lesgo/internal/engine/dns"
)

func TestIsWildcardResult(t *testing.T) {
	tests := []struct {
		name        string
		result      *dns.Result
		wildcardIPs []string
		expect      bool
	}{
		{
			name:        "nil wildcard IPs",
			result:      &dns.Result{A: []string{"1.2.3.4"}},
			wildcardIPs: nil,
			expect:      false,
		},
		{
			name:        "empty wildcard IPs",
			result:      &dns.Result{A: []string{"1.2.3.4"}},
			wildcardIPs: []string{},
			expect:      false,
		},
		{
			name:        "no match",
			result:      &dns.Result{A: []string{"1.2.3.4"}},
			wildcardIPs: []string{"5.6.7.8"},
			expect:      false,
		},
		{
			name:        "exact single match",
			result:      &dns.Result{A: []string{"1.2.3.4"}},
			wildcardIPs: []string{"1.2.3.4"},
			expect:      true,
		},
		{
			name:        "match among multiple IPs",
			result:      &dns.Result{A: []string{"9.9.9.9", "1.2.3.4"}},
			wildcardIPs: []string{"1.2.3.4", "5.6.7.8"},
			expect:      true,
		},
		{
			name:        "no match among multiple",
			result:      &dns.Result{A: []string{"9.9.9.9", "8.8.8.8"}},
			wildcardIPs: []string{"1.2.3.4", "5.6.7.8"},
			expect:      false,
		},
		{
			name:        "empty result A records",
			result:      &dns.Result{A: nil},
			wildcardIPs: []string{"1.2.3.4"},
			expect:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isWildcardResult(tc.result, tc.wildcardIPs)
			if got != tc.expect {
				t.Errorf("isWildcardResult(%v, %v) = %v, want %v",
					tc.result.A, tc.wildcardIPs, got, tc.expect)
			}
		})
	}
}

func TestDNSRecordTypesIncludesAXFR(t *testing.T) {
	opts := &Options{AXFR: true}
	types := opts.DNSRecordTypes()
	found := false
	for _, rt := range types {
		if rt == "AXFR" {
			found = true
			break
		}
	}
	if !found {
		t.Error("DNSRecordTypes() should include AXFR when AXFR option is true")
	}
}

func TestDNSRecordTypesExcludesAXFR(t *testing.T) {
	opts := &Options{A: true, AXFR: false}
	types := opts.DNSRecordTypes()
	for _, rt := range types {
		if rt == "AXFR" {
			t.Error("DNSRecordTypes() should not include AXFR when AXFR option is false")
		}
	}
}

func TestResponseTypeFilterOptionWired(t *testing.T) {
	opts := &Options{RespTypeFilter: "a,cname"}
	if opts.RespTypeFilter != "a,cname" {
		t.Error("RespTypeFilter option should be set from -rtf flag")
	}
	if !opts.hasDNSFlags() {
		t.Error("hasDNSFlags() should return true when RespTypeFilter is set")
	}
	if !opts.RunDNS() {
		t.Error("RunDNS() should return true when RespTypeFilter is set")
	}
}

func TestTraceOptionsWiring(t *testing.T) {
	opts := &Options{DNSTrace: true, TraceMaxRecursion: 2}
	if !opts.DNSTrace {
		t.Error("DNSTrace should be set from -trace flag")
	}
	if opts.TraceMaxRecursion != 2 {
		t.Error("TraceMaxRecursion should be set from -trace-max-recursion flag")
	}
	if !opts.hasDNSFlags() {
		t.Error("hasDNSFlags() should return true when DNSTrace is set")
	}
}

func TestWildcardOptionsWiring(t *testing.T) {
	opts := &Options{WildcardDomain: "example.com", WildcardThreshold: 3}
	if opts.WildcardDomain != "example.com" {
		t.Error("WildcardDomain should be set from -wd flag")
	}
	if opts.WildcardThreshold != 3 {
		t.Error("WildcardThreshold should be set from -wt flag")
	}
	if !opts.hasDNSFlags() {
		t.Error("hasDNSFlags() should return true when WildcardDomain is set")
	}
}
