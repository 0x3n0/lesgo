package runner

import (
	"testing"

	"github.com/projectdiscovery/goflags"
)

func TestRunSelectionTakeoverOnlyWithInputTarget(t *testing.T) {
	opts := &Options{
		InputTargets: goflags.StringSlice{"example.com"},
		Takeover:     true,
	}

	if opts.RunDNS() {
		t.Fatal("takeover-only -u input should not run DNS")
	}
	if opts.RunHTTP() {
		t.Fatal("takeover-only -u input should not run HTTP")
	}
	if !opts.RunTakeover() {
		t.Fatal("takeover flag should run takeover")
	}
}

func TestRunSelectionInputTargetDefaultsToSubdomainDiscovery(t *testing.T) {
	opts := &Options{InputTargets: goflags.StringSlice{"example.com"}}

	if opts.RunDNS() {
		t.Fatal("-u shorthand should not run DNS")
	}
	if opts.RunSubdomain() {
		t.Fatal("-u shorthand without domain input should not run subdomain discovery")
	}
	if !opts.RunHTTP() {
		t.Fatal("-u shorthand without engine flags should run HTTP probing by default")
	}
}

func TestRunSelectionListDefaultsToSubdomainDiscovery(t *testing.T) {
	opts := &Options{InputFile: "targets.txt"}

	if opts.RunDNS() || opts.RunTakeover() {
		t.Fatal("-l without engine flags should not run DNS or takeover")
	}
	if !opts.RunSubdomain() {
		t.Fatal("-l without engine flags should run subdomain discovery")
	}
	if !opts.RunHTTP() {
		t.Fatal("-l without engine flags should run HTTP probing by default")
	}
}

func TestRunSelectionDomainDefaultsToSubdomainDiscovery(t *testing.T) {
	opts := &Options{Domains: goflags.StringSlice{"example.com"}}

	if opts.RunDNS() || opts.RunTakeover() {
		t.Fatal("-d without engine flags should not run DNS or takeover")
	}
	if !opts.RunSubdomain() {
		t.Fatal("-d without engine flags should run subdomain discovery")
	}
	if !opts.RunHTTP() {
		t.Fatal("-d without engine flags should run HTTP probing by default")
	}
}

func TestRunSelectionStdinDefaultsToSubdomainAndHTTP(t *testing.T) {
	opts := &Options{Stdin: true}

	if opts.RunDNS() || opts.RunTakeover() {
		t.Fatal("stdin without engine flags should not run DNS or takeover")
	}
	if !opts.RunSubdomain() {
		t.Fatal("stdin without engine flags should run subdomain discovery")
	}
	if !opts.RunHTTP() {
		t.Fatal("stdin without engine flags should run HTTP probing by default")
	}
}

func TestRunSelectionTakeoverWithExplicitHTTPRunsBoth(t *testing.T) {
	opts := &Options{
		InputTargets: goflags.StringSlice{"example.com"},
		Takeover:     true,
		StatusCode:   true,
	}

	if !opts.RunHTTP() {
		t.Fatal("explicit HTTP probe flag should run HTTP even with takeover")
	}
	if !opts.RunTakeover() {
		t.Fatal("takeover flag should run takeover")
	}
}

func TestRunSelectionHTTPFlagRunsHTTPOnly(t *testing.T) {
	opts := &Options{
		InputTargets: goflags.StringSlice{"example.com"},
		StatusCode:   true,
	}

	if opts.RunDNS() || opts.RunSubdomain() || opts.RunTakeover() {
		t.Fatal("HTTP flags should not implicitly run DNS, subdomain, or takeover")
	}
	if !opts.RunHTTP() {
		t.Fatal("HTTP flag should run HTTP")
	}
}

func TestRunSelectionDNSFlagRunsDNSOnly(t *testing.T) {
	opts := &Options{
		InputTargets: goflags.StringSlice{"example.com"},
		A:            true,
	}

	if opts.RunHTTP() || opts.RunSubdomain() || opts.RunTakeover() {
		t.Fatal("DNS flags should not implicitly run HTTP, subdomain, or takeover")
	}
	if !opts.RunDNS() {
		t.Fatal("DNS flag should run DNS")
	}
}

func TestRunSelectionDomainWithHTTPProbeRunsSubdomainThenHTTP(t *testing.T) {
	opts := &Options{
		Domains:    goflags.StringSlice{"example.com"},
		TechDetect: true,
	}

	if opts.RunDNS() || opts.RunTakeover() {
		t.Fatal("-d mlb.com -td should not implicitly run DNS or takeover")
	}
	if !opts.RunSubdomain() {
		t.Fatal("-d mlb.com -td should run subdomain discovery")
	}
	if !opts.RunHTTP() {
		t.Fatal("-d mlb.com -td should run HTTP probing")
	}
}

func TestRunSelectionDomainWithHTTPProbesRunsSubdomainThenHTTP(t *testing.T) {
	opts := &Options{
		Domains:     goflags.StringSlice{"example.com"},
		StatusCode:  true,
		ContentType: true,
		TechDetect:  true,
	}

	if opts.RunDNS() || opts.RunTakeover() {
		t.Fatal("-d with HTTP probe flags should not implicitly run DNS or takeover")
	}
	if !opts.RunSubdomain() {
		t.Fatal("-d with HTTP probe flags should run subdomain discovery")
	}
	if !opts.RunHTTP() {
		t.Fatal("-d with HTTP probe flags should run HTTP probing")
	}
}

func TestRunSelectionDomainWithHTTPProbeAndDNSRunsAllThree(t *testing.T) {
	opts := &Options{
		Domains:    goflags.StringSlice{"example.com"},
		TechDetect: true,
		A:          true,
	}

	if !opts.RunSubdomain() {
		t.Fatal("-d -td -a should run subdomain discovery")
	}
	if !opts.RunHTTP() {
		t.Fatal("-d -td -a should run HTTP")
	}
	if !opts.RunDNS() {
		t.Fatal("-d -td -a should run DNS")
	}
}

func TestRunSelectionTargetWithHTTPProbeDoesNotRunSubdomain(t *testing.T) {
	// -u (direct target) with HTTP flags should NOT run subdomain discovery
	opts := &Options{
		InputTargets: goflags.StringSlice{"example.com"},
		StatusCode:   true,
	}

	if opts.RunSubdomain() || opts.RunDNS() || opts.RunTakeover() {
		t.Fatal("-u with HTTP flags should not run subdomain, DNS, or takeover")
	}
	if !opts.RunHTTP() {
		t.Fatal("-u with HTTP flags should run HTTP")
	}
}

func TestRunSelectionDomainWithHTTPFlagDoesNotRunSubdomainWhenOnlyDNSDesired(t *testing.T) {
	// -d with DNS flags should NOT run subdomain discovery
	opts := &Options{
		Domains: goflags.StringSlice{"example.com"},
		A:       true,
	}

	if opts.RunHTTP() || opts.RunSubdomain() || opts.RunTakeover() {
		t.Fatal("-d -a should not run HTTP, subdomain, or takeover")
	}
	if !opts.RunDNS() {
		t.Fatal("-d -a should run DNS")
	}
}

func TestRunSelectionDiscoverTakeoverRunsSubdomainThenTakeover(t *testing.T) {
	opts := &Options{
		InputTargets:     goflags.StringSlice{"example.com"},
		DiscoverTakeover: true,
	}

	if opts.RunDNS() || opts.RunHTTP() {
		t.Fatal("-dt should not run DNS or HTTP")
	}
	if !opts.RunSubdomain() || !opts.RunTakeover() {
		t.Fatal("-dt should run subdomain discovery and takeover")
	}
}
