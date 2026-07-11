package takeover

import (
	"reflect"
	"testing"
)

func TestNormalizeResolversDoesNotDoublePort(t *testing.T) {
	got := normalizeResolvers([]string{"1.1.1.1:53", "8.8.8.8"})
	want := []string{"1.1.1.1:53", "8.8.8.8:53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected resolvers: got %#v want %#v", got, want)
	}
}

func TestNewDefaultsToAllChecksWhenNoneSpecified(t *testing.T) {
	engine, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !engine.opts.CheckCNAME || !engine.opts.CheckNS || !engine.opts.CheckHTTP {
		t.Fatalf("expected all checks enabled by default, got %+v", engine.opts)
	}
}

func TestNewPreservesSpecificCheckSelection(t *testing.T) {
	engine, err := New(Options{CheckCNAME: true})
	if err != nil {
		t.Fatal(err)
	}
	if !engine.opts.CheckCNAME {
		t.Fatal("expected CNAME check enabled")
	}
	if engine.opts.CheckNS || engine.opts.CheckHTTP {
		t.Fatalf("unexpected extra checks enabled: %+v", engine.opts)
	}
}

func TestHTTPOnlyFingerprintCanIdentifyService(t *testing.T) {
	engine, err := New(Options{CheckHTTP: true})
	if err != nil {
		t.Fatal(err)
	}

	result := &Result{
		StatusCode: 404,
		Response:   "No such app",
	}
	fp := engine.matchHTTPFingerprint(result, allFingerprints())
	if fp == nil {
		t.Fatal("expected HTTP-only fingerprint match")
	}
	if fp.Name != "Heroku" {
		t.Fatalf("unexpected fingerprint match: %s", fp.Name)
	}
	if result.Evidence != "No such app" {
		t.Fatalf("expected evidence to be set, got %q", result.Evidence)
	}
}
