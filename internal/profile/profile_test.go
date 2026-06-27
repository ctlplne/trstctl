package profile_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/profile"
)

func webProfile() profile.CertificateProfile {
	return profile.CertificateProfile{
		Name: "web-server", Version: 3,
		AllowedKeyAlgorithms: []string{"ECDSA", "RSA"},
		MinRSABits:           3072,
		MinECDSABits:         256,
		AllowedEKUs:          []string{"serverAuth"},
		MaxValidity:          profile.Duration(90 * 24 * time.Hour),
		AllowedProtocols:     []string{"api", "acme"},
		AllowedDNSSuffixes:   []string{"example.com"},
	}
}

func TestProfileAcceptsCompliantRequest(t *testing.T) {
	r := profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, RequestedEKUs: []string{"serverAuth"},
		TTL: 30 * 24 * time.Hour, DNSNames: []string{"api.example.com"}, Protocol: "acme"}
	if err := webProfile().Validate(r); err != nil {
		t.Fatalf("compliant request should pass, got %v", err)
	}
}

func TestProfileRejectsDisallowedKeyAlgorithm(t *testing.T) {
	err := webProfile().Validate(profile.Request{KeyAlgorithm: "Ed25519", KeyBits: 256, Protocol: "api"})
	if err == nil || !strings.Contains(err.Error(), "key algorithm") {
		t.Fatalf("want key-algorithm rejection, got %v", err)
	}
}

func TestProfileRejectsWeakRSAKey(t *testing.T) {
	err := webProfile().Validate(profile.Request{KeyAlgorithm: "RSA", KeyBits: 2048, Protocol: "api"})
	if err == nil || !strings.Contains(err.Error(), "RSA") {
		t.Fatalf("want weak-RSA rejection, got %v", err)
	}
}

func TestProfileRejectsDisallowedEKU(t *testing.T) {
	err := webProfile().Validate(profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, RequestedEKUs: []string{"codeSigning"}, Protocol: "api"})
	if err == nil || !strings.Contains(err.Error(), "extended key usage") {
		t.Fatalf("want EKU rejection, got %v", err)
	}
}

func TestProfileRejectsOverLongValidity(t *testing.T) {
	err := webProfile().Validate(profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, TTL: 365 * 24 * time.Hour, Protocol: "api"})
	if err == nil || !strings.Contains(err.Error(), "caps validity") {
		t.Fatalf("want validity rejection, got %v", err)
	}
}

func TestProfileRejectsDisallowedProtocolAndDNS(t *testing.T) {
	if err := webProfile().Validate(profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, Protocol: "scep"}); err == nil {
		t.Error("scep is not an allowed protocol; want rejection")
	}
	if err := webProfile().Validate(profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, Protocol: "api", DNSNames: []string{"api.evil.test"}}); err == nil {
		t.Error("evil.test is outside the allowed suffix; want rejection")
	}
}

// TestProfileDNSSuffixMatchIsLabelBounded is the adversarial regression for
// PKIGOV-005: the DNS-suffix name-constraint matcher must reject hosts that only
// share a textual suffix (notexample.com / evil-example.com) while accepting the
// suffix itself and its proper subdomains. A bare strings.HasSuffix branch fails
// this — the rejected cases below must FAIL pre-fix and PASS post-fix.
func TestProfileDNSSuffixMatchIsLabelBounded(t *testing.T) {
	p := profile.CertificateProfile{
		Name: "suffix-only", Version: 1,
		AllowedDNSSuffixes: []string{"example.com"},
	}
	req := func(name string) profile.Request {
		return profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, Protocol: "api", DNSNames: []string{name}}
	}
	accept := []string{"example.com", "a.example.com", "deep.nested.example.com"}
	reject := []string{
		"notexample.com",       // shares the textual suffix, different registrable domain
		"evil-example.com",     // hyphenated impostor
		"example.com.evil.net", // suffix is a left-anchored substring, not a suffix
		"xexample.com",         // no label boundary
		"com",                  // shorter than the suffix
		"",                     // empty
	}
	for _, name := range accept {
		if err := p.Validate(req(name)); err != nil {
			t.Errorf("suffix example.com should accept %q, got %v", name, err)
		}
	}
	for _, name := range reject {
		if err := p.Validate(req(name)); err == nil {
			t.Errorf("suffix example.com must reject %q (label-boundary suffix match), but it was accepted", name)
		}
	}
}

// TestProfileDNSSuffixLeadingDotNormalized: a configured suffix may be written
// with a leading dot (".example.com"); it must behave identically to the
// dot-free form and still be label-bounded.
func TestProfileDNSSuffixLeadingDotNormalized(t *testing.T) {
	p := profile.CertificateProfile{Name: "dotted", Version: 1, AllowedDNSSuffixes: []string{".example.com"}}
	req := func(name string) profile.Request {
		return profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, Protocol: "api", DNSNames: []string{name}}
	}
	if err := p.Validate(req("a.example.com")); err != nil {
		t.Errorf(".example.com should accept a.example.com, got %v", err)
	}
	if err := p.Validate(req("notexample.com")); err == nil {
		t.Error(".example.com must reject notexample.com")
	}
}

func TestProfileJSONRoundTrip(t *testing.T) {
	p := webProfile()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"2160h0m0s"`) {
		t.Errorf("max_validity should serialize as a duration string: %s", b)
	}
	var got profile.CertificateProfile
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if time.Duration(got.MaxValidity) != 90*24*time.Hour {
		t.Errorf("round-trip validity = %s, want 2160h", time.Duration(got.MaxValidity))
	}
}

func TestRequiresApprovalJSONRoundTrip(t *testing.T) {
	raw, err := json.Marshal(profile.CertificateProfile{Name: "prod", RequiresApproval: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"requires_approval":true`) {
		t.Fatalf("serialized profile = %s, want requires_approval flag", raw)
	}
	var got profile.CertificateProfile
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !got.RequiresApproval {
		t.Fatal("requires_approval did not round-trip")
	}
}
