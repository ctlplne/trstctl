// SPDX-License-Identifier: BUSL-1.1

package profile

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// P15-L10: every refusal of a request is a *Refusal, flagged when what it
// refuses is a requested name, and its message is the one operators already
// read; a profile that cannot be evaluated is not a refusal.
func TestValidateRefusalsSayWhetherTheyRefuseAName(t *testing.T) {
	p := CertificateProfile{Name: "scoped", Version: 2, AllowedKeyAlgorithms: []string{"ECDSA"}, MinECDSABits: 384,
		AllowedEKUs: []string{"serverAuth"}, AllowedProtocols: []string{"acme"}, MaxValidity: Duration(24 * time.Hour),
		AllowedDNSSuffixes: []string{"internal.test"}, AllowedIPCIDRs: []string{"10.0.0.0/8"},
		AllowedEmailDomains: []string{"mail.test"}, AllowedURIPrefixes: []string{"spiffe://internal.test/"}}
	ok := Request{KeyAlgorithm: "ECDSA", KeyBits: 384, RequestedEKUs: []string{"serverAuth"}, TTL: time.Hour, Protocol: "acme",
		DNSNames: []string{"a.internal.test"}}
	if err := p.Validate(ok); err != nil {
		t.Fatalf("a permitted request: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate     func(*Request)
		identifier bool
		says       string
	}{
		"key algorithm": {func(r *Request) { r.KeyAlgorithm = "RSA" }, false, "does not allow key algorithm"},
		"curve":         {func(r *Request) { r.KeyBits = 256 }, false, "requires ECDSA curves of at least 384 bits"},
		"eku":           {func(r *Request) { r.RequestedEKUs = []string{"clientAuth"} }, false, "does not allow extended key usage"},
		"protocol":      {func(r *Request) { r.Protocol = "est" }, false, "does not permit enrollment protocol"},
		"validity":      {func(r *Request) { r.TTL = 48 * time.Hour }, false, "caps validity at"},
		"dns":           {func(r *Request) { r.DNSNames = []string{"a.outside.test"} }, true, "does not permit DNS SAN"},
		"ip":            {func(r *Request) { r.IPAddresses = []string{"192.0.2.1"} }, true, "does not permit IP SAN"},
		"email":         {func(r *Request) { r.EmailAddresses = []string{"a@outside.test"} }, true, "does not permit email SAN"},
		"uri":           {func(r *Request) { r.URIs = []string{"spiffe://outside.test/x"} }, true, "does not permit URI SAN"},
	} {
		r := ok
		tc.mutate(&r)
		err := p.Validate(r)
		var refusal *Refusal
		if !errors.As(err, &refusal) || refusal.Identifier != tc.identifier || !strings.Contains(err.Error(), tc.says) ||
			!strings.HasPrefix(err.Error(), `profile "scoped" v2 `) {
			t.Errorf("%s: %v (refusal %+v), want a refusal (identifier %v) saying %q", name, err, refusal, tc.identifier, tc.says)
		}
	}
	broken := p
	broken.AllowedIPCIDRs = []string{"not-a-cidr"}
	r := ok
	r.IPAddresses = []string{"10.1.2.3"}
	var refusal *Refusal
	if err := broken.Validate(r); err == nil || errors.As(err, &refusal) {
		t.Fatalf("a profile that cannot be evaluated read as a refusal: %v", err)
	}
}
