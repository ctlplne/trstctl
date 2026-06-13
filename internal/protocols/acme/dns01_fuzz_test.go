package acme_test

import (
	"context"
	"strings"
	"testing"

	"trustctl.io/trustctl/internal/protocols/acme"
)

// dns01FuzzResolver returns a fixed set of TXT records regardless of the queried
// name, so the fuzzer controls exactly what the validator sees.
type dns01FuzzResolver struct{ txt []string }

func (r dns01FuzzResolver) LookupTXT(_ context.Context, _ string) ([]string, error) {
	return r.txt, nil
}

// FuzzDNS01RecordName hardens record-name derivation against hostile domains: it
// must never panic and must always root the name at the _acme-challenge label
// (including the wildcard-stripping path).
func FuzzDNS01RecordName(f *testing.F) {
	for _, s := range []string{"example.com", "*.example.com", "", "*.", "a..b", strings.Repeat("x.", 600)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, domain string) {
		name := acme.DNS01RecordName(domain)
		if !strings.HasPrefix(name, "_acme-challenge.") {
			t.Fatalf("DNS01RecordName(%q) = %q; not rooted at _acme-challenge.", domain, name)
		}
	})
}

// FuzzDNS01Validate hardens the validator against hostile resolver output: no TXT
// payload may crash it, and it must fail closed — accepting only when some record
// exactly equals the expected authorization digest (no partial/substring match).
func FuzzDNS01Validate(f *testing.F) {
	f.Add("token.thumbprint", "v1\nv2")
	f.Add("", "")
	f.Add("k", strings.Repeat(`"`, 64))
	f.Fuzz(func(t *testing.T, keyAuth, txtBlob string) {
		records := strings.Split(txtBlob, "\n")
		v := acme.DNS01Validator{Resolver: dns01FuzzResolver{txt: records}}
		accepted := v.Validate(context.Background(), acme.ChallengeDNS01, "example.com", "token", keyAuth) == nil

		want := acme.DNS01RecordValue(keyAuth)
		present := false
		for _, r := range records {
			if strings.TrimSpace(r) == want {
				present = true
				break
			}
		}
		if accepted != present {
			t.Fatalf("Validate accepted=%v but matching-record-present=%v (keyAuth=%q)", accepted, present, keyAuth)
		}
	})
}
