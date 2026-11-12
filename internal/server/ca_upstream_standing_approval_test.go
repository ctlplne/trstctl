// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

// OD-8: the grant ceremony's purpose binds the authority, the SPIRE server's
// principal, its trust domain, how long the approval lasts and the whole CA
// spec, so custodians approve exactly one grant; a malformed grant is refused
// before any ceremony opens.
func TestUpstreamStandingApprovalPurposeBindsEveryFieldOD8(t *testing.T) {
	const caID = "11111111-1111-4111-8111-111111111111"
	spec := api.CASpec{CommonName: "SPIRE Server CA", TTLSeconds: 3600, SignatureAlgorithm: "ecdsa-p256", PermittedDNSDomains: []string{"example.org"}}
	base, err := upstreamStandingApprovalPurpose(caID, "spire-server-a", "od8.test", 86400, spec)
	if err != nil || base == "" {
		t.Fatalf("purpose = %q, %v", base, err)
	}
	if again, _ := upstreamStandingApprovalPurpose(caID, "spire-server-a", "od8.test", 86400, spec); again != base {
		t.Fatalf("the purpose is not stable: %q then %q", base, again)
	}
	with := func(change func(*api.CASpec)) api.CASpec {
		out := spec
		out.PermittedDNSDomains = append([]string(nil), spec.PermittedDNSDomains...)
		change(&out)
		return out
	}
	variants := map[string]struct {
		caID, principal, trustDomain string
		validFor                     int64
		spec                         api.CASpec
	}{
		"another authority":    {"22222222-2222-4222-8222-222222222222", "spire-server-a", "od8.test", 86400, spec},
		"another principal":    {caID, "spire-server-b", "od8.test", 86400, spec},
		"another trust domain": {caID, "spire-server-a", "other.test", 86400, spec},
		"a longer approval":    {caID, "spire-server-a", "od8.test", 86401, spec},
		"a longer CA lifetime": {caID, "spire-server-a", "od8.test", 86400, with(func(s *api.CASpec) { s.TTLSeconds = 7200 })},
		"another common name":  {caID, "spire-server-a", "od8.test", 86400, with(func(s *api.CASpec) { s.CommonName = "Other CA" })},
		"other DNS domains":    {caID, "spire-server-a", "od8.test", 86400, with(func(s *api.CASpec) { s.PermittedDNSDomains = []string{"example.com"} })},
	}
	for name, v := range variants {
		got, err := upstreamStandingApprovalPurpose(v.caID, v.principal, v.trustDomain, v.validFor, v.spec)
		if err != nil || got == base {
			t.Errorf("%s: purpose = %q, %v; want a different purpose", name, got, err)
		}
	}
	refused := map[string]struct {
		caID, principal, trustDomain string
		validFor                     int64
		spec                         api.CASpec
	}{
		"no authority":               {"", "spire-server-a", "od8.test", 86400, spec},
		"no principal":               {caID, "", "od8.test", 86400, spec},
		"a padded principal":         {caID, " spire-server-a", "od8.test", 86400, spec},
		"an uppercase trust domain":  {caID, "spire-server-a", "OD8.test", 86400, spec},
		"a trust domain with a path": {caID, "spire-server-a", "od8.test/ns", 86400, spec},
		"no validity":                {caID, "spire-server-a", "od8.test", 0, spec},
		"more than 90 days":          {caID, "spire-server-a", "od8.test", 90*86400 + 1, spec},
		"no CA lifetime":             {caID, "spire-server-a", "od8.test", 86400, with(func(s *api.CASpec) { s.TTLSeconds = 0 })},
	}
	for name, v := range refused {
		if _, err := upstreamStandingApprovalPurpose(v.caID, v.principal, v.trustDomain, v.validFor, v.spec); !errors.Is(err, api.ErrCAHierarchyInvalid) {
			t.Errorf("%s: err = %v; want ErrCAHierarchyInvalid", name, err)
		}
	}
}

// OD-8: a CA requested under a standing approval matches the approved spec in
// every field but its lifetime, which may only be shorter.
func TestSameApprovedSpecAllowsOnlyAShorterLifetimeOD8(t *testing.T) {
	approved := api.CASpec{CommonName: "SPIRE Server CA", TTLSeconds: 3600, SignatureAlgorithm: "ecdsa-p256",
		PermittedDNSDomains: []string{"example.org"}, ExtendedKeyUsages: []string{"serverAuth"}}
	with := func(change func(*api.CASpec)) api.CASpec {
		out := approved
		out.PermittedDNSDomains = append([]string(nil), approved.PermittedDNSDomains...)
		out.ExtendedKeyUsages = append([]string(nil), approved.ExtendedKeyUsages...)
		change(&out)
		return out
	}
	for name, requested := range map[string]api.CASpec{
		"the approved spec":       approved,
		"a shorter lifetime":      with(func(s *api.CASpec) { s.TTLSeconds = 1800 }),
		"the algorithm's casing":  with(func(s *api.CASpec) { s.SignatureAlgorithm = "ECDSA-P256" }),
		"a one-second lifetime":   with(func(s *api.CASpec) { s.TTLSeconds = 1 }),
		"the approved max length": with(func(s *api.CASpec) { s.TTLSeconds = 3600 }),
	} {
		if !sameApprovedSpec(approved, requested) {
			t.Errorf("%s: refused", name)
		}
	}
	for name, requested := range map[string]api.CASpec{
		"a longer lifetime":     with(func(s *api.CASpec) { s.TTLSeconds = 3601 }),
		"no lifetime":           with(func(s *api.CASpec) { s.TTLSeconds = 0 }),
		"another common name":   with(func(s *api.CASpec) { s.CommonName = "Other CA" }),
		"a longer path":         with(func(s *api.CASpec) { s.MaxPathLen = 1 }),
		"another algorithm":     with(func(s *api.CASpec) { s.SignatureAlgorithm = "rsa-2048" }),
		"other DNS domains":     with(func(s *api.CASpec) { s.PermittedDNSDomains = []string{"example.com"} }),
		"no DNS domains":        with(func(s *api.CASpec) { s.PermittedDNSDomains = nil }),
		"another key usage set": with(func(s *api.CASpec) { s.ExtendedKeyUsages = append(s.ExtendedKeyUsages, "clientAuth") }),
	} {
		if sameApprovedSpec(approved, requested) {
			t.Errorf("%s: accepted", name)
		}
	}
}
