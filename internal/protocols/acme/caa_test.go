// SPDX-License-Identifier: BUSL-1.1

package acme_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/protocols/acme"
)

type fakeCAA struct {
	m   map[string][]acme.CAARecord
	err error
}

func (f fakeCAA) LookupCAA(_ context.Context, name string) ([]acme.CAARecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.m[name], nil
}

func issue(ca string) acme.CAARecord     { return acme.CAARecord{Tag: "issue", Value: ca} }
func issuewild(ca string) acme.CAARecord { return acme.CAARecord{Tag: "issuewild", Value: ca} }

func TestCAAAllowsWhenNoRecords(t *testing.T) {
	c := acme.CAAChecker{Resolver: fakeCAA{m: map[string][]acme.CAARecord{}}, IssuerDomain: "ca.test"}
	if err := c.Check(context.Background(), "example.com", false); err != nil {
		t.Errorf("no CAA anywhere should be unrestricted, got: %v", err)
	}
}

func TestCAAAllowsAuthorizedIssuer(t *testing.T) {
	c := acme.CAAChecker{
		Resolver:     fakeCAA{m: map[string][]acme.CAARecord{"example.com": {issue("ca.test")}}},
		IssuerDomain: "ca.test",
	}
	if err := c.Check(context.Background(), "example.com", false); err != nil {
		t.Errorf("authorized issuer should pass, got: %v", err)
	}
}

func TestCAADeniesUnauthorizedIssuer(t *testing.T) {
	c := acme.CAAChecker{
		Resolver:     fakeCAA{m: map[string][]acme.CAARecord{"example.com": {issue("other.ca")}}},
		IssuerDomain: "ca.test",
	}
	if err := c.Check(context.Background(), "example.com", false); err == nil {
		t.Error("unauthorized issuer should be denied")
	}
}

func TestCAAWalksUpToParent(t *testing.T) {
	c := acme.CAAChecker{
		Resolver:     fakeCAA{m: map[string][]acme.CAARecord{"example.com": {issue("ca.test")}}}, // none at the subdomain
		IssuerDomain: "ca.test",
	}
	if err := c.Check(context.Background(), "www.sub.example.com", false); err != nil {
		t.Errorf("should walk up to the parent CAA, got: %v", err)
	}
}

func TestCAAWildcardUsesIssuewild(t *testing.T) {
	recs := []acme.CAARecord{issue("ca.test"), issuewild("other.ca")}
	c := acme.CAAChecker{Resolver: fakeCAA{m: map[string][]acme.CAARecord{"example.com": recs}}, IssuerDomain: "ca.test"}
	// Non-wildcard governed by issue -> allowed.
	if err := c.Check(context.Background(), "example.com", false); err != nil {
		t.Errorf("non-wildcard should use issue and pass: %v", err)
	}
	// Wildcard governed by issuewild -> denied (issuewild names other.ca).
	if err := c.Check(context.Background(), "*.example.com", true); err == nil {
		t.Error("wildcard should use issuewild and be denied for ca.test")
	}
}

func TestCAASemicolonForbidsAll(t *testing.T) {
	c := acme.CAAChecker{
		Resolver:     fakeCAA{m: map[string][]acme.CAARecord{"example.com": {issue(";")}}},
		IssuerDomain: "ca.test",
	}
	if err := c.Check(context.Background(), "example.com", false); err == nil {
		t.Error(`a bare ";" issue property must forbid all issuance`)
	}
}

func TestCAAFailsClosedOnLookupError(t *testing.T) {
	c := acme.CAAChecker{Resolver: fakeCAA{err: errors.New("servfail")}, IssuerDomain: "ca.test"}
	if err := c.Check(context.Background(), "example.com", false); err == nil {
		t.Error("CAA check must fail closed on a lookup error")
	}
}

func TestCAAInspectExplainsUnrestrictedPolicy(t *testing.T) {
	c := acme.CAAChecker{Resolver: fakeCAA{m: map[string][]acme.CAARecord{}}, IssuerDomain: "ca.test"}

	got, err := c.Inspect(context.Background(), "www.example.com", false)
	if err != nil {
		t.Fatalf("inspect unrestricted CAA: %v", err)
	}
	if !got.Unrestricted || !got.Authorized {
		t.Fatalf("inspection = %+v, want unrestricted and authorized", got)
	}
	if got.GoverningName != "" || len(got.Records) != 0 || len(got.AllowedIssuers) != 0 {
		t.Fatalf("inspection = %+v, want no governing record set", got)
	}
	if got.RelevantTag != "issue" {
		t.Fatalf("relevant tag = %q, want issue", got.RelevantTag)
	}
}

func TestCAAInspectExplainsGoverningPolicyAndIssuerParameters(t *testing.T) {
	records := []acme.CAARecord{
		{Flag: 0, Tag: "iodef", Value: "mailto:pki@example.com"},
		{Flag: 0, Tag: "issue", Value: "other.ca; account=123"},
		{Flag: 0, Tag: "issue", Value: "CA.TEST; validationmethods=dns-01"},
		{Flag: 0, Tag: "issue", Value: ";"},
	}
	c := acme.CAAChecker{
		Resolver:     fakeCAA{m: map[string][]acme.CAARecord{"example.com": records}},
		IssuerDomain: "ca.test",
	}

	got, err := c.Inspect(context.Background(), "service.example.com", false)
	if err != nil {
		t.Fatalf("inspect authorized CAA: %v", err)
	}
	if got.GoverningName != "example.com" || got.Unrestricted || !got.Authorized {
		t.Fatalf("inspection = %+v, want governing example.com and authorized", got)
	}
	if got.RelevantTag != "issue" {
		t.Fatalf("relevant tag = %q, want issue", got.RelevantTag)
	}
	if len(got.Records) != len(records) {
		t.Fatalf("records = %+v, want all governing records %+v", got.Records, records)
	}
	wantIssuers := []string{"other.ca", "CA.TEST"}
	if len(got.AllowedIssuers) != len(wantIssuers) {
		t.Fatalf("allowed issuers = %v, want %v", got.AllowedIssuers, wantIssuers)
	}
	for i := range wantIssuers {
		if got.AllowedIssuers[i] != wantIssuers[i] {
			t.Fatalf("allowed issuers = %v, want %v", got.AllowedIssuers, wantIssuers)
		}
	}
}

func TestCAAInspectExplainsWildcardDenial(t *testing.T) {
	records := []acme.CAARecord{issue("ca.test"), issuewild("wildcard.ca")}
	c := acme.CAAChecker{
		Resolver:     fakeCAA{m: map[string][]acme.CAARecord{"example.com": records}},
		IssuerDomain: "ca.test",
	}

	got, err := c.Inspect(context.Background(), "*.example.com", true)
	if err == nil {
		t.Fatal("wildcard inspection should retain the denial error")
	}
	if got.GoverningName != "example.com" || got.RelevantTag != "issuewild" || got.Authorized || got.Unrestricted {
		t.Fatalf("inspection = %+v, want governing wildcard denial", got)
	}
	if len(got.AllowedIssuers) != 1 || got.AllowedIssuers[0] != "wildcard.ca" {
		t.Fatalf("allowed issuers = %v, want [wildcard.ca]", got.AllowedIssuers)
	}
}

func TestCAAInspectPreservesFailedLookupName(t *testing.T) {
	c := acme.CAAChecker{Resolver: fakeCAA{err: errors.New("servfail")}, IssuerDomain: "ca.test"}

	got, err := c.Inspect(context.Background(), "www.example.com", false)
	if err == nil {
		t.Fatal("CAA inspection must fail closed on a lookup error")
	}
	if got.GoverningName != "www.example.com" || got.Authorized || got.Unrestricted {
		t.Fatalf("inspection = %+v, want failed lookup name and fail-closed status", got)
	}
}
