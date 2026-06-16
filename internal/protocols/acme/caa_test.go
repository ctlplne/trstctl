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
