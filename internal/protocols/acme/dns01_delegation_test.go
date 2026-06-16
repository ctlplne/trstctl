package acme_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/protocols/acme"
)

type fakeCNAME struct {
	m   map[string]string
	err error
}

func (f fakeCNAME) LookupCNAME(_ context.Context, name string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if c, ok := f.m[name]; ok {
		return c, nil
	}
	return name, nil // no CNAME: net.LookupCNAME echoes the queried name
}

func TestDelegatingProviderWritesToValidationZone(t *testing.T) {
	ctx := context.Background()
	const domain = "example.com"
	name := acme.DNS01RecordName(domain) // _acme-challenge.example.com
	const target = "abc123.validation.acme-dns.example.org"
	base := &acme.MemoryDNSProvider{}
	d := acme.DelegatingProvider{
		Base:     base,
		Resolver: fakeCNAME{m: map[string]string{name: target}},
	}
	const value = "the-digest"
	if err := d.PresentTXT(ctx, name, value); err != nil {
		t.Fatalf("PresentTXT: %v", err)
	}
	// The record must land in the validation zone (the delegated target), never at the
	// production name.
	if got, _ := base.LookupTXT(ctx, target); len(got) != 1 || got[0] != value {
		t.Fatalf("delegated target records = %v, want [%q]", got, value)
	}
	if got, _ := base.LookupTXT(ctx, name); len(got) != 0 {
		t.Errorf("production name got a record %v; delegation must never write there", got)
	}
	if err := d.CleanupTXT(ctx, name, value); err != nil {
		t.Fatalf("CleanupTXT: %v", err)
	}
	if got, _ := base.LookupTXT(ctx, target); len(got) != 0 {
		t.Errorf("cleanup left a record at the target: %v", got)
	}
}

func TestDelegatingProviderFailsClosedWhenNotDelegated(t *testing.T) {
	ctx := context.Background()
	name := acme.DNS01RecordName("example.com")
	base := &acme.MemoryDNSProvider{}
	d := acme.DelegatingProvider{Base: base, Resolver: fakeCNAME{m: map[string]string{}}} // no CNAME
	if err := d.PresentTXT(ctx, name, "v"); err == nil {
		t.Fatal("PresentTXT succeeded for a non-delegated name; must fail closed")
	}
	if got, _ := base.LookupTXT(ctx, name); len(got) != 0 {
		t.Error("a record was written despite no delegation")
	}
}

func TestVerifyDelegation(t *testing.T) {
	ctx := context.Background()
	const domain = "example.com"
	name := acme.DNS01RecordName(domain)
	const target = "abc.validation.example.org"
	ok := fakeCNAME{m: map[string]string{name: target}}
	if err := acme.VerifyDelegation(ctx, ok, domain, target); err != nil {
		t.Errorf("VerifyDelegation on a correct CNAME: %v", err)
	}
	if err := acme.VerifyDelegation(ctx, ok, domain, "wrong.example.org"); err == nil {
		t.Error("VerifyDelegation accepted a wrong target")
	}
	bad := fakeCNAME{err: errors.New("servfail")}
	if err := acme.VerifyDelegation(ctx, bad, domain, target); err == nil {
		t.Error("VerifyDelegation must fail closed on a lookup error")
	}
}
