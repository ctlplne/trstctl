package acme_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// validatorFunc adapts a function to the Validator interface for routing tests.
type validatorFunc func(ctx context.Context, ct, domain, token, keyAuth string) error

func (f validatorFunc) Validate(ctx context.Context, ct, domain, token, keyAuth string) error {
	return f(ctx, ct, domain, token, keyAuth)
}

// fakeResolver returns canned TXT records (or an error) for DNS-01 tests.
type fakeResolver struct {
	records map[string][]string
	err     error
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.records[name], nil
}

// ---- DNS-01 -------------------------------------------------------------

func TestDNS01ValidatorAcceptsMatchingRecord(t *testing.T) {
	const domain, keyAuth = "example.com", "tok.thumbprint"
	name := acmesrv.DNS01RecordName(domain)
	val := acmesrv.DNS01RecordValue(keyAuth)
	v := acmesrv.DNS01Validator{Resolver: fakeResolver{records: map[string][]string{
		name: {"some-unrelated-txt", " " + val + " "}, // surrounding whitespace tolerated
	}}}
	if err := v.Validate(context.Background(), acmesrv.ChallengeDNS01, domain, "tok", keyAuth); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
}

func TestDNS01ValidatorWildcardValidatesAtBaseLabel(t *testing.T) {
	const domain, keyAuth = "*.example.com", "tok.thumbprint"
	name := acmesrv.DNS01RecordName(domain)
	if name != "_acme-challenge.example.com" {
		t.Fatalf("wildcard record name = %q, want _acme-challenge.example.com", name)
	}
	v := acmesrv.DNS01Validator{Resolver: fakeResolver{records: map[string][]string{
		name: {acmesrv.DNS01RecordValue(keyAuth)},
	}}}
	if err := v.Validate(context.Background(), acmesrv.ChallengeDNS01, domain, "tok", keyAuth); err != nil {
		t.Fatalf("expected wildcard accept, got %v", err)
	}
}

func TestDNS01ValidatorFailsClosed(t *testing.T) {
	const domain, keyAuth = "example.com", "tok.thumbprint"
	name := acmesrv.DNS01RecordName(domain)

	// Wrong TXT value.
	mismatch := acmesrv.DNS01Validator{Resolver: fakeResolver{records: map[string][]string{name: {"not-the-digest"}}}}
	if err := mismatch.Validate(context.Background(), acmesrv.ChallengeDNS01, domain, "tok", keyAuth); err == nil {
		t.Fatal("expected mismatch to fail, got nil")
	}

	// No record at all.
	empty := acmesrv.DNS01Validator{Resolver: fakeResolver{records: map[string][]string{}}}
	if err := empty.Validate(context.Background(), acmesrv.ChallengeDNS01, domain, "tok", keyAuth); err == nil {
		t.Fatal("expected missing record to fail, got nil")
	}

	// Resolver error.
	failing := acmesrv.DNS01Validator{Resolver: fakeResolver{err: errors.New("SERVFAIL")}}
	if err := failing.Validate(context.Background(), acmesrv.ChallengeDNS01, domain, "tok", keyAuth); err == nil {
		t.Fatal("expected resolver error to fail closed, got nil")
	}

	// Wrong challenge type.
	if err := (acmesrv.DNS01Validator{}).Validate(context.Background(), acmesrv.ChallengeHTTP01, domain, "tok", keyAuth); err == nil {
		t.Fatal("expected wrong-type rejection, got nil")
	}
}

// ---- TLS-ALPN-01 --------------------------------------------------------

func TestTLSALPN01ValidatorAcceptsRealHandshake(t *testing.T) {
	const domain, keyAuth = "host.example", "tok.thumbprint"
	digest := crypto.SHA256Sum([]byte(keyAuth))
	srvAddr, closeFn, err := tlsprobe.NewACMEALPNTestServer(digest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeFn)

	// The validator hard-codes :443 in production; inject a prober pointed at the
	// loopback responder so the rest of the path (ALPN + digest check) runs for real.
	v := acmesrv.TLSALPN01Validator{Prober: func(ctx context.Context, _ string) (tlsprobe.Result, error) {
		return tlsprobe.Probe(ctx, srvAddr, tlsprobe.WithALPN(tlsprobe.ACMETLSALPNProto))
	}}
	if err := v.Validate(context.Background(), acmesrv.ChallengeTLSALPN01, domain, "tok", keyAuth); err != nil {
		t.Fatalf("expected accept against real handshake, got %v", err)
	}
}

func TestTLSALPN01ValidatorRejectsWrongDigest(t *testing.T) {
	const keyAuth = "tok.thumbprint"
	// Responder presents the digest of a DIFFERENT key authorization.
	srvAddr, closeFn, err := tlsprobe.NewACMEALPNTestServer(crypto.SHA256Sum([]byte("attacker.thumbprint")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeFn)
	v := acmesrv.TLSALPN01Validator{Prober: func(ctx context.Context, _ string) (tlsprobe.Result, error) {
		return tlsprobe.Probe(ctx, srvAddr, tlsprobe.WithALPN(tlsprobe.ACMETLSALPNProto))
	}}
	if err := v.Validate(context.Background(), acmesrv.ChallengeTLSALPN01, "host.example", "tok", keyAuth); err == nil {
		t.Fatal("expected digest mismatch to fail, got nil")
	}
}

func TestTLSALPN01ValidatorRejectsMissingALPN(t *testing.T) {
	const keyAuth = "tok.thumbprint"
	// Right digest, but the server did not negotiate acme-tls/1.
	v := acmesrv.TLSALPN01Validator{Prober: func(context.Context, string) (tlsprobe.Result, error) {
		return tlsprobe.Result{NegotiatedProtocol: "", ACMEIdentifier: crypto.SHA256Sum([]byte(keyAuth))}, nil
	}}
	if err := v.Validate(context.Background(), acmesrv.ChallengeTLSALPN01, "host", "tok", keyAuth); err == nil {
		t.Fatal("expected rejection when acme-tls/1 was not negotiated, got nil")
	}
}

func TestTLSALPN01ValidatorFailsClosedOnError(t *testing.T) {
	v := acmesrv.TLSALPN01Validator{Prober: func(context.Context, string) (tlsprobe.Result, error) {
		return tlsprobe.Result{}, errors.New("connection refused")
	}}
	if err := v.Validate(context.Background(), acmesrv.ChallengeTLSALPN01, "host", "tok", "k.t"); err == nil {
		t.Fatal("expected handshake error to fail closed, got nil")
	}
	// Wrong challenge type.
	if err := (acmesrv.TLSALPN01Validator{}).Validate(context.Background(), acmesrv.ChallengeDNS01, "host", "tok", "k.t"); err == nil {
		t.Fatal("expected wrong-type rejection, got nil")
	}
}

// ---- multiplexer (production validator) ---------------------------------

func TestValidatorsRoutesByType(t *testing.T) {
	var got string
	mk := func(tag string) acmesrv.Validator {
		return validatorFunc(func(_ context.Context, ct, _, _, _ string) error {
			got = tag + ":" + ct
			return nil
		})
	}
	m := acmesrv.Validators{HTTP01: mk("http"), DNS01: mk("dns"), TLSALPN01: mk("alpn")}

	for _, tc := range []struct{ typ, want string }{
		{acmesrv.ChallengeHTTP01, "http:http-01"},
		{acmesrv.ChallengeDNS01, "dns:dns-01"},
		{acmesrv.ChallengeTLSALPN01, "alpn:tls-alpn-01"},
	} {
		got = ""
		if err := m.Validate(context.Background(), tc.typ, "d", "t", "k"); err != nil {
			t.Fatalf("%s: unexpected error %v", tc.typ, err)
		}
		if got != tc.want {
			t.Fatalf("%s routed to %q, want %q", tc.typ, got, tc.want)
		}
	}
}

func TestValidatorsFailClosed(t *testing.T) {
	// Unknown challenge type.
	if err := (acmesrv.Validators{}).Validate(context.Background(), "carrier-pigeon-01", "d", "t", "k"); err == nil {
		t.Fatal("expected unknown challenge type to fail, got nil")
	}
	// Known type but no validator wired (nil) — must fail closed, never accept.
	if err := (acmesrv.Validators{}).Validate(context.Background(), acmesrv.ChallengeDNS01, "d", "t", "k"); err == nil {
		t.Fatal("expected unconfigured dns-01 to fail closed, got nil")
	}
}

func TestDefaultValidatorsWiresAllThree(t *testing.T) {
	m := acmesrv.DefaultValidators()
	if m.HTTP01 == nil || m.DNS01 == nil || m.TLSALPN01 == nil {
		t.Fatal("DefaultValidators must wire a real validator for every DV method")
	}
}

// ---- DV method selector -------------------------------------------------

func TestSelectMethod(t *testing.T) {
	cases := []struct {
		name string
		ctx  acmesrv.MethodContext
		want string
		err  bool
	}{
		{"wildcard needs dns-01", acmesrv.MethodContext{Domain: "*.x.com", Wildcard: true, DNSManaged: true}, acmesrv.ChallengeDNS01, false},
		{"wildcard without managed dns errors", acmesrv.MethodContext{Domain: "*.x.com", Wildcard: true}, "", true},
		{"reachable host uses http-01", acmesrv.MethodContext{Domain: "x.com", Port80Reachable: true}, acmesrv.ChallengeHTTP01, false},
		{"no port80 but dns managed uses dns-01", acmesrv.MethodContext{Domain: "x.com", DNSManaged: true}, acmesrv.ChallengeDNS01, false},
		{"no port80 no dns uses tls-alpn-01", acmesrv.MethodContext{Domain: "x.com"}, acmesrv.ChallengeTLSALPN01, false},
		{"override wins", acmesrv.MethodContext{Domain: "x.com", Wildcard: true, DNSManaged: true, Override: acmesrv.ChallengeHTTP01}, acmesrv.ChallengeHTTP01, false},
		{"unknown override errors", acmesrv.MethodContext{Domain: "x.com", Override: "smoke-signal-01"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			method, rationale, err := acmesrv.SelectMethod(tc.ctx)
			if tc.err {
				if err == nil {
					t.Fatalf("expected error for %s", tc.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if method != tc.want {
				t.Fatalf("method = %q, want %q", method, tc.want)
			}
			if rationale == "" {
				t.Fatal("expected a non-empty rationale to record in the audit trail")
			}
		})
	}
}
