package acme_test

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/protocols/acme"
)

// FuzzTLSALPN01Validate (S8b.5) hardens the tls-alpn-01 validator against hostile
// handshake results: no prober output may crash it, and it must fail closed — returning
// nil only when the negotiated ALPN is acme-tls/1 AND the presented acmeIdentifier
// equals SHA-256(keyAuthorization).
func FuzzTLSALPN01Validate(f *testing.F) {
	f.Add("keyauth", tlsprobe.ACMETLSALPNProto, []byte("ident"))
	f.Add("", "", []byte(nil))
	f.Add("k", "h2", []byte("\x00\x01\x02"))

	f.Fuzz(func(t *testing.T, keyAuth, negProto string, ident []byte) {
		v := acme.TLSALPN01Validator{Prober: func(context.Context, string) (tlsprobe.Result, error) {
			return tlsprobe.Result{NegotiatedProtocol: negProto, ACMEIdentifier: ident}, nil
		}}
		accepted := v.Validate(context.Background(), acme.ChallengeTLSALPN01, "example.com", "token", keyAuth) == nil
		want := negProto == tlsprobe.ACMETLSALPNProto && bytes.Equal(ident, crypto.SHA256Sum([]byte(keyAuth)))
		if accepted != want {
			t.Fatalf("accepted=%v want=%v (proto=%q, idlen=%d)", accepted, want, negProto, len(ident))
		}
	})
}
