package acme

import (
	"bytes"
	"context"
	"fmt"
	"net"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

// ALPNProber performs a TLS-ALPN-01 probe of addr and returns the handshake
// result (the negotiated protocol and the leaf's acmeIdentifier). tlsprobe.Probe
// with the acme-tls/1 ALPN satisfies it; it is injectable so the validator can be
// tested against a loopback responder.
type ALPNProber func(ctx context.Context, addr string) (tlsprobe.Result, error)

// TLSALPN01Validator validates tls-alpn-01 challenges (RFC 8737): an ALPN
// "acme-tls/1" handshake on port 443 must present a certificate whose
// id-pe-acmeIdentifier extension equals the SHA-256 digest of the key
// authorization. It fails closed on any handshake error, a non-negotiated ALPN,
// a missing extension, or a digest mismatch.
type TLSALPN01Validator struct {
	Prober ALPNProber
}

// Validate performs the tls-alpn-01 check.
func (v TLSALPN01Validator) Validate(ctx context.Context, challengeType, domain, token, keyAuth string) error {
	if challengeType != ChallengeTLSALPN01 {
		return fmt.Errorf("acme: TLSALPN01Validator cannot validate %q", challengeType)
	}
	prober := v.Prober
	if prober == nil {
		prober = func(ctx context.Context, addr string) (tlsprobe.Result, error) {
			return tlsprobe.Probe(ctx, addr, tlsprobe.WithALPN(tlsprobe.ACMETLSALPNProto))
		}
	}
	addr := net.JoinHostPort(domain, "443")
	res, err := prober(ctx, addr)
	if err != nil {
		return fmt.Errorf("acme: tls-alpn-01 handshake %s: %w", addr, err)
	}
	if res.NegotiatedProtocol != tlsprobe.ACMETLSALPNProto {
		return fmt.Errorf("acme: tls-alpn-01: server did not negotiate %q", tlsprobe.ACMETLSALPNProto)
	}
	if !bytes.Equal(res.ACMEIdentifier, crypto.SHA256Sum([]byte(keyAuth))) {
		return fmt.Errorf("acme: tls-alpn-01: acmeIdentifier mismatch")
	}
	return nil
}
