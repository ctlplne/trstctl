// SPDX-License-Identifier: BUSL-1.1

// Package tlssource is a CBOM source that observes the cryptography a TLS
// endpoint negotiates — the protocol version and the certificate's public key —
// through a non-invasive handshake (F52). The handshake routes through the
// crypto boundary (tlsprobe); the certificate is parsed by certinfo; this
// package consumes only crypto-free results.
package tlssource

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

// Prober performs the non-invasive TLS handshake. The default is tlsprobe.Probe;
// tests inject a fake.
type Prober func(ctx context.Context, addr string) (tlsprobe.Result, error)

func defaultProber(ctx context.Context, addr string) (tlsprobe.Result, error) {
	return tlsprobe.Probe(ctx, addr)
}

func compatibilityProber(ctx context.Context, addr string) (tlsprobe.Result, error) {
	return tlsprobe.Probe(ctx, addr, tlsprobe.WithMaxVersion(tlsprobe.TLSVersion12))
}

// Source observes a set of TLS endpoints.
type Source struct {
	addrs                 []string
	prober                Prober
	compatibilityProber   Prober
	compatibilityExplicit bool
}

// Option configures a Source.
type Option func(*Source)

// WithProber overrides the handshake function (for tests).
func WithProber(p Prober) Option {
	return func(s *Source) {
		if p != nil {
			s.prober = p
			// A caller substituting its own transport must also opt into a
			// compatibility probe; never silently dial a real endpoint in a test.
			if !s.compatibilityExplicit {
				s.compatibilityProber = nil
			}
		}
	}
}

// WithCompatibilityProber supplies the second read-only handshake in tests.
func WithCompatibilityProber(p Prober) Option {
	return func(s *Source) {
		s.compatibilityProber = p
		s.compatibilityExplicit = true
	}
}

// New returns a TLS-endpoint source over the given host:port addresses.
func New(addrs []string, opts ...Option) *Source {
	s := &Source{addrs: addrs, prober: defaultProber, compatibilityProber: compatibilityProber}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Name identifies the source.
func (s *Source) Name() string { return "tls-endpoints" }

// Scan handshakes each endpoint and reports its negotiated protocol version and
// leaf-certificate key. An unreachable endpoint is skipped, never fatal.
func (s *Source) Scan(ctx context.Context) ([]cbom.Finding, error) {
	var out []cbom.Finding
	failures := 0
	for _, addr := range s.addrs {
		endpointCtx, cancel := context.WithTimeout(ctx, tlsprobe.DefaultTimeout)
		res, err := s.prober(endpointCtx, addr)
		if err != nil {
			cancel()
			failures++
			continue
		}
		out = append(out, cbom.Finding{
			Kind:     cbom.AssetTLSEndpoint,
			Location: addr,
			Protocol: cbom.TLSVersionName(res.TLSVersion),
			Library:  res.NegotiatedProtocol,
		})
		// A modern client picks TLS 1.3 even when this listener also accepts
		// TLS 1.2. That first result alone cannot characterize the floor. A
		// successful capped handshake is a separate observed protocol finding;
		// refusal simply supplies no lower-version evidence.
		if res.TLSVersion == tlsprobe.TLSVersion13 && s.compatibilityProber != nil {
			if lower, lowerErr := s.compatibilityProber(endpointCtx, addr); lowerErr == nil && lower.TLSVersion <= tlsprobe.TLSVersion12 {
				out = append(out, cbom.Finding{Kind: cbom.AssetTLSEndpoint, Location: addr,
					Protocol: cbom.TLSVersionName(lower.TLSVersion), Library: lower.NegotiatedProtocol})
			}
		}
		cancel()
		if len(res.PeerCertificates) == 0 {
			failures++
			continue
		}
		info, err := certinfo.Inspect(res.PeerCertificates[0])
		if err != nil {
			failures++
			continue
		}
		out = append(out, cbom.Finding{Kind: cbom.AssetCertKey, Location: addr, Algorithm: info.KeyAlgorithm, KeyBits: info.PublicKeyBits, CertificateFingerprint: info.SHA256Fingerprint})

	}
	if failures > 0 {
		return out, &cbom.PartialScanError{Failures: failures, Err: errors.New("one or more CBOM TLS endpoints could not complete a bounded handshake and certificate inspection")}
	}
	return out, nil
}
