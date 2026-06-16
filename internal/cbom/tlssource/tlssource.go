// Package tlssource is a CBOM source that observes the cryptography a TLS
// endpoint negotiates — the protocol version and the certificate's public key —
// through a non-invasive handshake (F52). The handshake routes through the
// crypto boundary (tlsprobe); the certificate is parsed by certinfo; this
// package consumes only crypto-free results.
package tlssource

import (
	"context"

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

// Source observes a set of TLS endpoints.
type Source struct {
	addrs  []string
	prober Prober
}

// Option configures a Source.
type Option func(*Source)

// WithProber overrides the handshake function (for tests).
func WithProber(p Prober) Option {
	return func(s *Source) {
		if p != nil {
			s.prober = p
		}
	}
}

// New returns a TLS-endpoint source over the given host:port addresses.
func New(addrs []string, opts ...Option) *Source {
	s := &Source{addrs: addrs, prober: defaultProber}
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
	for _, addr := range s.addrs {
		res, err := s.prober(ctx, addr)
		if err != nil {
			continue
		}
		out = append(out, cbom.Finding{
			Kind:     cbom.AssetTLSEndpoint,
			Location: addr,
			Protocol: cbom.TLSVersionName(res.TLSVersion),
			Library:  res.NegotiatedProtocol,
		})
		if len(res.PeerCertificates) > 0 {
			if info, err := certinfo.Inspect(res.PeerCertificates[0]); err == nil {
				out = append(out, cbom.Finding{
					Kind:      cbom.AssetCertKey,
					Location:  addr,
					Algorithm: info.KeyAlgorithm,
					KeyBits:   info.PublicKeyBits,
				})
			}
		}
	}
	return out, nil
}
