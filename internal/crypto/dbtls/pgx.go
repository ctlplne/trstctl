// SPDX-License-Identifier: BUSL-1.1

package dbtls

import (
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/crypto/trust"
)

// HardenPGXConfig installs the runtime distrust check on every TLS route pgx
// parsed from an operator DSN, including alternate hosts and TLS fallbacks.
// If a TLS-first DSN permits plaintext fallback, the fallback may proceed
// only after that fallback connection explicitly refused PostgreSQL's
// SSLRequest. A TLS distrust failure must not become a plaintext password
// exchange.
func HardenPGXConfig(cfg *pgconn.Config) {
	if cfg == nil {
		return
	}
	if cfg.TLSConfig != nil {
		cfg.TLSConfig = hardenPGXTLS(cfg.TLSConfig)
	}
	for _, fallback := range cfg.Fallbacks {
		if fallback != nil && fallback.TLSConfig != nil {
			fallback.TLSConfig = hardenPGXTLS(fallback.TLSConfig)
		}
		if cfg.TLSConfig != nil && fallback != nil && fallback.TLSConfig == nil {
			dial := cfg.DialFunc
			if dial == nil {
				dial = (&net.Dialer{}).DialContext
			}
			cfg.DialFunc = PostgresPreferDial(dial)
			break
		}
	}
}

func hardenPGXTLS(cfg *tls.Config) *tls.Config {
	previous := cfg.VerifyConnection
	check := trust.VerifyConnection(nil)
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		if previous != nil {
			if err := previous(state); err != nil {
				return err
			}
		}
		// pgx's prefer/require/verify-ca modes bypass Go's normal chain
		// verification. Verify the chain here, so a root omitted from the
		// server's wire chain is still checked against the active distrust list.
		if len(state.VerifiedChains) == 0 && len(state.PeerCertificates) > 0 {
			intermediates := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			chains, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots: cfg.RootCAs, Intermediates: intermediates,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			if err != nil {
				return err
			}
			state.VerifiedChains = chains
		}
		return check(state)
	}
	return cfg
}
