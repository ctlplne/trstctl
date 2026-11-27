// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"fmt"
	"strings"

	"github.com/nats-io/nats.go"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

func dialExternalNATS(cfg config.NATS) (*nats.Conn, error) {
	if err := cfg.ValidateExternalSecurity(); err != nil {
		return nil, fmt.Errorf("events: external NATS security: %w", err)
	}
	options := make([]nats.Option, 0, 4)
	if strings.HasPrefix(strings.TrimSpace(cfg.URL), "tls://") {
		options = append(options, nats.Secure(crypto.NATSTLSClientConfig()))
	}
	if cfg.TLSCAFile != "" {
		options = append(options, nats.RootCAs(cfg.TLSCAFile))
	}
	if cfg.TLSCertFile != "" {
		options = append(options, nats.ClientCert(cfg.TLSCertFile, cfg.TLSKeyFile))
	}
	if cfg.CredentialsFile != "" {
		options = append(options, nats.UserCredentials(cfg.CredentialsFile))
	}
	if cfg.NKeySeedFile != "" {
		identity, err := nats.NkeyOptionFromSeed(cfg.NKeySeedFile)
		if err != nil {
			return nil, fmt.Errorf("events: load NATS NKey seed: %w", err)
		}
		options = append(options, identity)
	}
	nc, err := nats.Connect(cfg.URL, options...)
	if err != nil {
		return nil, fmt.Errorf("events: connect external NATS: %w", err)
	}
	return nc, nil
}
