// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"trstctl.com/trstctl/internal/agent/secretrender"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/netsec"
)

// runSecretRender keeps the configured secret templates rendered (A238): a
// self-contained mode that reads secrets with an API token and needs no
// enrollment.
func runSecretRender(ctx context.Context, path string) error {
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator's --secret-render-config (CWE-22)
	if err != nil {
		return err
	}
	var cfg secretrender.Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	// A control plane on a private address is reached with its CA pinned; without
	// a ca_file the server is a public https endpoint (or loopback http).
	var cp *http.Client
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile) // #nosec G304 -- operator-configured CA bundle (CWE-22)
		if err != nil {
			return err
		}
		transport, err := mtls.HTTPTransport(pem)
		if err != nil {
			return err
		}
		cp = netsec.ClientFor(transport, 15*time.Second, nil)
	} else if cp, err = netsec.OutboundClientForEndpoint(cfg.Server, 15*time.Second); err != nil {
		return err
	}
	client, err := secretrender.NewHTTPClient(cfg.Server, cfg.Tenant, cfg.TokenFile, cp)
	if err != nil {
		return err
	}
	renderer, err := secretrender.New(cfg, client, client, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return err
	}
	renderer.UseLeases(client)
	return renderer.Run(ctx)
}
