// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"trstctl.com/trstctl/internal/agent/csisecrets"
	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/netsec"
)

// runCSISecrets serves the secrets.csi.trstctl.com node plugin on socketPath
// until ctx ends (A238). It reads secrets with each pod's own service-account
// token and holds no credential of its own; the node id is NODE_NAME from the
// downward API, as the shipped DaemonSet sets it.
func runCSISecrets(ctx context.Context, socketPath, configPath string) error {
	if configPath == "" {
		return fmt.Errorf("the CSI secrets driver needs --csi-secrets-config")
	}
	raw, err := os.ReadFile(configPath) // #nosec G304 -- the operator's --csi-secrets-config (CWE-22)
	if err != nil {
		return err
	}
	var cfg csisecrets.Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	// A control plane on a private address is reached with its CA pinned;
	// without a ca_file the server is a public https endpoint.
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
	node := strings.TrimSpace(os.Getenv("NODE_NAME"))
	if node == "" {
		if node, err = os.Hostname(); err != nil || node == "" {
			return fmt.Errorf("the CSI secrets driver needs NODE_NAME (the downward API spec.nodeName)")
		}
	}
	driver, err := csisecrets.NewDriver(cfg, cp, csisecrets.SystemMounter{}, slog.New(slog.NewTextHandler(os.Stderr, nil)), node, buildinfo.Version())
	if err != nil {
		return err
	}
	fmt.Printf("trstctl-agent: serving %s on %s for node %s\n", csisecrets.DriverName, socketPath, node)
	return driver.Serve(ctx, socketPath)
}
