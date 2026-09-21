// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/succession/agent"
)

// cosign_attach.go is the workload-agent co-sign seam (INT-16, claim 19). PCAS is
// part of the core, so every agent build carries it. When configured, the agent
// serves the internal/succession/agent CoSignerService: it holds the workload's predecessor
// key and co-signs succession commitments the control plane forms, over a real gRPC
// transport, enforcing the FIG. 5 oracle-prevention rules server-side. Only the
// predecessor signature (public) ever leaves the agent.

// workloadCoSignConfig configures the workload-held predecessor co-sign service.
type workloadCoSignConfig struct {
	Listen             string // "unix:/path" or "host:port"; empty disables the service
	DeploymentScope    string
	IdentityID         string
	TenantID           string
	PredecessorKeyPath string // PKCS#8 PEM holding the workload predecessor key
}

// runWorkloadCoSign serves the co-sign service until ctx is canceled, then stops it
// gracefully. It is a self-contained agent mode (like --secret-inject): it needs no
// enrollment/connection settings.
func runWorkloadCoSign(ctx context.Context, cfg workloadCoSignConfig) error {
	signer, cleanup, err := loadPredecessorSigner(cfg.PredecessorKeyPath)
	if err != nil {
		return err
	}
	defer cleanup()

	cs, err := agent.New(agent.Config{
		DeploymentScope: cfg.DeploymentScope,
		IdentityID:      cfg.IdentityID,
		TenantID:        cfg.TenantID,
		Signer:          signer,
	})
	if err != nil {
		return err
	}

	network, addr := "tcp", cfg.Listen
	if rest, ok := strings.CutPrefix(cfg.Listen, "unix:"); ok {
		network, addr = "unix", rest
	}
	lis, err := net.Listen(network, addr)
	if err != nil {
		return fmt.Errorf("workload co-sign: listen %s: %w", cfg.Listen, err)
	}

	gs := grpc.NewServer()
	agent.NewCoSignServer(cs).Register(gs)
	errc := make(chan error, 1)
	go func() { errc <- gs.Serve(lis) }()

	fmt.Fprintf(os.Stderr, "trstctl-agent: serving workload co-sign for %s on %s\n", cfg.IdentityID, cfg.Listen)
	select {
	case <-ctx.Done():
		gs.GracefulStop()
		return nil
	case err := <-errc:
		return err
	}
}

// loadPredecessorSigner loads the workload predecessor key from a PKCS#8 PEM file into
// a locked (mlock/zeroize) signer, returning a cleanup that zeroizes the key material.
func loadPredecessorSigner(path string) (crypto.Signer, func(), error) {
	if path == "" {
		return nil, nil, errors.New("workload co-sign: --workload-predecessor-key is required")
	}
	pemBytes, err := os.ReadFile(path) // #nosec G304 -- operator-configured local path from the agent's own config (CWE-22)
	if err != nil {
		return nil, nil, fmt.Errorf("workload co-sign: read predecessor key: %w", err)
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, nil, errors.New("workload co-sign: predecessor key is not PEM")
	}
	ls, err := crypto.LockedKeyFromPKCS8(blk.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("workload co-sign: parse predecessor key: %w", err)
	}
	return crypto.SignerFromDigestSigner(ls), ls.Destroy, nil
}
