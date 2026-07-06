// SPDX-License-Identifier: MPL-2.0

//go:build !trstctl_core

package main

import (
	"fmt"
	"os"

	eepqc "trstctl.com/trstctl/ee/pqc"
	"trstctl.com/trstctl/ee/succession/signerwiring"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/signing"
)

// appendEEOptions attaches the Enterprise signer options. The PCAS succession minter
// is attached iff the deployment is licensed for PCAS (INT-02/INT-02a). Fail-closed:
// no license, or a license without the PCAS feature, means no minter is attached and
// the signer's MintSuccessor RPC returns UNIMPLEMENTED.
//
// Attaching the minter is AN-4-safe as of INT-02a: ee/succession's crypto primitives
// depend on the NATS-free internal/eventspec, not internal/events, so the minter's
// transitive closure links no message bus and no SQL driver (enforced by
// TestSignerDependencyClosure / TestNoHTTPServerLinkedIntoSigner).
func appendEEOptions(opts []signing.ServerOption, lic *license.Manager) []signing.ServerOption {
	opts = append(opts, signing.WithKeyFactory(eepqc.NewSignerKeyFactory()))
	if lic != nil && lic.Has(license.FeaturePCAS) {
		m, err := signerwiring.NewProductionMinter(signerwiring.Config{SignerID: "trstctl-signer"})
		if err != nil {
			fmt.Fprintf(os.Stderr, "trstctl-signer: build PCAS minter: %v\n", err)
			os.Exit(1)
		}
		opts = append(opts, signing.WithSuccessionMinter(m))
	}
	return opts
}
