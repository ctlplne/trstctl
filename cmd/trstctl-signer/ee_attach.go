// SPDX-License-Identifier: MPL-2.0

//go:build !trstctl_core

package main

import (
	eepqc "trstctl.com/trstctl/ee/pqc"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/signing"
)

// appendEEOptions attaches the Enterprise signer options.
//
// The PCAS succession-minter attach (INT-02) is gated on lic.Has(FeaturePCAS) but
// is DEFERRED to INT-02a. Importing the minter (ee/succession/signerwiring ->
// ee/succession/minter -> ee/succession) currently drags internal/events, and thus
// the embedded NATS client, into the sacred signer process — which the AN-4
// dependency-closure guard (TestSignerDependencyClosure / TestNoHTTPServerLinked-
// IntoSigner) correctly forbids: the isolated signer has no message bus and no SQL
// driver. INT-02a decouples ee/succession's crypto primitives from the AN-2 event
// layer so the minter's transitive closure is AN-4-clean; the attach block then
// lands here. Until then, a PCAS-licensed signer attaches no minter and
// MintSuccessor returns UNIMPLEMENTED (fail-closed) — the RPC path, resolver seam,
// and production minter are proven by ee/succession/signerwiring's integration
// tests, which serve a real signer with the minter attached.
func appendEEOptions(opts []signing.ServerOption, lic *license.Manager) []signing.ServerOption {
	opts = append(opts, signing.WithKeyFactory(eepqc.NewSignerKeyFactory()))
	// INT-02a will add here, once AN-4-clean:
	//   if lic != nil && lic.Has(license.FeaturePCAS) {
	//       m, _ := signerwiring.NewProductionMinter(signerwiring.Config{SignerID: "trstctl-signer"})
	//       opts = append(opts, signing.WithSuccessionMinter(m))
	//   }
	_ = lic
	return opts
}
