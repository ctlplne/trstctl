// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/server"
)

// This file carries no build tag on purpose: it runs under -tags trstctl_core
// too, which is the proof that the core families attach without ee/ and
// without a license.

func TestAttachFamiliesMountsEveryFamilyInEveryBuild(t *testing.T) {
	deps := &server.Deps{}
	if err := attachFamilies(&config.Config{}, nil, deps); err != nil {
		t.Fatalf("attachFamilies: %v", err)
	}
	if !deps.EnablePCAS || len(deps.LicensedBackgroundWorkers) == 0 {
		t.Fatal("PCAS did not attach: EnablePCAS unset or no succession workers")
	}
	if deps.BrokerIssuancePrecondition == nil || deps.BrokerTaskEnvelopeGate == nil {
		t.Fatal("AGID did not attach the chain-bound broker issuance precondition and task-envelope gate")
	}
	if !hasBackgroundWorker(deps, "xrec.rounds") || deps.IssuanceAdmission == nil {
		t.Fatal("XREC did not attach the round scheduler and issuance admission")
	}
	if len(deps.LicensedProjectionOptions) == 0 {
		t.Fatal("no family registered a projection (XREC drift, VDEC retirement, PQC migration expected)")
	}
	if deps.LicensedLeafSigner == nil || deps.LicensedCSRInspector == nil || deps.LicensedCSRParser == nil || deps.LicensedSPIFFESVIDFactory == nil {
		t.Fatal("PQC did not attach the leaf signer, CSR inspector/parser, and SPIFFE SVID factory")
	}
	if deps.LicensedAPIOptionsFactory == nil || deps.LicensedOutboxFactory == nil {
		t.Fatal("the families did not compose API and outbox factories")
	}
}

// TestAttachVerifiableDecommissionMountsBothSeams is the AUD-2/AUD-3 attach
// regression: the VDEC stage must mount BOTH the re-protection outbox handler
// AND the API options factory (retirement checklist source + the re-protection
// start route, the handler's only production producer). Mounting just the
// outbox factory is exactly the defect the unreachable-capability audit found:
// a consumer with no producer and a served route with no source.
func TestAttachVerifiableDecommissionMountsBothSeams(t *testing.T) {
	deps := &server.Deps{}
	if err := attachVerifiableDecommission(nil, deps); err != nil {
		t.Fatalf("attachVerifiableDecommission: %v", err)
	}
	if deps.LicensedOutboxFactory == nil {
		t.Fatal("VDEC attach did not mount the re-protection outbox handler factory")
	}
	if deps.LicensedAPIOptionsFactory == nil {
		t.Fatal("VDEC attach did not mount the API options factory (checklist source + reprotect route)")
	}
	if len(deps.LicensedProjectionOptions) != 1 {
		t.Fatalf("VDEC attach mounted %d projection options, want the retirement replay projection", len(deps.LicensedProjectionOptions))
	}
	opts, err := deps.LicensedAPIOptionsFactory(server.LicensedAPIOptionsDeps{})
	if err != nil {
		t.Fatalf("VDEC API options factory: %v", err)
	}
	if len(opts) != 3 {
		t.Fatalf("VDEC API options factory yielded %d options, want 3 (checklist source, routes, schemas)", len(opts))
	}
}

func hasBackgroundWorker(deps *server.Deps, name string) bool {
	for _, worker := range deps.LicensedBackgroundWorkers {
		if worker != nil && worker.Name() == name {
			return true
		}
	}
	return false
}
