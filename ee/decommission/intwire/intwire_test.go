// SPDX-License-Identifier: LicenseRef-trstctl-EE
//go:build integration

package intwire

import "testing"

func TestVDEC_Wire_RetireKeyOfflineRecord_RealInfra(t *testing.T) {
	t.Fatal("red: VDEC-INT-WIRE real-infra retire/offline-record path is not wired yet")
}

func TestVDEC_Wire_SystemGateRefusesUntilComplete_RealInfra(t *testing.T) {
	t.Fatal("red: VDEC-INT-WIRE real-infra gate refusal path is not wired yet")
}

func TestVDEC_Wire_VerifierAcceptsRecordOffline(t *testing.T) {
	t.Fatal("red: VDEC-INT-WIRE offline verifier path is not wired yet")
}

func TestVDEC_Wire_GateDestroyMintInRealSigner(t *testing.T) {
	t.Fatal("red: VDEC-INT-WIRE real signer gate/destroy/mint path is not wired yet")
}

func TestVDEC_Restart_CompletionEvidenceSetSurvives(t *testing.T) {
	t.Fatal("red: VDEC-INT-WIRE completion evidence restart proof is not wired yet")
}

func TestVDEC_Restart_DestroyedTerminalIrreversible(t *testing.T) {
	t.Fatal("red: VDEC-INT-WIRE destroyed terminal restart proof is not wired yet")
}

func TestVDEC_Restart_ReprotectResumesIdempotent(t *testing.T) {
	t.Fatal("red: VDEC-INT-WIRE reprotect resume idempotency proof is not wired yet")
}
