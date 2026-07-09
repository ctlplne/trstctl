// SPDX-License-Identifier: LicenseRef-trstctl-EE
//go:build integration

package conformance

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVDEC_Conformance_EndToEndRealInfra(t *testing.T) {
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	cmd := exec.Command(goBin, "test", "-tags", "integration", "./ee/decommission/intwire", "-run",
		"TestVDEC_Wire_RetireKeyOfflineRecord_RealInfra|TestVDEC_Wire_SystemGateRefusesUntilComplete_RealInfra|TestVDEC_Wire_VerifierAcceptsRecordOffline|TestVDEC_Wire_GateDestroyMintInRealSigner|TestVDEC_Restart_CompletionEvidenceSetSurvives|TestVDEC_Restart_DestroyedTerminalIrreversible|TestVDEC_Restart_ReprotectResumesIdempotent",
		"-count=1", "-timeout=10m")
	cmd.Dir = moduleRoot(t)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("VDEC-INT-WIRE real-substrate conformance suite failed: %v\n%s", err, out)
	}
}
