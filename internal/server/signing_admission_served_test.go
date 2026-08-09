// SPDX-License-Identifier: MPL-2.0

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/signing"
)

// TestServedAssembly_InstallsSignerAdmission pins the AUD-6 wiring at the
// assembly root: building the served control plane must install the signer
// admission hook, so every signer RPC routes through the operator's
// bulkheads.signing pool. The mechanism itself (workers/queue bound, fast
// structured rejection) is proven in internal/signing; THIS test is the one
// that fails if the assembly stops installing the hook — the exact
// pool-with-no-work-in-it defect the unreachable-capability audit found.
func TestServedAssembly_InstallsSignerAdmission(t *testing.T) {
	signing.SetSignerAdmission(nil)
	_ = newServedHarness(t, config.Protocols{})
	if !signing.SignerAdmissionInstalled() {
		t.Fatal("served assembly did not install the signer admission hook — bulkheads.signing bounds nothing (AUD-6)")
	}
}
