package crypto

import (
	"errors"
	"strings"
	"testing"
)

// TestPowerOnSelfTest_KATAlwaysRuns asserts the known-answer self-test runs and
// passes in either FIPS mode: a sign→verify→reject round-trip through the live
// boundary succeeds, and the returned status records it. This is the part of the
// POST that runs unconditionally at startup so a broken crypto stack is caught at
// boot rather than on first issuance.
func TestPowerOnSelfTest_KATAlwaysRuns(t *testing.T) {
	// required=false: in the default (non-FIPS) test build the module is inactive,
	// so the only thing that must hold is the KAT.
	status, err := PowerOnSelfTest(false)
	if err != nil {
		t.Fatalf("PowerOnSelfTest(required=false) returned error: %v", err)
	}
	if !status.SelfTestPassed {
		t.Fatalf("self-test did not pass: %+v", status)
	}
	if status.ModuleActive != FIPSEnabled() {
		t.Fatalf("status.ModuleActive=%v but FIPSEnabled()=%v", status.ModuleActive, FIPSEnabled())
	}
}

// TestPowerOnSelfTest_FailsClosedWhenFIPSRequiredButInactive is the regulated-
// deployment guard: when the operator asserts FIPS is required (--fips /
// fips.required) but the FIPS module is NOT active in this binary, the POST must
// FAIL CLOSED with ErrFIPSRequiredButInactive — the process refuses to start.
//
// The default `go test` build does not enable the FIPS module, so FIPSEnabled()
// is false here and this is the live (not simulated) inactive case. If the suite
// is ever run under GOFIPS140=latest / GODEBUG=fips140=on, the module is active
// and there is nothing to fail closed on, so the assertion is skipped rather than
// made vacuously — the dedicated FIPS CI job (`make fips-build` + this package)
// covers the active path.
func TestPowerOnSelfTest_FailsClosedWhenFIPSRequiredButInactive(t *testing.T) {
	if FIPSEnabled() {
		t.Skip("FIPS module is active in this build; the inactive fail-closed path is covered by the non-FIPS test build")
	}
	status, err := PowerOnSelfTest(true)
	if !errors.Is(err, ErrFIPSRequiredButInactive) {
		t.Fatalf("PowerOnSelfTest(required=true) with inactive module: got err=%v, want ErrFIPSRequiredButInactive", err)
	}
	// The KAT still ran and passed even though the FIPS assert failed — the failure
	// is specifically the FIPS-required-but-inactive condition, not a crypto break.
	if !status.SelfTestPassed {
		t.Fatalf("KAT should still pass even when FIPS is required-but-inactive: %+v", status)
	}
	if status.ModuleActive {
		t.Fatalf("module reported active in a non-FIPS build: %+v", status)
	}
}

// TestPowerOnSelfTest_PassesWhenFIPSRequiredAndActive covers the success path of
// the assert: when FIPS is required AND the module is active, the POST passes.
// It only runs under a FIPS build (the `make fips-build` CI job), and skips
// otherwise so the default build does not need the FIPS toolchain flag.
func TestPowerOnSelfTest_PassesWhenFIPSRequiredAndActive(t *testing.T) {
	if !FIPSEnabled() {
		t.Skip("not a FIPS build; the required+active path is exercised by the fips-build CI job")
	}
	status, err := PowerOnSelfTest(true)
	if err != nil {
		t.Fatalf("PowerOnSelfTest(required=true) under an active FIPS module: %v", err)
	}
	if !status.ModuleActive || !status.SelfTestPassed || !status.Required {
		t.Fatalf("unexpected status under active FIPS module: %+v", status)
	}
}

// TestFIPSStatus_Summary asserts the human-readable posture line distinguishes
// the four states an operator needs to see at a glance.
func TestFIPSStatus_Summary(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    FIPSStatus
		want []string
	}{
		{"active-required-ok", FIPSStatus{ModuleActive: true, Required: true, SelfTestPassed: true}, []string{"ACTIVE", "REQUIRED", "self-test passed"}},
		{"inactive-notreq-ok", FIPSStatus{ModuleActive: false, Required: false, SelfTestPassed: true}, []string{"inactive", "not required", "self-test passed"}},
		{"inactive-required", FIPSStatus{ModuleActive: false, Required: true, SelfTestPassed: true}, []string{"inactive", "REQUIRED"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.s.Summary()
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("Summary()=%q missing %q", got, w)
				}
			}
		})
	}
}

// TestSelfTestKAT_Standalone exercises the known-answer self-test directly so the
// boundary's sign/verify/reject guarantee is covered as a unit, independent of
// the FIPS assert wrapper. It is the regression guard for the live crypto path.
func TestSelfTestKAT_Standalone(t *testing.T) {
	if err := selfTestKAT(); err != nil {
		t.Fatalf("known-answer self-test failed: %v", err)
	}
}
