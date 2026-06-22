package config

import (
	"strings"
	"testing"
)

// regulatedConfig returns a complete, coherent regulated-posture configuration
// built on the shipping defaults: the OPA policy gate on, four-eyes dual control
// with a >=2 threshold, a bound default certificate profile, and a revocation
// publication pointer. It is the baseline each negative test below mutates by
// removing exactly one regulated control so the resulting startup failure is
// attributable to that control (PKIGOV-003).
func regulatedConfig() *Config {
	c := Default()
	c.CA.GovernanceMode = GovernanceRegulated
	c.CA.Policy.Enabled = true
	c.CA.Policy.RequireApproval = true
	c.CA.Policy.RequiredApprovals = 2
	c.CA.DefaultProfile = "regulated-tls"
	c.CA.CRLDistributionPoints = []string{"http://crl.example.test/issuing.crl"}
	c.CA.OCSPServers = []string{"http://ocsp.example.test"}
	return c
}

// TestRegulatedGovernanceCompleteConfigBoots is the PKIGOV-003 positive
// acceptance: a fully-coherent regulated configuration validates (boots).
func TestRegulatedGovernanceCompleteConfigBoots(t *testing.T) {
	if err := regulatedConfig().Validate(); err != nil {
		t.Fatalf("a complete regulated config failed startup validation: %v", err)
	}
}

// TestStandardGovernanceImposesNoRegulatedCoupling confirms the default/standard
// posture does NOT require the regulated controls — a deployment that has not opted
// into regulated mode still boots with the controls independent (the shipping
// default), so PKIGOV-003 does not regress existing single-node deployments.
func TestStandardGovernanceImposesNoRegulatedCoupling(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("the default (standard) posture failed validation: %v", err)
	}
	c := Default()
	c.CA.GovernanceMode = GovernanceStandard
	// No policy, no approval, no profile, no revocation — all fine in standard mode.
	if err := c.Validate(); err != nil {
		t.Fatalf("explicit standard mode without the regulated controls failed validation: %v", err)
	}
}

func TestRegulatedGovernanceMissingPolicyFailsStartup(t *testing.T) {
	c := regulatedConfig()
	c.CA.Policy.Enabled = false
	assertRegulatedStartupError(t, c, "policy")
}

func TestRegulatedGovernanceMissingApprovalStoreFailsStartup(t *testing.T) {
	c := regulatedConfig()
	c.CA.Policy.RequireApproval = false
	assertRegulatedStartupError(t, c, "dual control")
}

// TestRegulatedGovernanceSingleApproverFailsStartup confirms an explicit
// single-approval threshold is not four-eyes and is rejected.
func TestRegulatedGovernanceSingleApproverFailsStartup(t *testing.T) {
	c := regulatedConfig()
	c.CA.Policy.RequiredApprovals = 1
	assertRegulatedStartupError(t, c, "distinct approvers")
}

func TestRegulatedGovernanceMissingDefaultProfileFailsStartup(t *testing.T) {
	c := regulatedConfig()
	c.CA.DefaultProfile = ""
	assertRegulatedStartupError(t, c, "default certificate profile")
}

func TestRegulatedGovernanceMissingRevocationFailsStartup(t *testing.T) {
	c := regulatedConfig()
	c.CA.CRLDistributionPoints = nil
	c.CA.OCSPServers = nil
	assertRegulatedStartupError(t, c, "revocation publication")
}

// TestRegulatedGovernanceFIPSRequiredButInactiveFailsStartup confirms that when a
// regulated config declares ca.require_fips but the FIPS module is not active, the
// config fails startup. fipsActive is overridden to model the non-FIPS build (the
// default test binary is non-FIPS, but pinning it makes the intent explicit and
// stable regardless of how the suite is built).
func TestRegulatedGovernanceFIPSRequiredButInactiveFailsStartup(t *testing.T) {
	prev := fipsActive
	fipsActive = func() bool { return false }
	defer func() { fipsActive = prev }()

	c := regulatedConfig()
	c.CA.RequireFIPS = true
	assertRegulatedStartupError(t, c, "FIPS 140-3 module")
}

// TestRegulatedGovernanceFIPSRequiredAndActiveBoots confirms the coherent case:
// regulated + require_fips with the module active validates.
func TestRegulatedGovernanceFIPSRequiredAndActiveBoots(t *testing.T) {
	prev := fipsActive
	fipsActive = func() bool { return true }
	defer func() { fipsActive = prev }()

	c := regulatedConfig()
	c.CA.RequireFIPS = true
	if err := c.Validate(); err != nil {
		t.Fatalf("regulated + require_fips with an active FIPS module failed startup: %v", err)
	}
}

// TestRegulatedGovernanceReportsEveryMissingControl confirms the failure is not
// fail-on-first: an empty regulated posture surfaces an actionable error for EVERY
// missing control at once, so an operator fixes the whole posture in one pass.
func TestRegulatedGovernanceReportsEveryMissingControl(t *testing.T) {
	c := Default()
	c.CA.GovernanceMode = GovernanceRegulated
	c.CA.Policy = PolicyGate{}
	c.CA.DefaultProfile = ""
	c.CA.CRLDistributionPoints = nil
	c.CA.OCSPServers = nil

	err := c.Validate()
	if err == nil {
		t.Fatal("an empty regulated posture booted; it must fail startup (PKIGOV-003)")
	}
	for _, want := range []string{"policy", "dual control", "default certificate profile", "revocation publication"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("regulated startup error is missing the %q control; got: %v", want, err)
		}
	}
}

// TestInvalidGovernanceModeRejected confirms an unknown governance mode is a
// startup error rather than silently treated as standard.
func TestInvalidGovernanceModeRejected(t *testing.T) {
	c := Default()
	c.CA.GovernanceMode = "audited-but-not-a-mode"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "governance_mode") {
		t.Fatalf("an invalid governance_mode was not rejected with an actionable error; got: %v", err)
	}
}

func assertRegulatedStartupError(t *testing.T, c *Config, wantSubstr string) {
	t.Helper()
	err := c.Validate()
	if err == nil {
		t.Fatalf("regulated config missing %q booted; it must fail startup (PKIGOV-003)", wantSubstr)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("regulated startup error did not mention %q; got: %v", wantSubstr, err)
	}
}
