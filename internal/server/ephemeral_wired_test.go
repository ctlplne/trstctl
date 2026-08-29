// SPDX-License-Identifier: MPL-2.0

package server

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

func TestEphemeralIssuanceHasAnOperatorSwitch(t *testing.T) {
	t.Parallel()
	if ephemeralIssuanceFromConfig(config.EphemeralIssuance{}).Enabled {
		t.Fatal("ephemeral issuance is on by default; an approval-gated mint must be explicitly enabled")
	}
	on := ephemeralIssuanceFromConfig(config.EphemeralIssuance{
		Enabled: true, TrustDomain: "example.org", DefaultTTL: "5m", MaxTTL: "30m",
		ApprovalTTL: "10m", RequiredApprovals: 2,
	})
	if !on.Enabled || on.TrustDomain != "example.org" {
		t.Fatalf("ephemeral operator switch = %+v", on)
	}
	if on.DefaultTTL != 5*time.Minute || on.MaxTTL != 30*time.Minute ||
		on.ApprovalTTL != 10*time.Minute || on.RequiredApprovals != 2 {
		t.Fatalf("ephemeral operator bounds = %+v", on)
	}
}

func TestMalformedEphemeralDurationsNeverLengthenCredentialOrApprovalLifetime(t *testing.T) {
	t.Parallel()
	got := ephemeralIssuanceFromConfig(config.EphemeralIssuance{
		Enabled: true, TrustDomain: "example.org", DefaultTTL: "bad", MaxTTL: "bad", ApprovalTTL: "bad",
	})
	if got.DefaultTTL != 0 || got.MaxTTL != 0 || got.ApprovalTTL != 0 {
		t.Fatalf("malformed ephemeral durations = %+v, want zero so built-in bounds apply", got)
	}
}

func TestEphemeralConfigKeyReachesTheAssembledServer(t *testing.T) {
	t.Parallel()
	src, err := readSourceFile("run.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(src, "ephemeralIssuanceFromConfig(cfg.EphemeralIssuance)") {
		t.Fatal("run.go does not assign Deps.EphemeralIssuance from config; every production request would remain 503")
	}
}
