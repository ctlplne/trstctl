// SPDX-License-Identifier: BUSL-1.1

package sshtrustrollout

import (
	"strings"
	"testing"
	"time"
)

func TestSSHTrustReceiptCannotPromoteQueueAcceptanceOrUnverifiedRollback(t *testing.T) {
	c := reviewedCommand(t)
	r := Report{RolloutID: c.RolloutID, AgentID: c.AgentID, PlanDigest: c.PlanDigest, ReadinessDigest: c.ReadinessDigest, CAFingerprint: c.CAFingerprint, State: "verified", Phase: "complete", Rollback: "not_needed", CAReadBack: true, EffectiveConfigReadBack: true, TrustFileSHA256: "sha256:" + strings.Repeat("c", 64), ConfigFileSHA256: "sha256:" + strings.Repeat("d", 64), Validated: true, Reloaded: true, Healthy: true, CheckedAt: time.Now().UTC()}
	_, digest, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(c, digest); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Report){
		"no-file-read":          func(r *Report) { r.CAReadBack = false },
		"shadowed-config":       func(r *Report) { r.EffectiveConfigReadBack = false },
		"no-health":             func(r *Report) { r.Healthy = false },
		"rollback-is-not-apply": func(r *Report) { r.Rollback = "verified" },
		"other-host":            func(r *Report) { r.AgentID = "another-host" },
		"other-plan":            func(r *Report) { r.PlanDigest = "sha256:" + strings.Repeat("e", 64) },
		"stderr-phase":          func(r *Report) { r.Phase = "arbitrary stderr" },
	} {
		t.Run(name, func(t *testing.T) {
			other := r
			change(&other)
			_, d, err := other.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err := other.Validate(c, d); err == nil {
				t.Fatal("accepted unverified effect")
			}
		})
	}
}
