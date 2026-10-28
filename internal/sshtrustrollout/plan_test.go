// SPDX-License-Identifier: BUSL-1.1

package sshtrustrollout

import (
	"testing"
	"time"
)

func TestPlanBindsSkippedRosterPolicyCAAndDeadline(t *testing.T) {
	c := reviewedCommand(t)
	p := Plan{Name: "lab-addition", Reason: "Trust the staged tenant SSH CA", PublicCAKey: c.PublicCAKey, CAFingerprint: c.CAFingerprint, ExpiresAt: time.Now().UTC().Add(15 * time.Minute), Hosts: []Host{{AgentID: c.AgentID, ReadinessDigest: c.ReadinessDigest, State: "ready"}, {AgentID: "a2260000-0000-4000-8000-000000000003", State: "skipped", Reason: "disabled"}}}
	want, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Plan){
		"deadline": func(p *Plan) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
		"roster":   func(p *Plan) { p.Hosts = p.Hosts[:1] },
		"policy": func(p *Plan) {
			p.Hosts[0].ReadinessDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		},
		"skip": func(p *Plan) { p.Hosts[1].Reason = "unconfirmed" },
	} {
		t.Run(name, func(t *testing.T) {
			other := p
			other.Hosts = append([]Host(nil), p.Hosts...)
			change(&other)
			got, err := other.Digest()
			if err != nil || got == want {
				t.Fatalf("unbound change: %s %v", got, err)
			}
		})
	}
	if err := p.ExecutionWindow(p.ExpiresAt); err == nil {
		t.Fatal("expired plan authorized a new dispatch")
	}
	// Structural replay still accepts the same source after its execution window.
	if _, err := p.Digest(); err != nil {
		t.Fatal(err)
	}
}
