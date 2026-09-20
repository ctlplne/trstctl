// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestRetainedIdentityProfileFollowsReviewedRevisionAcrossRebuild(t *testing.T) {
	for _, approved := range []bool{false, true} {
		name := "without approval"
		if approved {
			name = "with approval"
		}
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			st, log, projector := recordingSpine(t)
			orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
			policy := "retained-mail-policy-v5"
			if approved {
				policy = "retained-mail-policy-v4"
			}
			if _, err := orch.CreateProfile(ctx, tenantA, policy, mustProfileSpec(t, profile.CertificateProfile{
				Name: policy, MaxValidity: profile.Duration(12 * time.Minute), AllowedProtocols: []string{"api"},
			})); err != nil {
				t.Fatal(err)
			}
			initial, err := orch.ProfileApprovalRequirementByName(ctx, tenantA, policy)
			if err != nil {
				t.Fatal(err)
			}
			refs, err := initial.IssuanceBinding().EvidenceRefs()
			if err != nil {
				t.Fatal(err)
			}
			// This identity deliberately has no profile attribute, like an identity
			// enrolled through the existing endpoint API before this repair.
			f := newLifecycleAuthorityFixture(t, st, log, "retained-mail-issue", "", "review mail policy", "alice", refs...)
			if approved {
				err = orch.TransitionWithSubjectCSRAndApproval(ctx, tenantA, f.identity.ID, orchestrator.StateIssued,
					f.reason, f.key, "", f.use)
			} else {
				err = orch.TransitionWithSubjectCSR(ctx, tenantA, f.identity.ID, orchestrator.StateIssued,
					f.reason, f.key, "", initial.IssuanceBinding())
			}
			if err != nil {
				t.Fatal(err)
			}
			check := func(version int, ttl time.Duration, requiresApproval bool) {
				t.Helper()
				got, err := orch.ProfileApprovalRequirement(ctx, tenantA, f.identity.ID)
				if err != nil || got.ProfileName != policy || got.ProfileVersion != version ||
					got.EffectiveTTLSeconds != int64(ttl/time.Second) || got.RequiresApproval != requiresApproval {
					t.Fatalf("retained policy = %+v, err=%v; want %s v%d, TTL %s, approval=%v", got, err, policy, version, ttl, requiresApproval)
				}
			}
			check(1, 12*time.Minute, false)
			alice := events.ContextWithActor(ctx, events.Actor{Subject: "alice"})
			bob := events.ContextWithActor(ctx, events.Actor{Subject: "bob"})
			_, err = orch.CreateProfile(alice, tenantA, policy, mustProfileSpec(t, profile.CertificateProfile{
				Name: policy, MaxValidity: profile.Duration(10 * time.Minute), AllowedProtocols: []string{"api"}, RequiresApproval: true,
			}))
			pending := profileEditPending(t, err)
			check(1, 12*time.Minute, false)
			if _, err := orch.ApproveProfileEdit(bob, tenantA, pending.Request.ID, "bob"); err != nil {
				t.Fatal(err)
			}
			check(2, 10*time.Minute, true)
			if err := projector.Rebuild(ctx, log); err != nil {
				t.Fatal(err)
			}
			orch = orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
			check(2, 10*time.Minute, true)
			if approved {
				request, err := st.GetOperationApproval(ctx, tenantA, f.request.ID)
				if err != nil || request.ConsumedEventID == "" {
					t.Fatalf("retained selection must not clear consumed approval: %+v, %v", request, err)
				}
			}
			if _, err := orch.ProfileApprovalRequirement(ctx, tenantB, f.identity.ID); err == nil {
				t.Fatal("foreign tenant resolved retained policy")
			}
		})
	}
}

func TestRetainedIdentityProfileRejectsUntrustedHistoryIndex(t *testing.T) {
	ctx := t.Context()
	seqParam := func(seq uint64) int64 {
		if seq > math.MaxInt64 {
			t.Fatal("fixture event sequence exceeds PostgreSQL bigint")
			return 0
		}
		return int64(seq)
	}
	st, log, _ := recordingSpine(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	const policy = "indexed-mail-policy"
	if _, err := orch.CreateProfile(ctx, tenantA, policy, mustProfileSpec(t, profile.CertificateProfile{
		Name: policy, MaxValidity: profile.Duration(12 * time.Minute), AllowedProtocols: []string{"api"},
	})); err != nil {
		t.Fatal(err)
	}
	requirement, err := orch.ProfileApprovalRequirementByName(ctx, tenantA, policy)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := orch.CreateOwner(ctx, tenantA, "service", "indexed mail", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := orch.CreateIdentity(ctx, tenantA, store.Identity{Kind: store.KindX509Certificate, Name: "mail.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := orch.TransitionWithSubjectCSR(ctx, tenantA, identity.ID, orchestrator.StateIssued, "retain mail", "indexed-issue", "", requirement.IssuanceBinding()); err != nil {
		t.Fatal(err)
	}
	index, found, err := st.IdentityInitialIssuance(ctx, tenantA, identity.ID)
	if err != nil || !found {
		t.Fatalf("first issuance = %+v, %v, %v", index, found, err)
	}
	original, found, err := log.EventAtSequence(ctx, index.Seq)
	if err != nil || !found {
		t.Fatalf("original event: %v, %v", found, err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*events.Event, *lifecycleSecurityPayload)
	}{
		{"foreign tenant", func(e *events.Event, _ *lifecycleSecurityPayload) { e.TenantID = tenantB }},
		{"wrong event type", func(e *events.Event, _ *lifecycleSecurityPayload) { e.Type = projections.EventIdentityDeployed }},
		{"wrong identity", func(_ *events.Event, p *lifecycleSecurityPayload) { p.IdentityID = store.ZeroUUID }},
		{"wrong command", func(_ *events.Event, p *lifecycleSecurityPayload) { p.IdempotencyKey = "other-command" }},
		{"wrong edge", func(_ *events.Event, p *lifecycleSecurityPayload) { p.From = "renewing" }},
		{"unknown schema", func(e *events.Event, _ *lifecycleSecurityPayload) { e.SchemaVersion = 99 }},
		{"legacy schema smuggles policy", func(e *events.Event, _ *lifecycleSecurityPayload) { e.SchemaVersion = 3 }},
		{"missing binding", func(_ *events.Event, p *lifecycleSecurityPayload) { p.Issuance = nil }},
		{"missing policy revision", func(_ *events.Event, p *lifecycleSecurityPayload) { p.Issuance.ProfileVersion = 99 }},
		{"changed policy digest", func(_ *events.Event, p *lifecycleSecurityPayload) {
			p.Issuance.ProfileSpecDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := original
			e.ID = ""
			var payload lifecycleSecurityPayload
			if err := json.Unmarshal(e.Data, &payload); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&e, &payload)
			e.Data, err = json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			e, err = log.Append(ctx, e)
			if err != nil {
				t.Fatal(err)
			}
			// Fault injection only: a corrupted projection points at another event.
			// The production reader must verify the immutable event, not trust this index.
			if _, err := st.SystemPool().Exec(ctx, `UPDATE identity_transitions SET seq=$3 WHERE tenant_id=$1 AND identity_id=$2`, tenantA, identity.ID, seqParam(e.Sequence)); err != nil {
				t.Fatal(err)
			}
			if got, err := orch.ProfileApprovalRequirement(ctx, tenantA, identity.ID); err == nil {
				t.Fatalf("untrusted history selected/fell back to policy: %+v", got)
			}
		})
	}
	// Historical, unassigned issuance remains unassigned; fields from a newer
	// schema cannot silently turn it into policy authority (tested above).
	legacy := original
	legacy.ID, legacy.SchemaVersion = "", 3
	var historical lifecycleSecurityPayload
	if err := json.Unmarshal(legacy.Data, &historical); err != nil {
		t.Fatal(err)
	}
	historical.Issuance = nil
	legacy.Data, err = json.Marshal(historical)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err = log.Append(ctx, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SystemPool().Exec(ctx, `UPDATE identity_transitions SET seq=$3 WHERE tenant_id=$1 AND identity_id=$2`, tenantA, identity.ID, seqParam(legacy.Sequence)); err != nil {
		t.Fatal(err)
	}
	if got, err := orch.ProfileApprovalRequirement(ctx, tenantA, identity.ID); err != nil || got.ProfileName != "" {
		t.Fatalf("legacy unassigned issuance = %+v, %v", got, err)
	}
	if _, err := st.SystemPool().Exec(ctx, `INSERT INTO identity_transitions
		(tenant_id, identity_id, seq, from_state, to_state, event_type, reason, occurred_at, idempotency_key, subject_csr_pem)
		SELECT tenant_id, identity_id, $3, from_state, to_state, event_type, reason, occurred_at, idempotency_key, subject_csr_pem
		FROM identity_transitions WHERE tenant_id=$1 AND identity_id=$2`, tenantA, identity.ID, seqParam(original.Sequence)); err != nil {
		t.Fatal(err)
	}
	if got, err := orch.ProfileApprovalRequirement(ctx, tenantA, identity.ID); err == nil {
		t.Fatalf("ambiguous first issuance selected/fell back to policy: %+v", got)
	}
	if _, err := st.SystemPool().Exec(ctx, `DELETE FROM identity_transitions WHERE tenant_id=$1 AND identity_id=$2 AND seq=$3`, tenantA, identity.ID, seqParam(legacy.Sequence)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SystemPool().Exec(ctx, `UPDATE identity_transitions SET seq=$3 WHERE tenant_id=$1 AND identity_id=$2`, tenantA, identity.ID, seqParam(original.Sequence)); err != nil {
		t.Fatal(err)
	}
	if err := log.Delete(ctx, original.Sequence); err != nil {
		t.Fatal(err)
	}
	if got, err := orch.ProfileApprovalRequirement(ctx, tenantA, identity.ID); err == nil {
		t.Fatalf("missing event selected/fell back to policy: %+v", got)
	}
}
