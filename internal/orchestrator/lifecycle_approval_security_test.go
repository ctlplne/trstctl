// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/privacyref"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type lifecycleAuthorityFixture struct {
	store      *store.Store
	log        *events.Log
	orch       *orchestrator.Orchestrator
	identity   store.Identity
	request    store.OperationApprovalRequest
	use        store.OperationApprovalUse
	key        string
	csr        string
	reason     string
	requester  string
	outboxKey  string
	targetType string
}

func newLifecycleAuthorityFixture(
	t *testing.T,
	st *store.Store,
	log *events.Log,
	key, csr, reason, requester string,
	extraEvidence ...string,
) lifecycleAuthorityFixture {
	t.Helper()
	if st == nil {
		st = newStore(t)
	}
	resetOrchestratorOperationApprovals(t, st)
	if log == nil {
		log = openLog(t)
	}
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	owner, err := orch.CreateOwner(context.Background(), tenantA, "service", "lifecycle-security-owner", "")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	identity, err := orch.CreateIdentity(context.Background(), tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "lifecycle-security.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
	_, version, err := st.IdentityApprovalTarget(context.Background(), tenantA, identity.ID)
	if err != nil {
		t.Fatalf("resolve identity approval target: %v", err)
	}
	evidence := append([]string(nil), extraEvidence...)
	evidence = append(evidence, "idempotency-key-sha256:"+crypto.SHA256Hex([]byte(key)))
	if strings.TrimSpace(csr) != "" {
		evidence = append(evidence, "csr-sha256:"+crypto.SHA256Hex([]byte(strings.TrimSpace(csr))))
	}
	request, err := orch.EnsureOperationApprovalRequest(context.Background(), tenantA, orchestrator.OperationApprovalIntent{
		ResourceKind: "identity", ResourceID: identity.ID, ResourceName: identity.Name,
		Action: "issue", Requester: requester, FromState: string(orchestrator.StateRequested),
		ToState: string(orchestrator.StateIssued), TargetVersion: version,
		Reason: reason, EvidenceRefs: evidence, RequiredApprovals: 1, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("ensure lifecycle approval: %v", err)
	}
	request, err = orch.RecordOperationApprovalDecision(context.Background(), tenantA, orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: request.IntentDigest,
		Approver: "reviewer@example.test", Decision: store.ApprovalDecisionApprove,
	})
	if err != nil {
		t.Fatalf("approve lifecycle command: %v", err)
	}
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		t.Fatalf("build lifecycle authority: %v", err)
	}
	return lifecycleAuthorityFixture{
		store: st, log: log, orch: orch, identity: identity, request: request, use: use,
		key: key, csr: strings.TrimSpace(csr), reason: reason, requester: requester,
		outboxKey: "transition:" + key, targetType: projections.EventIdentityIssued,
	}
}

func TestApprovedLifecycleCommandBindsAttemptReasonAndGenericEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*lifecycleAuthorityFixture)
	}{
		{name: "idempotency key", mutate: func(f *lifecycleAuthorityFixture) { f.key = "different-key" }},
		{name: "CSR", mutate: func(f *lifecycleAuthorityFixture) { f.csr = "different-public-csr" }},
		{name: "reason", mutate: func(f *lifecycleAuthorityFixture) { f.reason = "different reason" }},
		{name: "generic evidence", mutate: func(f *lifecycleAuthorityFixture) {
			for index, ref := range f.use.EvidenceRefs {
				if ref == "ticket:INC-770" {
					f.use.EvidenceRefs[index] = "ticket:INC-771"
				}
			}
		}},
		{name: "missing complete evidence", mutate: func(f *lifecycleAuthorityFixture) { f.use.EvidenceRefs = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLifecycleAuthorityFixture(t, nil, nil, "approved-attempt", "public-csr",
				"reviewed reason", "requester@example.test", "ticket:INC-770")
			headBefore, err := fixture.log.LastSequence(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&fixture)
			err = fixture.orch.TransitionWithSubjectCSRAndApproval(context.Background(), tenantA,
				fixture.identity.ID, orchestrator.StateIssued, fixture.reason, fixture.key, fixture.csr, fixture.use)
			if !errors.Is(err, store.ErrApprovalDrifted) {
				t.Fatalf("mutated %s command = %v, want ErrApprovalDrifted", test.name, err)
			}
			if headAfter, headErr := fixture.log.LastSequence(context.Background()); headErr != nil || headAfter != headBefore {
				t.Fatalf("mutated command event head = (%d, %v), want %d", headAfter, headErr, headBefore)
			}
			request, err := fixture.store.GetOperationApproval(context.Background(), tenantA, fixture.request.ID)
			if err != nil || request.Status != store.ApprovalStatusApproved || request.ConsumedEventID != "" {
				t.Fatalf("mutated command authority = (%+v, %v), want still approved", request, err)
			}
			identity, err := fixture.store.GetIdentity(context.Background(), tenantA, fixture.identity.ID)
			if err != nil || identity.Status != string(orchestrator.StateRequested) {
				t.Fatalf("mutated command identity = (%+v, %v), want requested", identity, err)
			}
		})
	}
}

type lifecycleSecurityPayload struct {
	IdentityID     string                                  `json:"identity_id"`
	From           string                                  `json:"from"`
	To             string                                  `json:"to"`
	Reason         string                                  `json:"reason,omitempty"`
	IdempotencyKey string                                  `json:"idempotency_key,omitempty"`
	SubjectCSRPEM  string                                  `json:"subject_csr_pem,omitempty"`
	SideEffect     *lifecycleSecuritySideEffect            `json:"side_effect,omitempty"`
	Approval       *store.OperationApprovalUse             `json:"approval,omitempty"`
	Issuance       *store.OperationApprovalIssuanceBinding `json:"issuance,omitempty"`
}

type lifecycleSecuritySideEffect struct {
	Destination       string `json:"destination"`
	IdempotencyKey    string `json:"idempotency_key"`
	Payload           []byte `json:"payload,omitempty"`
	RequiredAgentRole string `json:"required_agent_role,omitempty"`
}

func retainedEventByID(t *testing.T, log *events.Log, eventID string) events.Event {
	t.Helper()
	var retained events.Event
	if err := log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.ID == eventID {
			retained = event
		}
		return nil
	}); err != nil {
		t.Fatalf("replay retained event: %v", err)
	}
	if retained.ID == "" {
		t.Fatalf("retained event %s not found", eventID)
	}
	return retained
}

func TestApprovedLifecycleCanonicalOuterEventIsTheOnlyOutboxBody(t *testing.T) {
	fixture := newLifecycleAuthorityFixture(t, nil, nil, "canonical-outbox", "", "canonical reason",
		"requester@example.test", "ticket:canonical")
	ctx := context.Background()
	if err := fixture.orch.TransitionWithSubjectCSRAndApproval(ctx, tenantA, fixture.identity.ID,
		orchestrator.StateIssued, fixture.reason, fixture.key, fixture.csr, fixture.use); err != nil {
		t.Fatalf("commit approved lifecycle: %v", err)
	}
	consumed, err := fixture.store.GetOperationApproval(ctx, tenantA, fixture.request.ID)
	if err != nil {
		t.Fatal(err)
	}
	retained := retainedEventByID(t, fixture.log, consumed.ConsumedEventID)
	var payload lifecycleSecurityPayload
	if err := json.Unmarshal(retained.Data, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.SideEffect == nil || len(payload.SideEffect.Payload) != 0 ||
		bytes.Contains(retained.Data, []byte(`"payload"`)) {
		t.Fatalf("v4 lifecycle event retained a nested command copy: %s", retained.Data)
	}
	payload.SideEffect = nil
	wantBody, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got := outboxPayload(t, ctx, fixture.store.SystemPool(), tenantA, fixture.outboxKey); !bytes.Equal(got, wantBody) {
		t.Fatalf("warm outbox body differs from canonical outer event:\n got=%s\nwant=%s", got, wantBody)
	}

	if _, err := fixture.store.SystemPool().Exec(ctx,
		`DELETE FROM outbox WHERE tenant_id = $1 AND destination = 'ca.issue' AND idempotency_key = $2`,
		tenantA, fixture.outboxKey); err != nil {
		t.Fatalf("remove exact test outbox row: %v", err)
	}
	if _, err := fixture.store.SystemPool().Exec(ctx,
		`UPDATE outbox_reconciliation_checkpoint SET reconciled_seq = $1 WHERE id = 1`, retained.Sequence-1); err != nil {
		t.Fatalf("rewind exact reconciliation cursor: %v", err)
	}
	healed, err := fixture.orch.ReconcileOutbox(ctx, fixture.log)
	if err != nil || healed != 1 {
		t.Fatalf("reconcile canonical lifecycle body = (%d, %v), want (1, nil)", healed, err)
	}
	if got := outboxPayload(t, ctx, fixture.store.SystemPool(), tenantA, fixture.outboxKey); !bytes.Equal(got, wantBody) {
		t.Fatalf("reconciled outbox body differs from canonical outer event:\n got=%s\nwant=%s", got, wantBody)
	}
}

func TestUnapprovedProfileIssuanceCanonicalV5RebuildAndReconcile(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	resetOrchestratorOperationApprovals(t, st)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	const profileName = "unapproved-v5-profile"
	if _, err := orch.CreateProfile(ctx, tenantA, profileName, mustProfileSpec(t, profile.CertificateProfile{
		Name: profileName, MaxValidity: profile.Duration(6 * time.Hour), AllowedProtocols: []string{"api"},
	})); err != nil {
		t.Fatal(err)
	}
	owner, err := orch.CreateOwner(ctx, tenantA, "service", "unapproved-v5-owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "unapproved-v5.example.test", OwnerID: owner.ID,
		Attributes: json.RawMessage(`{"profile_name":"unapproved-v5-profile"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	requirement, err := orch.ProfileApprovalRequirement(ctx, tenantA, identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	binding := requirement.IssuanceBinding()
	const key = "unapproved-v5-issue"
	if err := orch.TransitionWithSubjectCSR(ctx, tenantA, identity.ID, orchestrator.StateIssued,
		"pin short profile without approval", key, "", binding); err != nil {
		t.Fatalf("commit v5 issuance: %v", err)
	}

	var retained events.Event
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type != projections.EventIdentityIssued {
			return nil
		}
		var payload lifecycleSecurityPayload
		if err := json.Unmarshal(event.Data, &payload); err == nil && payload.IdentityID == identity.ID {
			retained = event
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if retained.ID == "" || retained.SchemaVersion != projections.LifecycleIssuanceEventSchemaVersion {
		t.Fatalf("retained non-approval issuance event = %+v", retained)
	}
	var payload lifecycleSecurityPayload
	if err := json.Unmarshal(retained.Data, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Approval != nil || payload.Issuance == nil || payload.SideEffect == nil ||
		len(payload.SideEffect.Payload) != 0 || payload.Issuance.ProfileID != binding.ProfileID ||
		payload.Issuance.ProfileVersion != binding.ProfileVersion ||
		payload.Issuance.ProfileSpecDigest != binding.ProfileSpecDigest ||
		payload.Issuance.EffectiveTTLSeconds != int64((6*time.Hour)/time.Second) {
		t.Fatalf("retained v5 binding = %+v approval=%+v side_effect=%+v", payload.Issuance, payload.Approval, payload.SideEffect)
	}
	payload.SideEffect = nil
	wantBody, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	outboxKey := "transition:" + key
	if got := outboxPayload(t, ctx, st.SystemPool(), tenantA, outboxKey); !bytes.Equal(got, wantBody) {
		t.Fatalf("warm v5 outbox body differs from canonical event:\n got=%s\nwant=%s", got, wantBody)
	}

	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatalf("cold rebuild v5 issuance: %v", err)
	}
	rebuilt, err := st.GetIdentity(ctx, tenantA, identity.ID)
	if err != nil || rebuilt.Status != string(orchestrator.StateIssued) {
		t.Fatalf("rebuilt v5 identity = (%+v, %v)", rebuilt, err)
	}
	if _, err := st.SystemPool().Exec(ctx,
		`DELETE FROM outbox WHERE tenant_id = $1 AND destination = 'ca.issue' AND idempotency_key = $2`,
		tenantA, outboxKey); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SystemPool().Exec(ctx,
		`UPDATE outbox_reconciliation_checkpoint SET reconciled_seq = $1 WHERE id = 1`, retained.Sequence-1); err != nil {
		t.Fatal(err)
	}
	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil || healed != 1 {
		t.Fatalf("reconcile v5 issuance = (%d, %v), want (1, nil)", healed, err)
	}
	if got := outboxPayload(t, ctx, st.SystemPool(), tenantA, outboxKey); !bytes.Equal(got, wantBody) {
		t.Fatalf("reconciled v5 outbox body differs from canonical event:\n got=%s\nwant=%s", got, wantBody)
	}
}

func TestApprovedLifecycleConsumedReplayRevalidatesRetainedCommand(t *testing.T) {
	fixture := newLifecycleAuthorityFixture(t, nil, nil, "replay-command", "public-csr", "replay reason",
		"requester@example.test", "ticket:replay")
	ctx := context.Background()
	if err := fixture.orch.TransitionWithSubjectCSRAndApproval(ctx, tenantA, fixture.identity.ID,
		orchestrator.StateIssued, fixture.reason, fixture.key, fixture.csr, fixture.use); err != nil {
		t.Fatalf("commit approved lifecycle: %v", err)
	}
	headBefore, err := fixture.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		reason    string
		key       string
		csr       string
		mutateUse func(*store.OperationApprovalUse)
	}{
		{name: "reason", reason: "changed", key: fixture.key, csr: fixture.csr},
		{name: "idempotency key", reason: fixture.reason, key: "changed", csr: fixture.csr},
		{name: "CSR", reason: fixture.reason, key: fixture.key, csr: "changed"},
		{name: "action", reason: fixture.reason, key: fixture.key, csr: fixture.csr,
			mutateUse: func(use *store.OperationApprovalUse) { use.Action = "revoke" }},
		{name: "target version", reason: fixture.reason, key: fixture.key, csr: fixture.csr,
			mutateUse: func(use *store.OperationApprovalUse) { use.TargetVersion++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			use := fixture.use
			use.EvidenceRefs = append([]string(nil), fixture.use.EvidenceRefs...)
			if test.mutateUse != nil {
				test.mutateUse(&use)
			}
			err := fixture.orch.TransitionWithSubjectCSRAndApproval(ctx, tenantA, fixture.identity.ID,
				orchestrator.StateIssued, test.reason, test.key, test.csr, use)
			if err == nil {
				t.Fatalf("changed retained %s replay succeeded", test.name)
			}
			if headAfter, headErr := fixture.log.LastSequence(ctx); headErr != nil || headAfter != headBefore {
				t.Fatalf("changed replay event head = (%d, %v), want %d", headAfter, headErr, headBefore)
			}
		})
	}
}

func lifecycleRewriteLog(t *testing.T, options ...events.OpenOption) *events.Log {
	t.Helper()
	options = append([]events.OpenOption{
		events.WithHistoryRewriteContinuityVerifier(func(_ context.Context, evidence events.TenantDataContinuityEvidence) error {
			if evidence.OperationID == "" || evidence.TenantID == "" || evidence.ReceiptSequence == 0 || evidence.Receipt.ID == "" {
				return errors.New("incomplete lifecycle rewrite continuity evidence")
			}
			return nil
		}),
	}, options...)
	log, err := events.Open(context.Background(), config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	}, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

func lifecycleRewriteProofOptions(st *store.Store) []events.TenantDataRewriteOption {
	prepare := func(ctx context.Context, _ events.TenantDataRewriteReport, proceed func(context.Context) error) error {
		return proceed(ctx)
	}
	if st != nil {
		prepare = st.PrepareTenantDataCutover
	}
	return []events.TenantDataRewriteOption{
		events.WithTenantDataCutoverPreparation(prepare),
		events.WithTenantDataAuditContinuity(func(context.Context, events.TenantDataAuditView) (events.TenantDataAuditCheckpoint, error) {
			return events.TenantDataAuditCheckpoint{IdentityDigest: strings.Repeat("d", 64)}, nil
		}),
		events.WithTenantDataContinuity(func(_ context.Context, report events.TenantDataRewriteReport) (events.Event, error) {
			data, err := json.Marshal(report)
			return events.Event{ID: "lifecycle-rewrite-receipt-" + report.OperationID,
				Type: "tenant.data.rewrite.receipt", TenantID: report.TenantID,
				Time: report.CompletedAt, Data: data}, err
		}),
	}
}

func TestApprovedLifecyclePrivacyRewriteRebuildAndRecoveryContainNoRawSubject(t *testing.T) {
	const subject = "alice.lifecycle@example.test"
	st := newStore(t)
	log := lifecycleRewriteLog(t,
		events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(st)))
	fixture := newLifecycleAuthorityFixture(t, st, log, "privacy-lifecycle", "",
		"issue for "+subject, subject, "profile-owner:"+subject)
	if fixture.store != st {
		t.Fatal("lifecycle authority fixture did not reuse the rewrite coordinator store")
	}
	ctx := context.Background()
	if err := fixture.orch.TransitionWithSubjectCSRAndApproval(ctx, tenantA, fixture.identity.ID,
		orchestrator.StateIssued, fixture.reason, fixture.key, fixture.csr, fixture.use); err != nil {
		t.Fatalf("commit privacy lifecycle: %v", err)
	}
	consumed, err := fixture.store.GetOperationApproval(ctx, tenantA, fixture.request.ID)
	if err != nil {
		t.Fatal(err)
	}
	retained := retainedEventByID(t, log, consumed.ConsumedEventID)
	owner, err := fixture.orch.CreateOwner(ctx, tenantA, "service", "legacy-privacy-owner", "")
	if err != nil {
		t.Fatal(err)
	}
	legacyIdentity, err := fixture.orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "legacy-privacy.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	legacyInner, err := json.Marshal(map[string]string{
		"identity_id": legacyIdentity.ID, "from": "requested", "to": "issued",
		"requester": subject, "profile": "prod/" + subject,
		"reason": "legacy issue for " + subject, "idempotency_key": "privacy-v3",
	})
	if err != nil {
		t.Fatal(err)
	}
	legacyOuter, err := json.Marshal(lifecycleSecurityPayload{
		IdentityID: legacyIdentity.ID, From: "requested", To: "issued",
		Reason: "legacy issue for " + subject, IdempotencyKey: "privacy-v3",
		SideEffect: &lifecycleSecuritySideEffect{
			Destination: "ca.issue", IdempotencyKey: "transition:privacy-v3", Payload: legacyInner,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	legacyEvent, err := log.Append(ctx, events.Event{
		ID: events.NewID(), Type: projections.EventIdentityIssued, TenantID: tenantA,
		SchemaVersion: projections.LifecycleSideEffectEventSchemaVersion, Data: legacyOuter,
	})
	if err != nil {
		t.Fatalf("append historical v3 lifecycle fixture: %v", err)
	}
	var approvedOutboxID int64
	if err := fixture.store.SystemPool().QueryRow(ctx,
		`UPDATE outbox
		    SET status = 'delivered', attempts = 4, delivered_at = now()
		  WHERE tenant_id = $1 AND destination = 'ca.issue' AND idempotency_key = $2
		  RETURNING id`, tenantA, fixture.outboxKey).Scan(&approvedOutboxID); err != nil {
		t.Fatal(err)
	}
	var legacyOutboxID int64
	if err := fixture.store.SystemPool().QueryRow(ctx,
		`INSERT INTO outbox
		    (tenant_id, destination, payload, idempotency_key, effect_lane, status, attempts, last_error)
		 VALUES ($1, 'ca.issue', $2, 'transition:privacy-v3', 'ca.issue', 'pending', 2, 'retry fixture')
		 RETURNING id`, tenantA, legacyInner).Scan(&legacyOutboxID); err != nil {
		t.Fatal(err)
	}
	if got := outboxPayload(t, ctx, fixture.store.SystemPool(), tenantA, fixture.outboxKey); !bytes.Contains(got, []byte(subject)) {
		t.Fatalf("delivered v4 fixture did not contain raw subject before rewrite: %s", got)
	}
	if got := outboxPayload(t, ctx, fixture.store.SystemPool(), tenantA, "transition:privacy-v3"); !bytes.Contains(got, []byte(subject)) {
		t.Fatalf("pending v3 fixture did not contain raw subject before rewrite: %s", got)
	}

	privacyOrch := orchestrator.NewOrchestrator(log, fixture.store, orchestrator.NewOutbox(fixture.store),
		orchestrator.WithTenantDataRewriteOptions(lifecycleRewriteProofOptions(st)...))
	if _, err := privacyOrch.ErasePrivacySubject(ctx, tenantA, subject, "erase lifecycle authority for "+subject); err != nil {
		t.Fatalf("erase lifecycle privacy subject: %v", err)
	}
	placeholder := privacyref.Placeholder(privacyref.SubjectRef(tenantA, subject))
	outbox := orchestrator.NewOutbox(fixture.store)
	approvedRecord, err := outbox.Get(ctx, tenantA, approvedOutboxID)
	if err != nil || approvedRecord.Status != "delivered" || approvedRecord.Attempts != 4 ||
		bytes.Contains(approvedRecord.Payload, []byte(subject)) || !bytes.Contains(approvedRecord.Payload, []byte(placeholder)) {
		t.Fatalf("rewritten delivered v4 outbox = (%+v, %v)", approvedRecord, err)
	}
	legacyRecord, err := outbox.Get(ctx, tenantA, legacyOutboxID)
	if err != nil || legacyRecord.Status != "pending" || legacyRecord.Attempts != 2 || legacyRecord.LastError != "retry fixture" ||
		bytes.Contains(legacyRecord.Payload, []byte(subject)) || !bytes.Contains(legacyRecord.Payload, []byte("prod/"+placeholder)) {
		t.Fatalf("rewritten pending v3 outbox = (%+v, %v)", legacyRecord, err)
	}
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if bytes.Contains(event.Data, []byte(subject)) {
			t.Fatalf("rewritten event %s retained raw subject: %s", event.Type, event.Data)
		}
		if event.ID == legacyEvent.ID {
			var legacy lifecycleSecurityPayload
			if err := json.Unmarshal(event.Data, &legacy); err != nil {
				return err
			}
			if legacy.SideEffect == nil || bytes.Contains(legacy.SideEffect.Payload, []byte(subject)) ||
				!bytes.Contains(legacy.SideEffect.Payload, []byte("prod/"+placeholder)) {
				t.Fatalf("rewritten v3 nested command = %+v payload=%s", legacy.SideEffect, legacy.SideEffect.Payload)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(fixture.store).Rebuild(ctx, log); err != nil {
		t.Fatalf("cold rebuild rewritten lifecycle: %v", err)
	}
	rebuilt, err := fixture.store.GetOperationApproval(ctx, tenantA, fixture.request.ID)
	if err != nil || rebuilt.Status != store.ApprovalStatusConsumed || rebuilt.Requester != placeholder ||
		rebuilt.Reason != "" || len(rebuilt.EvidenceRefs) != 0 {
		t.Fatalf("rebuilt rewritten authority = (%+v, %v)", rebuilt, err)
	}
	identity, err := fixture.store.GetIdentity(ctx, tenantA, fixture.identity.ID)
	if err != nil || identity.Status != string(orchestrator.StateIssued) {
		t.Fatalf("rebuilt rewritten identity = (%+v, %v), want issued", identity, err)
	}
	legacyRebuilt, err := fixture.store.GetIdentity(ctx, tenantA, legacyIdentity.ID)
	if err != nil || legacyRebuilt.Status != string(orchestrator.StateIssued) {
		t.Fatalf("rebuilt rewritten v3 identity = (%+v, %v), want issued", legacyRebuilt, err)
	}
	if _, err := fixture.store.SystemPool().Exec(ctx,
		`UPDATE outbox_reconciliation_checkpoint SET reconciled_seq = $1 WHERE id = 1`, retained.Sequence-1); err != nil {
		t.Fatal(err)
	}
	healed, err := privacyOrch.ReconcileOutbox(ctx, log)
	if err != nil || healed != 0 {
		t.Fatalf("reconcile existing rewritten lifecycle = (%d, %v), want (0, nil)", healed, err)
	}
	recoveredPayload := outboxPayload(t, ctx, fixture.store.SystemPool(), tenantA, fixture.outboxKey)
	if bytes.Contains(recoveredPayload, []byte(subject)) || !bytes.Contains(recoveredPayload, []byte(placeholder)) {
		t.Fatalf("recovered lifecycle outbox reintroduced erased subject: %s", recoveredPayload)
	}
	if _, err := fixture.store.SystemPool().Exec(ctx,
		`DELETE FROM outbox WHERE tenant_id = $1 AND id = $2`, tenantA, legacyOutboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.SystemPool().Exec(ctx,
		`UPDATE outbox_reconciliation_checkpoint SET reconciled_seq = $1 WHERE id = 1`, legacyEvent.Sequence-1); err != nil {
		t.Fatal(err)
	}
	healed, err = privacyOrch.ReconcileOutbox(ctx, log)
	if err != nil || healed != 1 {
		t.Fatalf("recreate missing rewritten v3 lifecycle = (%d, %v), want (1, nil)", healed, err)
	}
	legacyRecovered := outboxPayload(t, ctx, fixture.store.SystemPool(), tenantA, "transition:privacy-v3")
	if bytes.Contains(legacyRecovered, []byte(subject)) ||
		!bytes.Contains(legacyRecovered, []byte("prod/"+placeholder)) {
		t.Fatalf("recovered v3 nested outbox reintroduced erased identifiers: %s", legacyRecovered)
	}
}

func TestProfileRevisionDecisionRaceCannotLeaveExecutableStaleAuthority(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	resetOrchestratorOperationApprovals(t, st)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	const profileName = "decision-race-profile"
	v1, err := orch.CreateProfile(ctx, tenantA, profileName, mustProfileSpec(t, profile.CertificateProfile{
		Name: profileName, MaxValidity: profile.Duration(12 * time.Hour), AllowedProtocols: []string{"api"},
	}))
	if err != nil || v1.Version != 1 {
		t.Fatalf("create profile v1 = (%+v, %v)", v1, err)
	}
	owner, err := orch.CreateOwner(ctx, tenantA, "service", "profile-decision-race-owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "profile-decision-race.example.test", OwnerID: owner.ID,
		Attributes: json.RawMessage(`{"profile_name":"decision-race-profile"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	requirement, err := orch.ProfileApprovalRequirement(ctx, tenantA, identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	const key = "profile-decision-race"
	evidence, err := requirement.IssuanceBinding().EvidenceRefs()
	if err != nil {
		t.Fatal(err)
	}
	evidence = append(evidence, "idempotency-key-sha256:"+crypto.SHA256Hex([]byte(key)))
	request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
		ResourceKind: "identity", ResourceID: identity.ID, ResourceName: identity.Name,
		Action: "issue", Requester: "alice", FromState: string(orchestrator.StateRequested),
		ToState: string(orchestrator.StateIssued), TargetVersion: 0,
		Reason: "profile decision race", EvidenceRefs: evidence, RequiredApprovals: 1, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(2)
	decisionResult := make(chan error, 1)
	profileResult := make(chan error, 1)
	go func() {
		defer wait.Done()
		<-start
		_, decisionErr := orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
			RequestID: request.ID, IntentDigest: request.IntentDigest,
			Approver: "bob", Decision: store.ApprovalDecisionApprove,
		})
		decisionResult <- decisionErr
	}()
	go func() {
		defer wait.Done()
		<-start
		_, profileErr := orch.CreateProfile(ctx, tenantA, profileName, mustProfileSpec(t, profile.CertificateProfile{
			Name: profileName, MaxValidity: profile.Duration(time.Hour), AllowedProtocols: []string{"api"},
		}))
		profileResult <- profileErr
	}()
	close(start)
	wait.Wait()
	if err := <-profileResult; err != nil {
		t.Fatalf("concurrent profile update: %v", err)
	}
	decisionErr := <-decisionResult
	if decisionErr != nil && !errors.Is(decisionErr, store.ErrApprovalDrifted) {
		t.Fatalf("concurrent approval decision = %v, want success or stable drift", decisionErr)
	}
	current, err := st.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Status == store.ApprovalStatusApproved {
		err = orch.TransitionWithSubjectCSRAndApproval(ctx, tenantA, identity.ID,
			orchestrator.StateIssued, request.Reason, key, "", use)
		if !errors.Is(err, store.ErrApprovalDrifted) {
			t.Fatalf("decision-first stale execution = %v, want ErrApprovalDrifted", err)
		}
		current, err = st.GetOperationApproval(ctx, tenantA, request.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if current.Status != store.ApprovalStatusSuperseded {
		t.Fatalf("profile race left authority status %q, want superseded", current.Status)
	}
	identityAfter, err := st.GetIdentity(ctx, tenantA, identity.ID)
	if err != nil || identityAfter.Status != string(orchestrator.StateRequested) {
		t.Fatalf("profile race identity = (%+v, %v), want requested", identityAfter, err)
	}
	var issuedEvents, issueOutbox int
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type == projections.EventIdentityIssued {
			issuedEvents++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'ca.issue'`, tenantA).Scan(&issueOutbox); err != nil {
		t.Fatal(err)
	}
	if issuedEvents != 0 || issueOutbox != 0 {
		t.Fatalf("profile race emitted lifecycle/outbox work = %d/%d, want zero", issuedEvents, issueOutbox)
	}
}
