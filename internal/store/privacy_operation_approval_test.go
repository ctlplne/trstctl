// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

type operationApprovalPrivacyFixture struct {
	requesterRequestID string
	evidenceRequestID  string
	reasonRequestID    string
	requesterDecision  string
	reasonDecision     string
	consumedEventID    string
}

func TestOperationApprovalPrivacyExportAndErasureAreTenantScoped(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for tenantID, name := range map[string]string{tenantA: "Acme", tenantB: "Beta"} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: name}); err != nil {
			t.Fatal(err)
		}
	}

	const subject = "alice.approver@example.com"
	createdAt := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	fixtureA := seedOperationApprovalPrivacyFixture(t, s, tenantA, subject, 4100, createdAt)
	seedOperationApprovalPrivacyFixture(t, s, tenantB, subject, 4200, createdAt)

	exported, err := s.SelectPrivacySubjectExport(ctx, tenantA, subject)
	if err != nil {
		t.Fatalf("SelectPrivacySubjectExport: %v", err)
	}
	byTable := privacyRecordsByTable(exported.ReadModels)
	if got := len(byTable["operation_approval_requests"]); got != 2 {
		t.Fatalf("operation approval request export rows = %d, want 2: %+v", got, byTable["operation_approval_requests"])
	}
	if got := len(byTable["operation_approval_decisions"]); got != 2 {
		t.Fatalf("operation approval decision export rows = %d, want 2: %+v", got, byTable["operation_approval_decisions"])
	}
	if exported.Counts["operation_approval_requests"] != 2 || exported.Counts["operation_approval_decisions"] != 2 {
		t.Fatalf("operation approval export counts = %+v, want two request and two decision rows", exported.Counts)
	}
	for _, table := range []string{"operation_approval_requests", "operation_approval_decisions"} {
		for _, record := range byTable[table] {
			if record.ID == "" || record.Data == "" || !strings.Contains(record.Data, subject) {
				t.Fatalf("%s export omitted the subject-bearing non-secret record content: %+v", table, record)
			}
		}
	}
	for _, record := range exported.ReadModels {
		if record.ID == uuid(tenantB, 4201) || record.ID == uuid(tenantB, 4212) {
			t.Fatalf("tenant B approval record leaked into tenant A export: %+v", record)
		}
	}

	erasure, err := s.SelectPrivacySubjectErasure(ctx, tenantA, subject)
	if err != nil {
		t.Fatalf("SelectPrivacySubjectErasure: %v", err)
	}
	if erasure.Counts["operation_approval_requests"] != 2 || erasure.Counts["operation_approval_decisions"] != 3 {
		t.Fatalf("operation approval erasure counts = %+v, want two request and three decision selectors", erasure.Counts)
	}
	selectorsJSON, err := json.Marshal(erasure.Selectors)
	if err != nil {
		t.Fatalf("marshal erasure selectors: %v", err)
	}
	if strings.Contains(string(selectorsJSON), subject) {
		t.Fatalf("erasure event selectors contain the raw subject: %s", selectorsJSON)
	}
	erasure.RequestedByRef = privacy.SubjectRef(tenantA, "privacy-admin")
	erasure.Reason = "data subject request"
	erasure.ErasedAt = time.Now().UTC().Truncate(time.Microsecond)
	apply := func() error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyPrivacySubjectErasedTx(ctx, tx, erasure)
		})
	}
	if err := apply(); err != nil {
		t.Fatalf("ApplyPrivacySubjectErasedTx: %v", err)
	}
	if err := apply(); err != nil {
		t.Fatalf("idempotent ApplyPrivacySubjectErasedTx replay: %v", err)
	}

	placeholder := privacy.Placeholder(privacy.SubjectRef(tenantA, subject))
	var rawHits, placeholderRequesters, placeholderApprovers int
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT
			  (SELECT count(*) FROM operation_approval_requests
			    WHERE tenant_id = $1 AND (requester = $2 OR position($2 in reason) > 0 OR position($2 in evidence_refs::text) > 0))
			+ (SELECT count(*) FROM operation_approval_decisions
			    WHERE tenant_id = $1 AND (approver = $2 OR position($2 in reason) > 0)),
			  (SELECT count(*) FROM operation_approval_requests WHERE tenant_id = $1 AND requester = $3),
			  (SELECT count(*) FROM operation_approval_decisions WHERE tenant_id = $1 AND approver = $3)`,
			tenantA, subject, placeholder).Scan(&rawHits, &placeholderRequesters, &placeholderApprovers)
	}); err != nil {
		t.Fatalf("scan erased operation approval rows: %v", err)
	}
	if rawHits != 0 {
		t.Fatalf("raw subject remains in %d operation approval rows", rawHits)
	}
	if placeholderRequesters != 1 || placeholderApprovers != 1 {
		t.Fatalf("operation approval placeholder counts = requester:%d approver:%d, want 1/1", placeholderRequesters, placeholderApprovers)
	}

	var digest, status, consumedEventID string
	var reason string
	var evidenceCount int
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT intent_digest, status, consumed_event_id::text, reason, jsonb_array_length(evidence_refs)
			  FROM operation_approval_requests
			 WHERE tenant_id = $1 AND id = $2`,
			tenantA, fixtureA.requesterRequestID).Scan(&digest, &status, &consumedEventID, &reason, &evidenceCount)
	}); err != nil {
		t.Fatalf("scan stable approval authority after erasure: %v", err)
	}
	if digest != "sha256:privacy-requester" || status != store.ApprovalStatusConsumed || consumedEventID != fixtureA.consumedEventID {
		t.Fatalf("erasure changed immutable authority evidence: digest=%q status=%q consumed_event_id=%q", digest, status, consumedEventID)
	}
	if reason != "" || evidenceCount != 0 {
		t.Fatalf("erasure retained request free-form PII: reason=%q evidence_count=%d", reason, evidenceCount)
	}
	if hits := countOperationApprovalPrivacyHits(t, ctx, s, tenantB, subject); hits != 4 {
		t.Fatalf("tenant A erasure changed tenant B rows: raw hits=%d, want 4", hits)
	}

	after, err := s.SelectPrivacySubjectExport(ctx, tenantA, subject)
	if err != nil {
		t.Fatalf("SelectPrivacySubjectExport after erasure: %v", err)
	}
	afterByTable := privacyRecordsByTable(after.ReadModels)
	if len(afterByTable["operation_approval_requests"]) != 0 || len(afterByTable["operation_approval_decisions"]) != 0 {
		t.Fatalf("erased raw subject still resolves operation approvals: %+v", afterByTable)
	}
}

func TestOperationApprovalPrivacyErasureSupersedesLiveAuthorityBeforePseudonymizing(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}

	const subject = "live.approver@example.com"
	now := time.Now().UTC().Truncate(time.Microsecond)
	requesterID := uuid(tenantA, 6101)
	approverID := uuid(tenantA, 6102)
	requesterDecisionID := uuid(tenantA, 6111)
	approverDecisionID := uuid(tenantA, 6112)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO operation_approval_requests
			       (tenant_id, id, intent_digest, resource_kind, resource_id,
			        resource_name, action, requester, from_state, to_state,
			        target_version, reason, evidence_refs, required_approvals,
			        status, created_at, expires_at, updated_at)
			VALUES ($1, $2, 'sha256:live-requester', 'identity', 'identity:privacy-requester',
			        'privacy requester', 'issue', $4, 'requested', 'issued', 1,
			        'routine approval', '[]'::jsonb, 1, 'approved', $5, $6, $5),
			       ($1, $3, 'sha256:live-approver', 'identity', 'identity:privacy-approver',
			        'privacy approver', 'issue', 'other.requester@example.com', 'requested', 'issued', 1,
			        'routine approval', '[]'::jsonb, 1, 'approved', $5, $6, $5)`,
			tenantA, requesterID, approverID, subject, now, now.Add(24*time.Hour)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO operation_approval_decisions
			       (tenant_id, request_id, intent_digest, approver, decision, reason, event_id, decided_at)
			VALUES ($1, $2, 'sha256:live-requester', 'other.reviewer@example.com', 'approve', '', $4, $6),
			       ($1, $3, 'sha256:live-approver', $5, 'approve', '', $7, $6)`,
			tenantA, requesterID, approverID, requesterDecisionID, subject, now, approverDecisionID)
		return err
	}); err != nil {
		t.Fatalf("seed live operation approvals: %v", err)
	}

	erasure, err := s.SelectPrivacySubjectErasure(ctx, tenantA, subject)
	if err != nil {
		t.Fatalf("SelectPrivacySubjectErasure: %v", err)
	}
	erasure.RequestedByRef = privacy.SubjectRef(tenantA, "privacy-admin")
	erasure.ErasedAt = now.Add(time.Minute)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyPrivacySubjectErasedTx(ctx, tx, erasure)
	}); err != nil {
		t.Fatalf("ApplyPrivacySubjectErasedTx: %v", err)
	}

	for _, requestID := range []string{requesterID, approverID} {
		request, err := s.GetOperationApproval(ctx, tenantA, requestID)
		if err != nil {
			t.Fatalf("load erased live approval %s: %v", requestID, err)
		}
		if request.Status != store.ApprovalStatusSuperseded {
			t.Fatalf("erased live approval %s status = %q, want superseded", requestID, request.Status)
		}
		use := store.OperationApprovalUse{
			RequestID: request.ID, IntentDigest: request.IntentDigest,
			Requester: request.Requester, ResourceKind: request.ResourceKind,
			ResourceID: request.ResourceID, Action: request.Action,
			FromState: request.FromState, ToState: request.ToState,
			TargetVersion: request.TargetVersion, RequiredApprovals: request.RequiredApprovals,
		}
		err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			_, validateErr := s.ValidateOperationApprovalUseTx(ctx, tx, tenantA, use, now)
			return validateErr
		})
		if !errors.Is(err, store.ErrApprovalSuperseded) {
			t.Fatalf("erased live approval %s validation = %v, want ErrApprovalSuperseded", requestID, err)
		}
	}
}

func TestOperationApprovalPrivacyRetentionPreflightAndProjection(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for tenantID, name := range map[string]string{tenantA: "Acme", tenantB: "Beta"} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: name}); err != nil {
			t.Fatal(err)
		}
	}

	const subject = "retention.approver@example.com"
	now := time.Now().UTC().Truncate(time.Microsecond)
	oldA := seedOperationApprovalPrivacyFixture(t, s, tenantA, subject, 5100, now.Add(-500*24*time.Hour))
	seedOperationApprovalPrivacyFixture(t, s, tenantA, subject, 5200, now.Add(-24*time.Hour))
	seedOperationApprovalPrivacyFixture(t, s, tenantB, subject, 5300, now.Add(-500*24*time.Hour))

	run, err := s.SelectPrivacyRetention(ctx, tenantA, uuid(tenantA, 5199), privacy.DefaultRetentionPolicy(), now)
	if err != nil {
		t.Fatalf("SelectPrivacyRetention: %v", err)
	}
	if run.Counts["operation_approval_requests"] != 3 || run.Counts["operation_approval_decisions"] != 3 {
		t.Fatalf("operation approval retention preflight counts = %+v, want 3 old requests and 3 old decisions", run.Counts)
	}
	run.RequestedByRef = privacy.SubjectRef(tenantA, "privacy-admin")
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyPrivacyRetentionEnforcedTx(ctx, tx, run)
	}); err != nil {
		t.Fatalf("ApplyPrivacyRetentionEnforcedTx: %v", err)
	}

	oldRequestIDs := []string{oldA.requesterRequestID, oldA.evidenceRequestID, oldA.reasonRequestID}
	oldDecisionIDs := []string{uuid(tenantA, 5111), oldA.requesterDecision, oldA.reasonDecision}
	var retainedRequests, retainedDecisions int
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT
			  (SELECT count(*) FROM operation_approval_requests
			    WHERE tenant_id = $1 AND id::text = ANY($2::text[])
			      AND requester LIKE 'retained:%' AND reason = '' AND evidence_refs = '[]'::jsonb),
			  (SELECT count(*) FROM operation_approval_decisions
			    WHERE tenant_id = $1 AND event_id::text = ANY($3::text[])
			      AND approver LIKE 'retained:%' AND reason = '')`,
			tenantA, oldRequestIDs, oldDecisionIDs).Scan(&retainedRequests, &retainedDecisions)
	}); err != nil {
		t.Fatalf("scan retained operation approval rows: %v", err)
	}
	if retainedRequests != 3 || retainedDecisions != 3 {
		t.Fatalf("retained operation approval rows = requests:%d decisions:%d, want 3/3", retainedRequests, retainedDecisions)
	}

	var status, consumedEventID string
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status, consumed_event_id::text
			FROM operation_approval_requests WHERE tenant_id = $1 AND id = $2`,
			tenantA, oldA.requesterRequestID).Scan(&status, &consumedEventID)
	}); err != nil {
		t.Fatalf("scan retained stable authority: %v", err)
	}
	if status != store.ApprovalStatusConsumed || consumedEventID != oldA.consumedEventID {
		t.Fatalf("retention changed operation authority evidence: status=%q consumed_event_id=%q", status, consumedEventID)
	}
	if hits := countOperationApprovalPrivacyHits(t, ctx, s, tenantA, subject); hits != 4 {
		t.Fatalf("retention changed fresh tenant A approval rows: raw hits=%d, want 4", hits)
	}
	if hits := countOperationApprovalPrivacyHits(t, ctx, s, tenantB, subject); hits != 4 {
		t.Fatalf("tenant A retention changed tenant B rows: raw hits=%d, want 4", hits)
	}

	after, err := s.SelectPrivacyRetention(ctx, tenantA, uuid(tenantA, 5198), privacy.DefaultRetentionPolicy(), now)
	if err != nil {
		t.Fatalf("SelectPrivacyRetention after enforcement: %v", err)
	}
	if after.Counts["operation_approval_requests"] != 0 || after.Counts["operation_approval_decisions"] != 0 {
		t.Fatalf("retention preflight is not idempotent: %+v", after.Counts)
	}
}

func seedOperationApprovalPrivacyFixture(
	t *testing.T,
	s *store.Store,
	tenantID, subject string,
	base int,
	createdAt time.Time,
) operationApprovalPrivacyFixture {
	t.Helper()
	fixture := operationApprovalPrivacyFixture{
		requesterRequestID: uuid(tenantID, base+1),
		evidenceRequestID:  uuid(tenantID, base+2),
		reasonRequestID:    uuid(tenantID, base+3),
		requesterDecision:  uuid(tenantID, base+12),
		reasonDecision:     uuid(tenantID, base+13),
		consumedEventID:    uuid(tenantID, base+21),
	}
	type request struct {
		id, digest, requester, reason, status string
		evidence                              []string
		consumedEventID                       string
	}
	requests := []request{
		{fixture.requesterRequestID, "sha256:privacy-requester", subject, "routine approval", store.ApprovalStatusConsumed, []string{"ticket:privacy"}, fixture.consumedEventID},
		{fixture.evidenceRequestID, "sha256:privacy-evidence", "other.requester@example.com", "requested on behalf of " + subject, store.ApprovalStatusDenied, []string{"case:" + subject}, ""},
		{fixture.reasonRequestID, "sha256:privacy-review-reason", "another.requester@example.com", "routine approval", store.ApprovalStatusDenied, []string{"ticket:other"}, ""},
	}
	type decision struct {
		requestID, digest, approver, reason, eventID, decision string
	}
	decisions := []decision{
		{fixture.requesterRequestID, "sha256:privacy-requester", "reviewer@example.com", "routine approval", uuid(tenantID, base+11), store.ApprovalDecisionApprove},
		{fixture.evidenceRequestID, "sha256:privacy-evidence", subject, "reviewed request", fixture.requesterDecision, store.ApprovalDecisionDeny},
		{fixture.reasonRequestID, "sha256:privacy-review-reason", "another.reviewer@example.com", "consulted " + subject, fixture.reasonDecision, store.ApprovalDecisionDeny},
	}
	ctx := context.Background()
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for _, row := range requests {
			evidence, err := json.Marshal(row.evidence)
			if err != nil {
				return err
			}
			var consumedAt any
			var consumedEventID any
			if row.consumedEventID != "" {
				consumedAt = createdAt.Add(30 * time.Minute)
				consumedEventID = row.consumedEventID
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO operation_approval_requests
				       (tenant_id, id, intent_digest, resource_kind, resource_id, resource_name,
				        action, requester, from_state, to_state, target_version, reason,
				        evidence_refs, required_approvals, status, created_at, expires_at,
				        updated_at, consumed_at, consumed_event_id)
				VALUES ($1, $2, $3, 'identity', $4, $5, 'issue', $6, 'requested', 'issued',
				        1, $7, $8::jsonb, 1, $9, $10, $11, $12, $13, $14)`,
				tenantID, row.id, row.digest, "identity:"+row.id, "privacy "+row.id,
				row.requester, row.reason, evidence, row.status, createdAt,
				createdAt.Add(time.Hour), createdAt.Add(30*time.Minute), consumedAt, consumedEventID); err != nil {
				return err
			}
		}
		for _, row := range decisions {
			if _, err := tx.Exec(ctx, `
				INSERT INTO operation_approval_decisions
				       (tenant_id, request_id, intent_digest, approver, decision, reason, event_id, decided_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
				tenantID, row.requestID, row.digest, row.approver, row.decision, row.reason,
				row.eventID, createdAt.Add(15*time.Minute)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed operation approval privacy fixture for %s: %v", tenantID, err)
	}
	return fixture
}

func privacyRecordsByTable(records []store.PrivacyReadModelRecord) map[string][]store.PrivacyReadModelRecord {
	out := make(map[string][]store.PrivacyReadModelRecord)
	for _, record := range records {
		out[record.Table] = append(out[record.Table], record)
	}
	return out
}

func countOperationApprovalPrivacyHits(t *testing.T, ctx context.Context, s *store.Store, tenantID, subject string) int {
	t.Helper()
	var hits int
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT
			  (SELECT count(*) FROM operation_approval_requests
			    WHERE tenant_id = $1 AND (requester = $2 OR position($2 in reason) > 0 OR position($2 in evidence_refs::text) > 0))
			+ (SELECT count(*) FROM operation_approval_decisions
			    WHERE tenant_id = $1 AND (approver = $2 OR position($2 in reason) > 0))`,
			tenantID, subject).Scan(&hits)
	}); err != nil {
		t.Fatalf("count operation approval privacy hits for %s: %v", tenantID, err)
	}
	return hits
}
