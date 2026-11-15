// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestPAMSessionApprovalLinkIsDerivedOrUnrecordedG1L6: a PAM session started
// before its own approval link (G1, migration 0355) read "no approval". Its
// activation's event names the approval it consumed, so the session now
// takes that approval, marked derived. A session from before the link whose
// activation named none stays unrecorded, never "none"; a session whose
// started event is of the schema that records the link, and names none,
// consumed none; one that names its approval keeps it. A snapshot restore and
// an event-only rebuild reach the same links.
func TestPAMSessionApprovalLinkIsDerivedOrUnrecordedG1L6(t *testing.T) {
	s, log := newStore(t), openLog(t)
	p := projections.New(s)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("PAM approval link tenant")})
	marshal := func(v any) []byte {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	// An approved activation approval, as the PAM routes record one.
	approvalID, requestID := uuid.NewString(), uuid.NewString()
	request := projections.ApprovalRequested{ID: approvalID, IntentDigest: "sha256:g1l6-intent", ResourceKind: "pam", ResourceID: "pam:" + requestID,
		Action: "activate", Requester: "g1l6-requester", FromState: "attested", ToState: "active", EvidenceRefs: []string{"pam-command-sha256:g1l6"},
		RequiredApprovals: 1, CreatedAt: now.Add(-10 * time.Minute), ExpiresAt: now.Add(time.Hour)}
	mustAppend(t, log, events.Event{Type: projections.EventApprovalRequested, TenantID: tenantA, Data: marshal(request),
		Actor: &events.Actor{Subject: "g1l6-requester"}})
	mustAppend(t, log, events.Event{Type: projections.EventApprovalDecisionRecorded, TenantID: tenantA, Actor: &events.Actor{Subject: "g1l6-approver"},
		ID: projections.OperationApprovalDecisionEventID(tenantA, approvalID, request.IntentDigest, "g1l6-approver"),
		Data: marshal(projections.ApprovalDecisionRecorded{RequestID: approvalID, IntentDigest: request.IntentDigest, Approver: "g1l6-approver",
			Decision: "approve", DecidedAt: now.Add(-9 * time.Minute)})})
	derived := uuid.NewString()
	// The activation's event ID is a UUID, as the PAM routes derive it: it is
	// what the approval records as consuming it.
	mustAppend(t, log, events.Event{Type: projections.EventPAMSessionActivationRequested, TenantID: tenantA, ID: uuid.NewString(),
		Data: marshal(projections.PAMSessionActivationRequested{ID: derived, RequestID: requestID, TargetType: "postgres",
			CommandDigest: "g1l6", IdempotencyKey: "g1l6-derived", TTLSeconds: 600, Approval: store.OperationApprovalUse{
				RequestID: approvalID, IntentDigest: request.IntentDigest, Requester: request.Requester, ResourceKind: "pam",
				ResourceID: request.ResourceID, Action: "activate", FromState: "attested", ToState: "active",
				RequiredApprovals: 1, EvidenceRefs: request.EvidenceRefs}})})

	// Started events: schema 1 from before the link (the derived one, one
	// whose activation named nothing, one that names its approval), and one
	// of schema 2 that names none.
	started := func(id string, version int, approval string) {
		t.Helper()
		payload := map[string]any{"id": id, "target_type": "postgres", "target_id": "pg-g1l6", "role": "reader", "status": "active",
			"subject": "g1l6-workload", "requested_by": "g1l6-requester", "started_at": now, "expires_at": now.Add(time.Hour)}
		if approval != "" {
			payload["approval_request_id"] = approval
		}
		mustAppend(t, log, events.Event{Type: projections.EventPAMSessionStarted, TenantID: tenantA, SchemaVersion: version, Data: marshal(payload)})
	}
	unrecorded, named, none := uuid.NewString(), uuid.NewString(), uuid.NewString()
	namedApproval := uuid.NewString()
	started(derived, 1, "")
	started(unrecorded, 1, "")
	started(named, 1, namedApproval)
	started(none, projections.PAMCommandRulesEventSchemaVersion, "")
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}

	want := map[string][2]string{
		derived:    {approvalID, store.PAMApprovalLinkDerived},
		unrecorded: {"", ""},
		named:      {namedApproval, store.PAMApprovalLinkRecorded},
		none:       {"", store.PAMApprovalLinkRecorded},
	}
	check := func(stage string) {
		t.Helper()
		page, err := s.ListLivePAMSessionAccessPage(ctx, tenantA, now, "", 50)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string][2]string{}
		for _, session := range page {
			got[session.ID] = [2]string{session.ApprovalRequestID, session.ApprovalLink}
		}
		for id, w := range want {
			if got[id] != w {
				t.Fatalf("%s: session %s reads approval %q link %q, want %q %q", stage, id, got[id][0], got[id][1], w[0], w[1])
			}
		}
	}
	check("projection")
	if _, err := p.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	truncateReadModelAndCheckpoint(t, s)
	if _, err := p.RestoreFromSnapshot(ctx, log); err != nil {
		t.Fatal(err)
	}
	check("snapshot restore")
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	check("event-only rebuild")
}
