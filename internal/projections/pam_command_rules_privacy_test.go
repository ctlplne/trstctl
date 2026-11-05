// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func TestCommandReviewPrivacyKeepsConsumedAuthorityAlignedA262(t *testing.T) {
	for _, subject := range []string{"a", "DROP", "pam-action", "sha256"} {
		t.Run(subject, func(t *testing.T) {
			const tenant = "a2620000-0000-4000-8000-000000000001"

			at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
			session, connection := "a2620000-0000-4000-8000-000000000002", "a2620000-0000-4000-8000-000000000003"
			id := accessrules.ActionID(session, connection, 7, 1, 1)
			deadline := at.Add(30 * time.Second)
			refs := []string{"pam-action:" + id, "pam-message-sha256:" + strings.Repeat("a", 64), "pam-operations:DROP"}
			request := ApprovalRequested{ID: "a2620000-0000-4000-8000-000000000004", ResourceKind: "pam_command", ResourceID: "pam-command:" + id, ResourceName: "postgres/orders", Action: "execute", Requester: subject, FromState: "held", ToState: "authorized", IntentDigest: "sha256:" + strings.Repeat("b", 64), Reason: "Authorize DROP once", EvidenceRefs: refs, RequiredApprovals: 1, CreatedAt: at, ExpiresAt: deadline}
			use := store.OperationApprovalUse{RequestID: request.ID, IntentDigest: request.IntentDigest, Requester: subject, ResourceKind: request.ResourceKind, ResourceID: request.ResourceID, Action: request.Action, FromState: request.FromState, ToState: request.ToState, Reason: request.Reason, EvidenceRefs: refs, RequiredApprovals: 1}
			terminal := PAMCommandReviewDecided{Decision: accessrules.Decision{ID: id, SessionID: session, JobID: 7, Attempt: 1, Protocol: "postgres", Observation: accessrules.Observation{ConnectionID: connection, Ordinal: 1, Phase: "query", RuleIDs: []string{"a2620000-0000-4000-8000-000000000005"}, Operations: []string{"DROP"}, MessageDigest: strings.Repeat("a", 64)}, PolicyDigest: strings.Repeat("b", 64), Status: accessrules.StatusAuthorized, Reason: "review_approved", ObservedAt: at, DecidedAt: at.Add(time.Second), ReviewExpiresAt: &deadline}, Approval: &use}
			rewrite := func(kind string, value any) []byte {
				t.Helper()
				raw, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				out, changed, err := events.PseudonymizeEventDataForSubject(raw, tenant, subject, kind, 1)
				if err != nil || !changed {
					t.Fatalf("rewrite %s: changed=%v %v", kind, changed, err)
				}
				return out
			}
			var rewrittenRequest ApprovalRequested
			var rewrittenTerminal PAMCommandReviewDecided
			if err := json.Unmarshal(rewrite(EventPAMCommandApprovalRequested, request), &rewrittenRequest); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(rewrite(EventPAMCommandReviewDecided, terminal), &rewrittenTerminal); err != nil {
				t.Fatal(err)
			}
			if rewrittenTerminal.Approval == nil || !reflect.DeepEqual(rewrittenRequest.EvidenceRefs, rewrittenTerminal.Approval.EvidenceRefs) || rewrittenRequest.Requester != rewrittenTerminal.Approval.Requester || rewrittenRequest.Reason != rewrittenTerminal.Approval.Reason {
				t.Fatal("privacy rewrite separates consumed command authority from its canonical request")
			}
			if rewrittenTerminal.MessageDigest != terminal.MessageDigest || !reflect.DeepEqual(rewrittenTerminal.Operations, []string{"DROP"}) {
				t.Fatal("a short identity rewrote immutable public command facts")
			}
		})
	}
}

func TestPAMCommandAuthorityCannotHideUnderTheLegacySchemaA262(t *testing.T) {
	for _, kind := range []string{EventPAMTemplateSaved, EventPAMSessionStarted} {
		field := "command_rules"
		payload := `{"command_rules":[]}`
		if kind == EventPAMSessionStarted {
			field = "command_policy"
			payload = `{"command_policy":null}`
		}
		event := events.Event{Type: kind, SchemaVersion: 1, Data: []byte(payload)}
		var err error
		if kind == EventPAMTemplateSaved {
			var value PAMTemplateSaved
			err = decodePAMTemplateVersion(event, &value)
		} else {
			var value PAMSessionStarted
			err = decodePAMSessionVersion(event, &value)
		}
		if err == nil {
			t.Fatalf("legacy %s accepted new authority field %s", kind, field)
		}
		event.SchemaVersion = PAMCommandRulesEventSchemaVersion
		if kind == EventPAMTemplateSaved {
			var value PAMTemplateSaved
			err = decodePAMTemplateVersion(event, &value)
		} else {
			var value PAMSessionStarted
			err = decodePAMSessionVersion(event, &value)
		}
		if err != nil {
			t.Fatalf("declared current field %s refused: %v", field, err)
		}
	}
}
