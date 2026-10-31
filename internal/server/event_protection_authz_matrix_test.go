// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

// Source/custody and actual orchestrator/PG behavior with an explicit activation
// fixture. This is not public activation, worker or isolated signer proof.
func TestEventKeyAuthorizationAuditPreservesLegacyAndProtectedLifetimes(t *testing.T) {
	for _, tc := range []struct {
		name                string
		protected, offboard bool
	}{
		{"legacy-live", false, false}, {"legacy-offboarded", false, true},
		{"protected-live", true, false}, {"protected-offboarded", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newServerTestStore(t)
			cfg := eventProtectionRuntimeConfigFixture(t)
			if !tc.protected {
				cfg.Privacy.EventProtection.KeyDirectory = ""
			}
			key := testAuditSigningKey(t)
			log, protection, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = protection.Close() })
			t.Cleanup(func() { _ = log.Close() })
			const tenant = "d788946b-0f1b-4533-a910-2ec5d87af28c"
			registration, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: []byte(`{"name":"authorization fixture"}`)})
			if err != nil {
				t.Fatal(err)
			}
			if tc.protected {
				request, err := eventprivacy.NewRequested(tenant, registration.ID, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				wire, err := json.Marshal(request)
				if err != nil {
					t.Fatal(err)
				}
				requested, err := log.Append(t.Context(), events.Event{ID: eventprivacy.RequestedEventID(request), Type: eventprivacy.EventRequested, TenantID: tenant, Data: wire})
				if err != nil {
					t.Fatal(err)
				}
				ref := eventprotect.KeyRef{TenantID: tenant, ID: request.KeyID}
				if err := protection.custody.Provision(t.Context(), ref); err != nil {
					t.Fatal(err)
				}
				creation, err := protection.custody.CreationEvidence(t.Context(), ref)
				if err != nil {
					t.Fatal(err)
				}
				wire, err = json.Marshal(eventprivacy.Activated{RegistrationIdentity: registration.ID, OperationID: request.KeyID, KeyID: request.KeyID, RetentionNanos: request.RetentionNanos, RequestedEventID: requested.ID, RequestedSequence: requested.Sequence, RequestedAt: requested.Time, Creation: creation})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := log.Append(t.Context(), events.Event{ID: request.KeyID, Type: eventprivacy.EventActivated, TenantID: tenant, Data: wire}); err != nil {
					t.Fatal(err)
				}
			}
			if err := projections.New(st, protection.projectionOptions()...).Rebuild(t.Context(), log); err != nil {
				t.Fatal(err)
			}
			srv, err := Build(t.Context(), Deps{Store: st, Log: log, AuditSigningKey: key, eventProtection: protection})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = srv.Shutdown(t.Context()) }()
			if tc.offboard {
				if _, err := srv.orch.OffboardTenant(t.Context(), orchestrator.TenantOffboardCommand{TenantID: tenant, RegistrationIdentity: registration.ID}); err != nil {
					t.Fatal(err)
				}
				if _, err := st.GetTenant(t.Context(), tenant); !errors.Is(err, pgx.ErrNoRows) {
					t.Fatal("fixture did not really remove tenant state")
				}
			}
			const subject = "authorization-private-person@example.invalid"
			const privateReason = "authorization-private-reason"
			ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: subject, Roles: []string{"authorization-private-role"}})
			decision := orchestrator.AuthzDecision{Actor: subject, Permission: "owners:write", Resource: "authorization-private-resource", Target: "authorization-private-target", Decision: "deny", Reason: privateReason, Roles: []string{"authorization-private-role"}}
			if err := srv.orch.RecordAuthzDecision(ctx, tenant, decision); err != nil {
				t.Fatal(err)
			}
			var decisions []events.Event
			if err := log.Replay(t.Context(), 0, func(event events.Event) error {
				if event.Type == "authz.decision" {
					decisions = append(decisions, event)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if len(decisions) != 1 {
				t.Fatalf("decision count=%d", len(decisions))
			}
			event := decisions[0]
			if tc.protected && tc.offboard {
				body, err := eventprivacy.ParseMinimalAuthzDecision(event)
				if err != nil || body.DetailsOmitted != "tenant_offboarded" || event.Actor != nil || event.Protection != nil {
					t.Fatalf("offboard audit was not the closed alternate: %v", err)
				}
			} else {
				if event.SchemaVersion != 1 || event.Actor == nil || event.Actor.Subject != subject || !bytes.Contains(event.Data, []byte(privateReason)) {
					t.Fatal("legacy or active detailed audit representation changed")
				}
				if (event.Protection != nil) != tc.protected {
					t.Fatal("active protection/default-off semantics changed")
				}
			}
			head, err := log.LastSequence(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := log.ExportBackupHistoryThrough(t.Context(), head, func(record events.BackupHistoryRecord) error {
				if tc.protected && (bytes.Contains(record.Stored, []byte(subject)) || bytes.Contains(record.Stored, []byte(privateReason))) {
					t.Fatal("protected source retained readable audit context")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if tc.offboard {
				if _, err := st.GetTenant(t.Context(), tenant); !errors.Is(err, pgx.ErrNoRows) {
					t.Fatal("audit-only write recreated tenant service")
				}
				if _, err := srv.orch.CreateOwner(ctx, tenant, "team", "must remain refused", "refused@example.invalid"); err == nil {
					t.Fatal("post-delete audit exception granted an ordinary mutation")
				}
				after, err := log.LastSequence(t.Context())
				if err != nil || after != head {
					t.Fatal("refused mutation appended source after tenant deletion")
				}
			}
		})
	}
}
