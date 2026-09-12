// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

func TestRenewalFailureNotificationIsDurableAndTenantBound(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := t.Context()
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	const identityID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	seedLifecycleIdentity(t, s, tenantA, identityID, orchestrator.StateRenewing)
	seedLifecycleIdentity(t, s, tenantB, identityID, orchestrator.StateRenewing)
	if err := orch.Transition(ctx, tenantA, identityID, orchestrator.StateRenewalFailed, "private upstream diagnostics must stay out of the notification"); err != nil {
		t.Fatal(err)
	}
	mustStatus(t, s, tenantA, identityID, "renewal_failed")
	mustStatus(t, s, tenantB, identityID, "renewing")
	if got := countOutboxDestination(t, s, tenantA, notify.DestinationRenewalFailure); got != 1 {
		t.Fatalf("renewal failure notifications = %d, want one durable alert", got)
	}
	if got := countOutboxDestination(t, s, tenantB, notify.DestinationRenewalFailure); got != 0 {
		t.Fatalf("other tenant notifications = %d", got)
	}
	var key string
	var body []byte
	if err := s.SystemPool().QueryRow(ctx, `SELECT idempotency_key, payload FROM outbox WHERE tenant_id=$1 AND destination=$2`, tenantA, notify.DestinationRenewalFailure).Scan(&key, &body); err != nil {
		t.Fatal(err)
	}
	var alert notify.Alert
	if err := json.Unmarshal(body, &alert); err != nil {
		t.Fatal(err)
	}
	if alert.Kind != notify.KindRenewalFailed || alert.TenantID != tenantA || alert.IdentityID != identityID || alert.OwnerID != "99999999-9999-9999-9999-999999999999" || alert.Subject != "svc.example.test" || alert.OperationID == "" || alert.Severity != notify.AlertSeverityWarning {
		t.Fatalf("failure alert lost its routing or receiver identity: %+v", alert)
	}
	if strings.Contains(string(body), "private upstream") || !strings.Contains(alert.Detail, "retry") {
		t.Fatalf("notification must carry safe next steps, not raw failure detail: %s", body)
	}
	if err := orch.Transition(ctx, tenantA, identityID, orchestrator.StateRenewalFailed, "repeat attempt"); err == nil {
		t.Fatal("a repeated failure must not create another transition/alert")
	}
	// Discard just the disposable test outbox row to simulate loss of the SQL
	// projection after the immutable failure event was retained.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id=$1 AND destination=$2`, tenantA, notify.DestinationRenewalFailure)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for pass, want := range []int{1, 0} {
		got, err := orch.ReconcileOutbox(ctx, log)
		if err != nil || got != want {
			t.Fatalf("reconcile pass %d healed=%d error=%v; want %d", pass, got, err, want)
		}
	}
	if replay := outboxPayload(t, ctx, s.SystemPool(), tenantA, key); string(replay) != string(body) {
		t.Fatal("recovery changed the retained alert")
	}
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type != projections.EventIdentityRenewalFailed {
			return nil
		}
		data, changed, err := events.PseudonymizeEventDataForSubject(event.Data, tenantA, "svc.example.test", event.Type, event.SchemaVersion)
		if err != nil || !changed {
			t.Fatalf("failure notification privacy rewrite: changed=%v error=%v", changed, err)
		}
		var retained struct {
			SideEffect replayableTransitionSideEffect `json:"side_effect"`
		}
		if err := json.Unmarshal(data, &retained); err != nil {
			t.Fatal(err)
		}
		var rewritten notify.Alert
		if err := json.Unmarshal(retained.SideEffect.Payload, &rewritten); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(retained.SideEffect.Payload), "svc.example.test") || rewritten.OperationID != alert.OperationID || rewritten.IdentityID != alert.IdentityID || rewritten.OwnerID != alert.OwnerID || retained.SideEffect.IdempotencyKey != key {
			t.Fatal("privacy rewrite retained the subject or changed the notification authority")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n := countOutboxDestination(t, s, tenantA, "connector.deploy") + countOutboxDestination(t, s, tenantA, "revocation.publish"); n != 0 {
		t.Fatal("recording failure must not deploy or revoke")
	}
}

func TestRenewalFailureNotificationSharesTheStateTransaction(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := t.Context()
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	const identityID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	seedLifecycleIdentity(t, s, tenantA, identityID, orchestrator.StateRenewing)
	// This failure injector exists only inside the package's temporary database.
	if _, err := s.SystemPool().Exec(ctx, `CREATE FUNCTION qa_reject_renewal_alert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.destination = 'notification.renewal_failure' THEN RAISE EXCEPTION 'injected alert enqueue failure'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER qa_reject_renewal_alert BEFORE INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION qa_reject_renewal_alert()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := s.SystemPool().Exec(ctx, `DROP TRIGGER IF EXISTS qa_reject_renewal_alert ON outbox; DROP FUNCTION IF EXISTS qa_reject_renewal_alert()`); err != nil {
			t.Error(err)
		}
	}()
	if err := orch.Transition(ctx, tenantA, identityID, orchestrator.StateRenewalFailed, "attempt failed"); err == nil {
		t.Fatal("transition succeeded despite rejected notification intent")
	}
	mustStatus(t, s, tenantA, identityID, "renewing")
	if got := countIdentityTransitions(t, s, tenantA, identityID, projections.EventIdentityRenewalFailed); got != 0 {
		t.Fatalf("state history committed without its alert: %d", got)
	}
	if got := countOutboxDestination(t, s, tenantA, notify.DestinationRenewalFailure); got != 0 {
		t.Fatalf("rejected intent survived rollback: %d", got)
	}
	if _, err := s.SystemPool().Exec(ctx, `DROP TRIGGER qa_reject_renewal_alert ON outbox`); err != nil {
		t.Fatal(err)
	}
	if err := orch.Transition(ctx, tenantA, identityID, orchestrator.StateRenewalFailed, "attempt failed"); err != nil {
		t.Fatal(err)
	}
	var failures int
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type == projections.EventIdentityRenewalFailed {
			failures++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if failures != 1 {
		t.Fatalf("retry after SQL rollback retained %d failure events, want one", failures)
	}
	if _, err := orch.ReconcileOutbox(ctx, log); err != nil {
		t.Fatal(err)
	}
	if got := countOutboxDestination(t, s, tenantA, notify.DestinationRenewalFailure); got != 1 {
		t.Fatalf("crash retry created %d alerts, want one", got)
	}
}

func TestRenewalFailureReplayDoesNotInventHistoricalAlerts(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	for _, version := range []int{1, projections.LifecycleEventSchemaVersion, projections.LifecycleSideEffectEventSchemaVersion} {
		_, err := log.Append(t.Context(), events.Event{Type: projections.EventIdentityRenewalFailed, TenantID: tenantA, SchemaVersion: version,
			Data: transitionEvent(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", orchestrator.StateRenewing, orchestrator.StateRenewalFailed)})
		if err != nil {
			t.Fatal(err)
		}
	}
	if got, err := orch.ReconcileOutbox(t.Context(), log); err != nil || got != 0 {
		t.Fatalf("old failure history invented work: healed=%d error=%v", got, err)
	}
}
