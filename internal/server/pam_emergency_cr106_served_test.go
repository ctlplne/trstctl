// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
)

// CR-106: old responder-list events can exist from before the author guard.
// Both emergency paths must check who named the responder when they are used.
func TestServedEmergencyRejectsHistoricallySelfNamedResponderCR106(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{})
	const subject = "oncall@ops.example"
	if err := f.h.srv.pam.appendProject(f.ctx, f.h.tenant, projections.EventPAMEmergencyRespondersSet,
		projections.PAMEmergencyRespondersSet{Subjects: []string{subject}, Actor: "ONCALL@OPS.EXAMPLE", At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.srv.pam.SetPAMEmergencyResponders(f.ctx, f.h.tenant, subject, []string{subject}); !errors.Is(err, api.ErrPAMRejected) {
		t.Fatalf("service accepted a self-authored replacement: %v", err)
	}
	_, err := f.h.srv.pam.OpenPAMEmergencySession(f.ctx, f.h.tenant, uuid.NewString(), subject, api.PAMSessionRequest{
		TargetType: "postgres", TargetID: "pg-gw", Role: "readonly", Reason: "incident", Method: "stub_pam", Payload: []byte("genuine"), TTLSeconds: 60,
	})
	if !errors.Is(err, api.ErrPAMRejected) || !strings.Contains(err.Error(), "named by another") {
		t.Fatalf("historically self-named responder opened a session: %v", err)
	}
	_, err = f.h.srv.pam.OpenPAMEmergencyCheckout(f.ctx, f.h.tenant, uuid.NewString(), subject, api.PAMCheckoutRequest{
		RequestID: uuid.NewString(), TargetType: "breakglass", TargetID: "idp-admin", Reason: "incident", TTLSeconds: 60,
	})
	if !errors.Is(err, api.ErrPAMRejected) || !strings.Contains(err.Error(), "named by another") {
		t.Fatalf("historically self-named responder released a credential: %v", err)
	}
}

// The replacement is an event and the notification intent is durable in
// PostgreSQL before the API reports success; responders can audit the actor.
func TestServedEmergencyResponderChangeQueuesApproverNoticeCR106(t *testing.T) {
	probe := &approvalNotificationProbe{}
	f := startGatewayFixture(t, gatewayFixtureOptions{notificationChannels: []notify.Notifier{probe}})
	admin := seedScopedTokenSubject(t, f.h.store, f.h.tenant, "responder-custodian", "access:write", "access:approve", "access:targets.write")
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPut, "/api/v1/access/emergency/responders", admin, uuid.NewString(),
		map[string]any{"subjects": []string{"oncall@ops.example"}})
	if status != http.StatusOK {
		t.Fatalf("replace responders = %d %s", status, body)
	}
	rows, err := f.h.srv.outbox.Pending(f.ctx, f.h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		if row.Destination != notify.DestinationApproval {
			continue
		}
		var alert notify.Alert
		if err := json.Unmarshal(row.Payload, &alert); err != nil {
			t.Fatal(err)
		}
		if alert.Kind == "access.emergency_responders_changed" && strings.Contains(alert.Detail, "responder-custodian") && strings.Contains(alert.Detail, "oncall@ops.example") {
			found = true
		}
	}
	if !found {
		t.Fatal("responder list changed without a durable approver notice naming actor and responder")
	}
	if err := f.h.srv.Drain(f.ctx); err != nil {
		t.Fatal(err)
	}
	count, delivered := probe.snapshot()
	if count != 1 || delivered.Kind != notify.KindEmergencyRespondersChanged || !strings.Contains(delivered.Detail, "oncall@ops.example") {
		t.Fatalf("approval channel delivery: count=%d alert=%+v", count, delivered)
	}
}
