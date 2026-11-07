// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
)

// TestSessionRiskAlertIsANotifyAlertWithItsRecordingA275: the alert an
// alerted command's projection queues is a notify.Alert of the session risk
// kind, keyed by the action, naming what ran (operation names only), where,
// by whom, at the rule's severity, with the console page of the session's
// recording; every channel's message carries the link.
func TestSessionRiskAlertIsANotifyAlertWithItsRecordingA275(t *testing.T) {
	session, connection := "66666666-6666-4666-8666-666666666666", "77777777-7777-4777-8777-777777777777"
	at := time.Date(2026, 11, 7, 20, 0, 0, 0, time.UTC)
	d := accessrules.Decision{ID: accessrules.ActionID(session, connection, 3, 1, 1), SessionID: session, JobID: 3, Attempt: 1, Protocol: "postgres",
		Observation: accessrules.Observation{ConnectionID: connection, Ordinal: 1, Phase: "query", Operations: []string{"GRANT"},
			RuleIDs: []string{"11111111-1111-4111-8111-111111111111"}, MessageDigest: strings.Repeat("a", 64)},
		PolicyDigest: strings.Repeat("b", 64), Status: accessrules.StatusAlerted, Reason: "matched_alert_rule", ObservedAt: at, DecidedAt: at}
	raw, key, err := projections.PAMCommandRiskAlert("22222222-2222-4222-8222-222222222222",
		projections.PAMCommandAlerted{Decision: d, TargetType: "postgres", TargetID: "orders-db", Subject: "alice@example.test", Severity: "critical"})
	if err != nil {
		t.Fatal(err)
	}
	var alert notify.Alert
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&alert); err != nil {
		t.Fatalf("the queued payload is not a notify.Alert: %v", err)
	}
	if key != "pam-command-alert:"+d.ID || alert.OperationID != key || alert.Kind != notify.KindSessionRiskAlert || alert.Severity != notify.AlertSeverityCritical ||
		alert.SessionID != session || alert.RecordingPath != "/admin/access?session="+session || alert.Subject != "postgres/orders-db" {
		t.Fatalf("the alert: %+v (key %s)", alert, key)
	}
	message := notify.FormatMessage(alert)
	for _, want := range []string{"Risky command in a privileged session", "alice@example.test", "GRANT", "/admin/access?session=" + session} {
		if !strings.Contains(message, want) {
			t.Fatalf("the channel message lacks %q: %s", want, message)
		}
	}
}
