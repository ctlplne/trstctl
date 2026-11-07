// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/siem"
)

// a275SIEM is a local SIEM receiver: it keeps every event the SIEM channel
// posts to it.
type a275SIEM struct {
	srv    *httptest.Server
	mu     sync.Mutex
	events []a275SIEMEvent
}

type a275SIEMEvent struct {
	EventType string       `json:"event_type"`
	Message   string       `json:"message"`
	Severity  string       `json:"severity"`
	Alert     notify.Alert `json:"alert"`
}

func newA275SIEM(t *testing.T) *a275SIEM {
	s := &a275SIEM{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var e a275SIEMEvent
		if json.Unmarshal(raw, &e) == nil {
			s.mu.Lock()
			s.events = append(s.events, e)
			s.mu.Unlock()
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *a275SIEM) channel() notify.Notifier {
	return siem.New(s.srv.URL+"/events", []byte("a275-siem-token"), siem.WithHTTPClient(s.srv.Client()))
}

func (s *a275SIEM) sessionRisk() []a275SIEMEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []a275SIEMEvent
	for _, e := range s.events {
		if e.EventType == notify.KindSessionRiskAlert {
			out = append(out, e)
		}
	}
	return out
}

// TestServedGatewayCommandAlertRaisesOneAlertWithTheRecordingA275: an access
// template's alert rule lets a matching PostgreSQL statement run through the
// gateway once its decision is durable, and raises exactly one risk alert
// through the deployment's SIEM channel, naming the operation (never the
// statement), the target, the person and the rule's severity, with the
// console page of the session's recording; the recording marks the alerted
// action. A benign statement raises nothing.
func TestServedGatewayCommandAlertRaisesOneAlertWithTheRecordingA275(t *testing.T) {
	receiver := newA275SIEM(t)
	f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true, notificationChannels: []notify.Notifier{receiver.channel()}})
	ruleID := uuid.NewString()
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a275-bad-template", map[string]any{
		"name": "a275-bad", "reason": "Production maintenance", "required_approvals": 2, "max_ttl_seconds": 60,
		"command_rules": []map[string]any{{"id": uuid.NewString(), "name": "No severity", "enabled": true, "protocol": "postgres", "operations": []string{"GRANT"}, "effect": "alert"}},
	}); status == http.StatusCreated {
		t.Fatalf("an alert rule without a severity was saved: %s", body)
	}
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a275-alert-template", map[string]any{
		"name": "a275-alert-privilege-changes", "reason": "Production maintenance", "required_approvals": 2, "max_ttl_seconds": 60,
		"command_rules": []map[string]any{{"id": ruleID, "name": "Alert on privilege changes", "enabled": true, "protocol": "postgres",
			"operations": []string{"GRANT", "REVOKE"}, "effect": "alert", "severity": "critical"}},
	})
	var template struct {
		ID           string           `json:"id"`
		CommandRules []map[string]any `json:"command_rules"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil || template.ID == "" || len(template.CommandRules) != 1 ||
		template.CommandRules[0]["severity"] != "critical" || template.CommandRules[0]["effect"] != "alert" {
		t.Fatalf("save the alerting template = %d %s", status, body)
	}
	t.Cleanup(func() {
		_, _ = secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a275-alert-template-cleanup", nil)
	})
	session := f.open("a275-alert-open", map[string]any{"target_type": "postgres", "target_id": "pg-gw", "role": "readonly", "ttl_seconds": 60, "template_id": template.ID})
	t.Cleanup(func() {
		_, _ = secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a275-alert-session-cleanup", map[string]any{"reason": "A275 fixture complete"})
		a201Await(t, "the alerting session is revoked before target shutdown", func() bool {
			work, cancel := context.WithTimeout(f.ctx, 20*time.Second)
			defer cancel()
			_ = f.h.srv.Drain(work)
			return f.sessionRead(session.ID)["status"] == "revoked"
		})
	})
	local, stop := f.postgresTunnel(session)
	defer stop()
	conn, err := pgconn.Connect(f.ctx, "postgres://uncredentialed-client@"+local+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	query := func(sql string) error { _, err := conn.Exec(f.ctx, sql).ReadAll(); return err }
	actions := func() []map[string]any {
		t.Helper()
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
		var page struct {
			Items []map[string]any `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			t.Fatalf("session actions = %d %s", status, body)
		}
		return page.Items
	}
	drain := func() {
		t.Helper()
		work, cancel := context.WithTimeout(f.ctx, 30*time.Second)
		defer cancel()
		if err := f.h.srv.Drain(work); err != nil {
			t.Fatalf("drain: %v", err)
		}
	}

	// A benign session's statements raise nothing.
	const canary = "a275-statement-text-must-not-reach-the-alert"
	if err := query("CREATE TEMP TABLE a275_ledger(value text); INSERT INTO a275_ledger VALUES('" + canary + "'); SELECT count(*) FROM a275_ledger"); err != nil {
		t.Fatalf("benign statements: %v", err)
	}
	drain()
	if got := receiver.sessionRisk(); len(got) != 0 || len(actions()) != 0 {
		t.Fatalf("benign statements raised %d alerts and %d actions", len(got), len(actions()))
	}

	// The risky statement runs — the alert rule does not refuse it — and
	// raises one alert.
	if err := query("GRANT SELECT ON a275_ledger TO PUBLIC /* " + canary + " */"); err != nil {
		t.Fatalf("an alerted statement was refused: %v", err)
	}
	r := conn.ExecParams(f.ctx, "SELECT has_table_privilege('public', 'a275_ledger', 'SELECT')::text", nil, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
		t.Fatalf("the alerted GRANT did not take effect at the target: %v %v", r.Rows, r.Err)
	}
	got := actions()
	if len(got) != 1 || got[0]["status"] != "alerted" || got[0]["effective_status"] != "alerted" || got[0]["reason"] != "matched_alert_rule" {
		t.Fatalf("the alerted action = %+v", got)
	}
	actionID, _ := got[0]["id"].(string)
	drain()
	var alerts []a275SIEMEvent
	a201Await(t, "the risk alert reaches the SIEM", func() bool { alerts = receiver.sessionRisk(); return len(alerts) > 0 })
	drain()
	if alerts = receiver.sessionRisk(); len(alerts) != 1 {
		t.Fatalf("one risky statement raised %d alerts", len(alerts))
	}
	a := alerts[0]
	wantPath := "/admin/access?session=" + session.ID
	if a.Severity != "critical" || a.Alert.SessionID != session.ID || a.Alert.RecordingPath != wantPath || a.Alert.Subject != "postgres/pg-gw" ||
		a.Alert.OperationID != "pam-command-alert:"+actionID || !strings.Contains(a.Message, "GRANT") || !strings.Contains(a.Message, wantPath) ||
		!strings.Contains(a.Message, session.Subject) || !strings.Contains(a.Message, ruleID) {
		t.Fatalf("the alert = %+v", a)
	}
	raw, _ := json.Marshal(a)
	for _, forbidden := range []string{canary, "a275_ledger", "uncredentialed-client"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("statement content reached the alert: %s", forbidden)
		}
	}
	var outboxStatus string
	if err := f.h.store.SystemPool().QueryRow(f.ctx, `SELECT status FROM outbox WHERE tenant_id = $1 AND destination = $2 AND idempotency_key = $3`,
		f.h.tenant, notify.DestinationRisk, "pam-command-alert:"+actionID).Scan(&outboxStatus); err != nil || outboxStatus != "delivered" {
		t.Fatalf("the alert's outbox entry = %q %v", outboxStatus, err)
	}

	// The recording the alert links marks the alerted action.
	status, body = secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording/frames?wait=5", f.auditor, nil)
	var frames struct {
		Frames []json.RawMessage `json:"frames"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &frames) != nil {
		t.Fatalf("read the recording = %d %s", status, body)
	}
	marked := false
	for _, raw := range frames.Frames {
		var fr struct {
			Event string `json:"e"`
			Kind  string `json:"kind"`
			Text  string `json:"v"`
		}
		if json.Unmarshal(raw, &fr) == nil && fr.Event == "policy" && fr.Kind == "alerted" && fr.Text == actionID {
			marked = true
		}
	}
	if !marked {
		t.Fatalf("the recording does not mark the alerted action %s (%d frames)", actionID, len(frames.Frames))
	}
}

// TestServedRiskCategoriesAlertAndBlockA275: a template's rules name risk
// categories the gateway reads from the statement or command itself. Over
// PostgreSQL a credential read and an audit-setting change are alerted
// (allowed to run, one critical alert each) and a DELETE without WHERE is
// blocked with the rows unchanged, while a scoped DELETE and a string that
// mentions the catalogs pass with no action; over SSH a read of
// /etc/shadow is alerted and a recursive removal is blocked, while a plain
// removal passes. No table, path or argument reaches an action or an alert.
func TestServedRiskCategoriesAlertAndBlockA275(t *testing.T) {
	receiver := newA275SIEM(t)
	f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true, notificationChannels: []notify.Notifier{receiver.channel()}})
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a275-risk-template", map[string]any{
		"name": "a275-risk-categories", "reason": "Production maintenance", "required_approvals": 2, "max_ttl_seconds": 60,
		"command_rules": []map[string]any{
			{"id": uuid.NewString(), "name": "Alert on credential reads and audit changes", "enabled": true, "protocol": "postgres",
				"operations": []string{"CREDENTIAL_READ", "AUDIT_TAMPERING"}, "effect": "alert", "severity": "critical"},
			{"id": uuid.NewString(), "name": "Refuse bulk deletes", "enabled": true, "protocol": "postgres", "operations": []string{"BULK_DELETE"}, "effect": "block"},
			{"id": uuid.NewString(), "name": "Alert on credential reads", "enabled": true, "protocol": "ssh", "operations": []string{"credential_read"}, "effect": "alert", "severity": "warning"},
			{"id": uuid.NewString(), "name": "Refuse recursive removal", "enabled": true, "protocol": "ssh", "operations": []string{"bulk_delete"}, "effect": "block"},
		},
	})
	var template struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil || template.ID == "" {
		t.Fatalf("save the risk template = %d %s", status, body)
	}
	t.Cleanup(func() {
		_, _ = secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a275-risk-template-cleanup", nil)
	})
	revoke := func(id, key string) {
		_, _ = secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+id+"/revoke", f.requester, key, map[string]any{"reason": "A275 fixture complete"})
		a201Await(t, "the session is revoked before target shutdown", func() bool {
			work, cancel := context.WithTimeout(f.ctx, 20*time.Second)
			defer cancel()
			_ = f.h.srv.Drain(work)
			return f.sessionRead(id)["status"] == "revoked"
		})
	}
	actions := func(id string) []map[string]any {
		t.Helper()
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+id+"/actions", f.requester, nil)
		var page struct {
			Items []map[string]any `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			t.Fatalf("session actions = %d %s", status, body)
		}
		for _, forbidden := range []string{"pg_authid", "a275_risk", "log_statement", "/etc/shadow", "/tmp/a275"} {
			if strings.Contains(string(body), forbidden) {
				t.Fatalf("command content reached the actions: %s", forbidden)
			}
		}
		return page.Items
	}
	statuses := func(items []map[string]any) map[string]int {
		out := map[string]int{}
		for _, a := range items {
			s, _ := a["status"].(string)
			ops, _ := a["operations"].([]any)
			for _, op := range ops {
				out[s+":"+op.(string)]++
			}
		}
		return out
	}

	// PostgreSQL.
	pgSession := f.open("a275-risk-pg-open", map[string]any{"target_type": "postgres", "target_id": "pg-gw", "role": "readonly", "ttl_seconds": 60, "template_id": template.ID})
	t.Cleanup(func() { revoke(pgSession.ID, "a275-risk-pg-cleanup") })
	local, stop := f.postgresTunnel(pgSession)
	defer stop()
	conn, err := pgconn.Connect(f.ctx, "postgres://uncredentialed-client@"+local+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	query := func(sql string) error { _, err := conn.Exec(f.ctx, sql).ReadAll(); return err }
	count := func(want string) {
		t.Helper()
		r := conn.ExecParams(f.ctx, "SELECT count(*) FROM a275_risk", nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != want {
			t.Fatalf("rows = %v %v, want %s", r.Rows, r.Err, want)
		}
	}
	if err := query("CREATE TEMP TABLE a275_risk(value text); INSERT INTO a275_risk VALUES ('a'), ('b')"); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{"DELETE FROM a275_risk WHERE value = 'a'", "SELECT 'GRANT ALL ON pg_authid TO PUBLIC' AS note"} {
		if err := query(sql); err != nil {
			t.Fatalf("an ordinary statement %q: %v", sql, err)
		}
	}
	count("1")
	if got := actions(pgSession.ID); len(got) != 0 {
		t.Fatalf("ordinary statements recorded actions: %+v", got)
	}
	// Alerted: they reach the database, which refuses this login (an error
	// from PostgreSQL, not the gateway's policy marker).
	for _, sql := range []string{"SELECT rolname, rolpassword FROM pg_authid", "SET log_statement = 'none'"} {
		if err := query(sql); err != nil && strings.Contains(err.Error(), "TRSTCTL") {
			t.Fatalf("an alerted statement %q was refused by policy: %v", sql, err)
		}
	}
	if err := query("DELETE FROM a275_risk"); err == nil || !strings.Contains(err.Error(), "TRSTCTL") {
		t.Fatalf("a bulk delete was not refused by policy: %v", err)
	}
	count("1")
	if got := statuses(actions(pgSession.ID)); got["alerted:CREDENTIAL_READ"] != 1 || got["alerted:AUDIT_TAMPERING"] != 1 || got["blocked:BULK_DELETE"] != 1 || len(got) != 3 {
		t.Fatalf("PostgreSQL actions = %v", got)
	}

	// SSH.
	sshSession := f.open("a275-risk-ssh-open", map[string]any{"target_type": "ssh", "target_id": "ssh-gw", "role": "user", "ssh_principal": "alice", "ttl_seconds": 60, "template_id": template.ID})
	t.Cleanup(func() { revoke(sshSession.ID, "a275-risk-ssh-cleanup") })
	command, stopSSH := f.sshTunnel(sshSession)
	defer stopSSH()
	dir, file := "/tmp/a275-dir-"+uuid.NewString(), "/tmp/a275-file-"+uuid.NewString()
	if out, err := command("mkdir", "-p", dir+"/inner").CombinedOutput(); err != nil {
		t.Fatalf("mkdir: %v %s", err, out)
	}
	if out, err := command("touch", file).CombinedOutput(); err != nil {
		t.Fatalf("touch: %v %s", err, out)
	}
	if out, err := command("rm", file).CombinedOutput(); err != nil {
		t.Fatalf("a plain removal was refused: %v %s", err, out)
	}
	// Alerted: cat runs on the host, which refuses this login the file.
	out, _ := command("cat", "/etc/shadow").CombinedOutput()
	if strings.Contains(string(out), "TRSTCTL") {
		t.Fatalf("an alerted command was refused by policy: %s", out)
	}
	if out, err := command("rm", "-rf", dir).CombinedOutput(); err == nil {
		t.Fatalf("a recursive removal escaped the rule: %s", out)
	}
	if out, err := command("test", "-d", dir+"/inner").CombinedOutput(); err != nil {
		t.Fatalf("the blocked removal changed the host: %v %s", err, out)
	}
	if got := statuses(actions(sshSession.ID)); got["alerted:credential_read"] != 1 || got["blocked:bulk_delete"] != 1 || len(got) != 2 {
		t.Fatalf("SSH actions = %v", got)
	}

	// Three alerts: two critical from PostgreSQL, one warning from SSH; none
	// names a table, path or argument.
	work, cancel := context.WithTimeout(f.ctx, 30*time.Second)
	defer cancel()
	_ = f.h.srv.Drain(work)
	var alerts []a275SIEMEvent
	a201Await(t, "the three risk alerts reach the SIEM", func() bool { alerts = receiver.sessionRisk(); return len(alerts) >= 3 })
	_ = f.h.srv.Drain(work)
	if alerts = receiver.sessionRisk(); len(alerts) != 3 {
		t.Fatalf("%d alerts, want 3", len(alerts))
	}
	severities := map[string]int{}
	for _, a := range alerts {
		severities[a.Severity]++
		raw, _ := json.Marshal(a)
		for _, forbidden := range []string{"pg_authid", "a275_risk", "log_statement", "/etc/shadow", "/tmp/a275"} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatalf("command content reached an alert: %s in %s", forbidden, raw)
			}
		}
	}
	if severities["critical"] != 2 || severities["warning"] != 1 {
		t.Fatalf("alert severities = %v", severities)
	}
}
