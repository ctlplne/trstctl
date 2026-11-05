// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/mysqlsignin"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/api"
)

func TestServedMySQLCommandRuleBlocksAndRecordsA262(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true, mysqlNote: "a262-owned-mysql-note"})
	f.h.srv.pam.recordings = nil
	ruleID := uuid.NewString()
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a262-mysql-block-template", map[string]any{
		"name": "a262-mysql-block", "reason": "Reviewed maintenance", "required_approvals": 2, "max_ttl_seconds": 120,
		"command_rules": []map[string]any{{"id": ruleID, "name": "Refuse direct row deletion", "enabled": true, "protocol": "mysql", "operations": []string{"DELETE"}, "effect": "block"}},
	})
	var template api.PAMAccessTemplate
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil || template.ID == "" {
		t.Fatalf("save MySQL enforcing template = %d %s", status, body)
	}
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a262-mysql-clean-template", nil)
		if status != http.StatusOK {
			t.Errorf("delete owned MySQL template = %d %s", status, body)
		}
	})
	session := f.open("a262-mysql-block-open", map[string]any{"target_type": "mysql", "target_id": "mysql-gw", "role": "mysql-reader", "ttl_seconds": 120, "template_id": template.ID})
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a262-mysql-clean-session", map[string]any{"reason": "A262 fixture complete"})
		if status != http.StatusOK && status != http.StatusAccepted {
			t.Errorf("revoke owned MySQL session = %d %s", status, body)
			return
		}
		a201Await(t, "owned MySQL rule session revoked before target shutdown", func() bool {
			ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
			defer cancel()
			_ = f.h.srv.Drain(ctx)
			row, err := f.h.store.GetPAMSession(ctx, f.h.tenant, session.ID)
			return err == nil && row.Status == "revoked"
		})
	})
	accounts := mysqlSessionAccounts(t, f.mysqlID)
	if len(accounts) != 1 {
		t.Fatalf("expected one exact owned MySQL account: %v", accounts)
	}
	// Fixture authority: this exact session account can delete the owned row.
	// The same login's INVOKER procedure below proves its permission independently.
	setup := "GRANT DELETE ON app.notes TO '" + accounts[0] + "'@'%'; CREATE PROCEDURE app.a262_delete_guardrail() SQL SECURITY INVOKER DELETE FROM app.notes WHERE id=1; GRANT EXECUTE ON PROCEDURE app.a262_delete_guardrail TO '" + accounts[0] + "'@'%';"
	if out, err := a201Exec(f.mysqlID, "env", "MYSQL_PWD=a256-admin", "mysql", "--protocol=TCP", "-h", "127.0.0.1", "-uroot", "-e", setup); err != nil {
		t.Fatalf("seed exact owned authority: %v %s", err, out)
	}
	tunnel, stop := f.connect(session.ID, session.Gateway.Ticket, fixtureMySQLCommand.MatchString)
	defer stop()
	port := fixtureMySQLCommand.FindStringSubmatch(tunnel)[1]
	query := func(sql string) (string, error) {
		cmd := exec.CommandContext(f.ctx, "docker", "exec", f.mysqlID, "mysql", "-h", "host.docker.internal", "-P", port, "-u", "anyone", "-N", "-e", sql) // #nosec G204 G702 -- stock client against this test's owned tunnel (CWE-78)
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	count := func(want string) {
		t.Helper()
		out, err := a201Exec(f.mysqlID, "env", "MYSQL_PWD=a256-admin", "mysql", "--protocol=TCP", "-h", "127.0.0.1", "-uroot", "-N", "-e", "SELECT COUNT(*) FROM app.notes WHERE id=1")
		if err != nil || strings.TrimSpace(string(out)) != want {
			t.Fatalf("independent MySQL row readback = %v %s; want %s", err, out, want)
		}
	}
	count("1")
	for _, sql := range []string{"DELETE FROM app.notes WHERE id=1", "/* direct */ dElEtE FROM app.notes WHERE id=1", "/*!80000 DELETE FROM app.notes WHERE id=1 */"} {
		out, err := query(sql)
		if err == nil || !strings.Contains(out, "trstctl_command_refused") {
			t.Fatalf("direct MySQL deletion escaped guardrail: %v %s", err, out)
		}
		count("1")
	}
	if out, err := query("SELECT 'DELETE a262-argument-canary'"); err != nil || !strings.Contains(out, "DELETE a262-argument-canary") {
		t.Fatalf("quoted MySQL value became an operation: %v %s", err, out)
	}
	status, body = secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
	var page api.PAMCommandActionList
	if status != http.StatusOK || json.Unmarshal(body, &page) != nil || len(page.Items) != 3 {
		t.Fatalf("MySQL source evidence = %d %s", status, body)
	}
	for _, a := range page.Items {
		if a.Status != "blocked" || a.Protocol != "mysql" || len(a.RuleIDs) != 1 || a.RuleIDs[0] != ruleID || len(a.Operations) != 1 || a.Operations[0] != "DELETE" {
			t.Fatalf("MySQL occurrence lost its public binding: %+v", a)
		}
	}
	for _, value := range []string{"app.notes", "a262-owned-mysql-note", "a262-argument-canary", accounts[0], "a256-admin"} {
		if strings.Contains(string(body), value) {
			t.Fatalf("traffic or sign-in material entered MySQL source evidence: %s", value)
		}
	}
	wire := mysqlGatewayClient(t, "127.0.0.1:"+port)
	defer func() { _ = wire.Close() }()
	for _, payload := range [][]byte{append([]byte{0x16}, []byte("DELETE FROM app.notes WHERE id=1")...), {0x17, 1, 0, 0, 0, 0, 1, 0, 0, 0}} {
		if err := mysqlsignin.WritePacket(wire, 0, payload); err != nil {
			t.Fatal(err)
		}
		_, reply, err := mysqlsignin.ReadPacket(wire)
		if err != nil || len(reply) == 0 || reply[0] != 0xff || !strings.Contains(string(reply), "trstctl_command_refused") {
			t.Fatalf("opaque execution control escaped: %v %s", err, reply)
		}
		count("1")
	}

	status, body = secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
	if status != http.StatusOK || json.Unmarshal(body, &page) != nil || len(page.Items) != 5 {
		t.Fatalf("opaque controls lost source refusal = %d %s", status, body)
	}
	controls := 0
	for _, a := range page.Items {
		if a.Phase == "control" {
			if a.Status != "blocked" || a.Reason != "unsupported_control" || len(a.Operations) != 0 {
				t.Fatal("opaque control gained operation facts or authority")
			}
			controls++
		}
	}
	if controls != 2 {
		t.Fatalf("recorded control refusals = %d; want 2", controls)
	}

	// Stored program bodies are a documented lexical bypass, using this SAME login.
	if out, err := query("CALL app.a262_delete_guardrail()"); err != nil {
		t.Fatalf("same-login stored-program bypass: %v %s", err, out)
	}
	count("0")
}

func TestServedMySQLCommandReviewWaitsAndCancelsA262(t *testing.T) {
	for _, mode := range []string{"approve", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true, mysqlNote: "a262-review-owned-note"})
			f.h.srv.pam.recordings = nil
			status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a262-mysql-review-template-"+mode, map[string]any{
				"name": "a262-mysql-review-" + mode, "reason": "Reviewed maintenance", "required_approvals": 2, "max_ttl_seconds": 120,
				"command_rules": []map[string]any{{"id": uuid.NewString(), "name": "Review direct row deletion", "enabled": true, "protocol": "mysql", "operations": []string{"DELETE"}, "effect": "require_approval", "required_approvals": 2, "review_ttl_seconds": 40}},
			})
			var template api.PAMAccessTemplate
			if status != http.StatusCreated || json.Unmarshal(body, &template) != nil {
				t.Fatalf("MySQL review template = %d %s", status, body)
			}
			t.Cleanup(func() {
				status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a262-mysql-review-delete-"+mode, nil)
				if status != http.StatusOK {
					t.Errorf("delete owned MySQL review template = %d %s", status, body)
				}
			})
			session := f.open("a262-mysql-review-open-"+mode, map[string]any{"target_type": "mysql", "target_id": "mysql-gw", "role": "mysql-reader", "ttl_seconds": 120, "template_id": template.ID})
			t.Cleanup(func() {
				status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a262-mysql-review-revoke-"+mode, map[string]any{"reason": "A262 fixture complete"})
				if status != http.StatusOK && status != http.StatusAccepted {
					t.Errorf("revoke MySQL review = %d %s", status, body)
					return
				}
				a201Await(t, "MySQL review revoked before target shutdown", func() bool {
					ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
					defer cancel()
					_ = f.h.srv.Drain(ctx)
					row, err := f.h.store.GetPAMSession(ctx, f.h.tenant, session.ID)
					return err == nil && row.Status == "revoked"
				})
			})
			accounts := mysqlSessionAccounts(t, f.mysqlID)
			if len(accounts) != 1 {
				t.Fatal("owned session account missing")
			}
			if out, err := a201Exec(f.mysqlID, "env", "MYSQL_PWD=a256-admin", "mysql", "--protocol=TCP", "-h", "127.0.0.1", "-uroot", "-e", "GRANT DELETE ON app.notes TO '"+accounts[0]+"'@'%'"); err != nil {
				t.Fatalf("grant owned row deletion: %v %s", err, out)
			}
			count := func(want string) {
				t.Helper()
				out, err := a201Exec(f.mysqlID, "env", "MYSQL_PWD=a256-admin", "mysql", "--protocol=TCP", "-h", "127.0.0.1", "-uroot", "-N", "-e", "SELECT COUNT(*) FROM app.notes WHERE id=1")
				if err != nil || strings.TrimSpace(string(out)) != want {
					t.Fatalf("independent review target read = %v %s; want %s", err, out, want)
				}
			}
			tunnel, stop := f.connect(session.ID, session.Gateway.Ticket, fixtureMySQLCommand.MatchString)
			defer stop()
			port := fixtureMySQLCommand.FindStringSubmatch(tunnel)[1]
			conn := mysqlGatewayClient(t, "127.0.0.1:"+port)
			defer func() { _ = conn.Close() }()
			if err := mysqlsignin.WritePacket(conn, 0, append([]byte{3}, []byte("DELETE FROM app.notes WHERE id=1 /* a262-mysql-review-argument */")...)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				_, p, err := mysqlsignin.ReadPacket(conn)
				if err == nil && (len(p) == 0 || p[0] != 0) {
					err = errors.New("reviewed MySQL command did not return target OK")
				}
				done <- err
			}()
			var action api.PAMCommandAction
			a201Await(t, "MySQL statement is durably held", func() bool {
				status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
				var page api.PAMCommandActionList
				if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
					return false
				}
				for _, a := range page.Items {
					if a.Status == "pending" {
						action = a
						return true
					}
				}
				return false
			})
			count("1")
			select {
			case err := <-done:
				t.Fatalf("MySQL command completed before review: %v", err)
			default:
			}
			var request api.ApprovalRequestRecord
			a201Await(t, "MySQL command in normal approval queue", func() bool {
				status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/approval-requests?status=pending", f.reviewerOne, nil)
				var page struct {
					Items []api.ApprovalRequestRecord `json:"items"`
				}
				if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
					return false
				}
				for _, r := range page.Items {
					if r.ResourceKind == "pam_command" && r.ResourceID == "pam-command:"+action.ID {
						request = r
						return true
					}
				}
				return false
			})
			raw, _ := json.Marshal(request)
			for _, private := range []string{"app.notes", "a262-mysql-review-argument", accounts[0], "a256-admin"} {
				if strings.Contains(string(raw), private) {
					t.Fatalf("MySQL values entered review: %s", private)
				}
			}
			if mode == "disconnect" {
				_ = conn.Close()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("MySQL disconnect did not end client")
				}
				a201Await(t, "MySQL held occurrence canceled on disconnect", func() bool {
					status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
					var page api.PAMCommandActionList
					if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
						return false
					}
					for _, a := range page.Items {
						if a.ID == action.ID {
							return a.Status == "canceled"
						}
					}
					return false
				})
			}
			for i, reviewer := range []string{f.reviewerOne, f.reviewerTwo} {
				status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+request.ID+"/approvals", reviewer, "a262-mysql-vote-"+mode+strconv.Itoa(i), map[string]any{"intent_digest": request.IntentDigest})
				if mode == "approve" && status != http.StatusOK {
					t.Fatalf("MySQL review vote = %d %s", status, body)
				}
				if i == 0 || mode == "disconnect" {
					count("1")
				}
			}
			if mode == "approve" {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("approved MySQL command did not resume")
				}
				count("0")
			} else {
				count("1")
			}
		})
	}
}
