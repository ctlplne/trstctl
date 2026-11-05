// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/api"
)

func TestServedClickHouseCommandRuleBlocksAndRecordsA262(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true, clickhouseNote: "a262-owned-clickhouse-note"})
	f.h.srv.pam.recordings = nil
	ruleID := uuid.NewString()
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a262-clickhouse-template", map[string]any{
		"name": "a262-clickhouse-block", "reason": "Reviewed maintenance", "required_approvals": 2, "max_ttl_seconds": 120,
		"command_rules": []map[string]any{{"id": ruleID, "name": "Refuse direct table truncation", "enabled": true, "protocol": "clickhouse", "operations": []string{"TRUNCATE"}, "effect": "block"}},
	})
	var template api.PAMAccessTemplate
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil || template.ID == "" {
		t.Fatalf("save ClickHouse enforcing template = %d %s", status, body)
	}
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a262-clickhouse-template-delete", nil)
		if status != http.StatusOK {
			t.Errorf("delete owned ClickHouse template = %d %s", status, body)
		}
	})
	session := f.open("a262-clickhouse-open", map[string]any{"target_type": "clickhouse", "target_id": "clickhouse-gw", "role": "reader", "ttl_seconds": 120, "template_id": template.ID})
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a262-clickhouse-revoke", map[string]any{"reason": "A262 fixture complete"})
		if status != http.StatusOK && status != http.StatusAccepted {
			t.Errorf("revoke owned ClickHouse = %d %s", status, body)
			return
		}
		a201Await(t, "owned ClickHouse session revoked before target stops", func() bool {
			ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
			defer cancel()
			_ = f.h.srv.Drain(ctx)
			row, err := f.h.store.GetPAMSession(ctx, f.h.tenant, session.ID)
			return err == nil && row.Status == "revoked"
		})
	})
	users := clickhouseSessionUsers(t, f.clickhouse)
	if len(users) != 1 {
		t.Fatal("missing exact owned ClickHouse account")
	}
	// Give the exact disposable login the real authority used by both the direct
	// statement and the equivalent-effect bypass. No other target is changed.
	if out := f.clickhouse.admin(t, "GRANT TRUNCATE, ALTER DELETE ON lab.notes TO `"+users[0]+"`"); out != "" {
		t.Fatalf("seed owned ClickHouse authority: %s", out)
	}
	tunnel, stop := f.connect(session.ID, session.Gateway.Ticket, fixtureClickHouseCommand.MatchString)
	defer stop()
	local := "http://127.0.0.1:" + fixtureClickHouseCommand.FindStringSubmatch(tunnel)[1] + "/"
	queryAt := func(suffix string, args ...string) (string, error) {
		cmd := exec.CommandContext(f.ctx, "curl", append([]string{"-sS", "--fail-with-body", local + suffix}, args...)...) // #nosec G204 G702 -- stock curl against this test's owned tunnel (CWE-78)
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	query := func(args ...string) (string, error) { return queryAt("", args...) }
	count := func(want string) {
		t.Helper()
		if out := f.clickhouse.admin(t, "SELECT count() FROM lab.notes WHERE id=1"); out != want {
			t.Fatalf("independent ClickHouse row readback = %s; want %s", out, want)
		}
	}
	count("1")
	for _, args := range [][]string{{"--data-binary", "TRUNCATE TABLE lab.notes"}, {"--data-binary", "/* direct */ tRuNcAtE TABLE lab.notes"}} {
		out, err := query(args...)
		if err == nil || !strings.Contains(out, "TRSTCTL_COMMAND_REFUSED") {
			t.Fatalf("ClickHouse truncation escaped guardrail: %v %s", err, out)
		}
		count("1")
	}
	if out, err := queryAt("?query=TRUNCATE", "--data-binary", "TABLE lab.notes"); err == nil || !strings.Contains(out, "TRSTCTL_COMMAND_REFUSED") {
		t.Fatalf("split URL/body truncation escaped guardrail: %v %s", err, out)
	}
	count("1")

	if out, err := query("--data-binary", "SELECT 'TRUNCATE a262-value-canary'"); err != nil || !strings.Contains(out, "TRUNCATE a262-value-canary") {
		t.Fatalf("quoted ClickHouse value became an operation: %v %s", err, out)
	}
	status, body = secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
	var page api.PAMCommandActionList
	if status != http.StatusOK || json.Unmarshal(body, &page) != nil || len(page.Items) != 3 {
		t.Fatalf("ClickHouse refusal evidence = %d %s", status, body)
	}
	for _, a := range page.Items {
		if a.Status != "blocked" || a.Protocol != "clickhouse" || len(a.RuleIDs) != 1 || a.RuleIDs[0] != ruleID || len(a.Operations) != 1 || a.Operations[0] != "TRUNCATE" {
			t.Fatalf("ClickHouse refusal lost binding: %+v", a)
		}
	}
	for _, value := range []string{"lab.notes", "a262-owned-clickhouse-note", "a262-value-canary", users[0], "a256-admin"} {
		if strings.Contains(string(body), value) {
			t.Fatalf("ClickHouse values or sign-in material entered policy evidence: %s", value)
		}
	}
	// A TRUNCATE-only selector is not containment of the table's contents: the
	// SAME account's ALTER DELETE authority can achieve the equivalent effect.
	if out, err := query("--data-binary", "ALTER TABLE lab.notes DELETE WHERE id=1 SETTINGS mutations_sync=1"); err != nil || out != "" {
		t.Fatalf("documented same-login alternative-verb bypass: %v %s", err, out)
	}
	count("0")
}

func TestServedClickHouseCommandReviewWaitsAndCancelsA262(t *testing.T) {
	for _, mode := range []string{"approve", "disconnect", "pipeline_disconnect", "capacity"} {
		t.Run(mode, func(t *testing.T) {
			f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true, clickhouseNote: "a262-review-owned-note"})
			f.h.srv.pam.recordings = nil
			status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a262-clickhouse-review-template-"+mode, map[string]any{
				"name": "a262-clickhouse-review-" + mode, "reason": "Reviewed maintenance", "required_approvals": 2, "max_ttl_seconds": 120,
				"command_rules": []map[string]any{{"id": uuid.NewString(), "name": "Review direct table truncation", "enabled": true, "protocol": "clickhouse", "operations": []string{"TRUNCATE"}, "effect": "require_approval", "required_approvals": 2, "review_ttl_seconds": 40}},
			})
			var template api.PAMAccessTemplate
			if status != http.StatusCreated || json.Unmarshal(body, &template) != nil {
				t.Fatalf("ClickHouse review template = %d %s", status, body)
			}
			t.Cleanup(func() {
				status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a262-clickhouse-review-delete-"+mode, nil)
				if status != http.StatusOK {
					t.Errorf("delete ClickHouse review template = %d %s", status, body)
				}
			})
			session := f.open("a262-clickhouse-review-open-"+mode, map[string]any{"target_type": "clickhouse", "target_id": "clickhouse-gw", "role": "reader", "ttl_seconds": 120, "template_id": template.ID})
			t.Cleanup(func() {
				status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a262-clickhouse-review-revoke-"+mode, map[string]any{"reason": "A262 fixture complete"})
				if status != http.StatusOK && status != http.StatusAccepted {
					t.Errorf("revoke ClickHouse review = %d %s", status, body)
					return
				}
				a201Await(t, "ClickHouse review revoked before target stops", func() bool {
					ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
					defer cancel()
					_ = f.h.srv.Drain(ctx)
					row, err := f.h.store.GetPAMSession(ctx, f.h.tenant, session.ID)
					return err == nil && row.Status == "revoked"
				})
			})
			users := clickhouseSessionUsers(t, f.clickhouse)
			if len(users) != 1 {
				t.Fatal("missing owned ClickHouse review account")
			}
			if out := f.clickhouse.admin(t, "GRANT TRUNCATE ON lab.notes TO `"+users[0]+"`"); out != "" {
				t.Fatalf("seed exact truncation authority: %s", out)
			}
			count := func(want string) {
				t.Helper()
				if out := f.clickhouse.admin(t, "SELECT count() FROM lab.notes WHERE id=1"); out != want {
					t.Fatalf("independent ClickHouse review readback = %s; want %s", out, want)
				}
			}
			tunnel, stop := f.connect(session.ID, session.Gateway.Ticket, fixtureClickHouseCommand.MatchString)
			defer stop()
			address := "127.0.0.1:" + fixtureClickHouseCommand.FindStringSubmatch(tunnel)[1]
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			done := make(chan error, 1)
			var peer net.Conn
			sql := "TRUNCATE TABLE lab.notes /* a262-clickhouse-value-canary */"
			if mode == "pipeline_disconnect" || mode == "capacity" {
				var err error
				peer, err = net.Dial("tcp", address)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = peer.Close() }()
				wire := "POST / HTTP/1.1\r\nHost: gateway\r\nContent-Length: " + strconv.Itoa(len(sql)) + "\r\n\r\n" + sql
				if mode == "pipeline_disconnect" {
					wire += "GET /?query=SELECT%201 HTTP/1.1\r\nHost: gateway\r\n\r\n"
				}
				if _, err := io.WriteString(peer, wire); err != nil {
					t.Fatal(err)
				}
				go func() {
					response, err := http.ReadResponse(bufio.NewReader(peer), nil)
					if response != nil {
						data, readErr := io.ReadAll(response.Body)
						_ = response.Body.Close()
						if mode == "capacity" && (response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(data), "TRSTCTL_COMMAND_CAPACITY_FULL")) {
							err = errors.New("capacity rejection lost its structured HTTP error")
						}
						if err == nil {
							err = readErr
						}
					}
					done <- err
				}()
			} else {
				request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+address+"/", strings.NewReader(sql))
				if err != nil {
					t.Fatal(err)
				}
				go func() {
					response, err := http.DefaultClient.Do(request)
					if response != nil {
						_, readErr := io.Copy(io.Discard, response.Body)
						_ = response.Body.Close()
						if err == nil {
							err = readErr
						}
						if response.StatusCode != http.StatusOK && err == nil {
							err = errors.New("reviewed ClickHouse request did not return target success")
						}
					}
					done <- err
				}()
			}
			var action api.PAMCommandAction
			a201Await(t, "ClickHouse statement visibly held", func() bool {
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
				t.Fatalf("ClickHouse request completed before review: %v", err)
			default:
			}
			var request api.ApprovalRequestRecord
			a201Await(t, "ClickHouse action in ordinary reviewer queue", func() bool {
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
			for _, private := range []string{"lab.notes", "a262-clickhouse-value-canary", users[0], "a256-admin"} {
				if strings.Contains(string(raw), private) {
					t.Fatal("ClickHouse values/sign-in material entered review")
				}
			}
			if mode == "capacity" {
				extra := strings.Repeat("GET /?query=SELECT%201 HTTP/1.1\r\nHost: gateway\r\n\r\n", 3)
				if _, err := io.WriteString(peer, extra); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(8 * time.Second):
					t.Fatal("full input capacity did not reject promptly")
				}
				count("1")
				a201Await(t, "overloaded held request canceled", func() bool {
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
				return
			}
			if mode != "approve" {
				if peer != nil {
					_ = peer.Close()
				} else {
					cancel()
				}
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("ClickHouse disconnect did not return")
				}
				a201Await(t, "held ClickHouse action canceled", func() bool {
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
				status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+request.ID+"/approvals", reviewer, "a262-clickhouse-vote-"+mode+strconv.Itoa(i), map[string]any{"intent_digest": request.IntentDigest})
				if mode == "approve" && status != http.StatusOK {
					t.Fatalf("ClickHouse review vote = %d %s", status, body)
				}
				if i == 0 || mode != "approve" {
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
					t.Fatal("approved ClickHouse request did not resume")
				}
				count("0")
			} else {
				count("1")
			}
		})
	}
}
