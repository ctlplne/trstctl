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

func TestServedRedisCommandRuleBlocksAndRecordsA262(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true, redis: true})
	f.h.srv.pam.recordings = nil
	ruleID := uuid.NewString()
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a262-redis-template", map[string]any{
		"name": "a262-redis-block", "reason": "Reviewed maintenance", "required_approvals": 2, "max_ttl_seconds": 120,
		"command_rules": []map[string]any{{"id": ruleID, "name": "Refuse direct key deletion", "enabled": true, "protocol": "redis", "operations": []string{"DEL"}, "effect": "block"}},
	})
	var template api.PAMAccessTemplate
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil || template.ID == "" {
		t.Fatalf("save Redis enforcing template = %d %s", status, body)
	}
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a262-redis-template-delete", nil)
		if status != http.StatusOK {
			t.Errorf("delete owned Redis template = %d %s", status, body)
		}
	})
	session := f.open("a262-redis-open", map[string]any{"target_type": "redis", "target_id": "redis-gw", "role": "redis-writer", "ttl_seconds": 120, "template_id": template.ID})
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a262-redis-revoke", map[string]any{"reason": "A262 fixture complete"})
		if status != http.StatusOK && status != http.StatusAccepted {
			t.Errorf("revoke owned Redis = %d %s", status, body)
			return
		}
		a201Await(t, "owned Redis rule session revoked before target shutdown", func() bool {
			ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
			defer cancel()
			_ = f.h.srv.Drain(ctx)
			row, err := f.h.store.GetPAMSession(ctx, f.h.tenant, session.ID)
			return err == nil && row.Status == "revoked"
		})
	})
	tunnel, stop := f.connect(session.ID, session.Gateway.Ticket, fixtureRedisCommand.MatchString)
	defer stop()
	port := fixtureRedisCommand.FindStringSubmatch(tunnel)[1]
	query := func(args ...string) (string, error) {
		cmd := exec.CommandContext(f.ctx, "docker", append([]string{"exec", f.redisID, "redis-cli", "--raw", "-h", "host.docker.internal", "-p", port}, args...)...) // #nosec G204 G702 -- stock Redis client against this test's owned tunnel (CWE-78)
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	key := "a256:a262-owned-" + uuid.NewString()
	if out, err := query("SET", key, "a262-redis-value-canary"); err != nil || out != "OK" {
		t.Fatalf("set owned Redis key: %v %s", err, out)
	}
	exists := func(want string) {
		t.Helper()
		out, err := a201Exec(f.redisID, "redis-cli", "--no-auth-warning", "-a", "a256-admin", "EXISTS", key)
		if err != nil || strings.TrimSpace(out) != want {
			t.Fatalf("independent Redis key readback = %v %s; want %s", err, out, want)
		}
	}
	exists("1")
	for _, verb := range []string{"DEL", "dEl"} {
		out, err := query(verb, key)
		if err != nil || !strings.Contains(out, "TRSTCTL-GATEWAY-REFUSED-") {
			t.Fatalf("Redis key deletion escaped guardrail: %v %s", err, out)
		}
		exists("1")
	}
	status, body = secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
	var page api.PAMCommandActionList
	if status != http.StatusOK || json.Unmarshal(body, &page) != nil || len(page.Items) != 2 {
		t.Fatalf("Redis refusal evidence = %d %s", status, body)
	}
	for _, a := range page.Items {
		if a.Status != "blocked" || a.Protocol != "redis" || len(a.RuleIDs) != 1 || a.RuleIDs[0] != ruleID || len(a.Operations) != 1 || a.Operations[0] != "DEL" {
			t.Fatalf("Redis public refusal lost binding: %+v", a)
		}
	}
	users := redisSessionUsers(t, f.redisID)
	if len(users) != 1 {
		t.Fatal("missing exact owned Redis user")
	}
	for _, value := range []string{key, "a262-redis-value-canary", users[0], "a256-admin"} {
		if strings.Contains(string(body), value) {
			t.Fatalf("Redis value or sign-in material reached rule evidence: %s", value)
		}
	}
	// A pipeline's refusal stays between its two real read responses.
	encode := func(args ...string) string {
		var b strings.Builder
		b.WriteString("*" + strconv.Itoa(len(args)) + "\r\n")
		for _, arg := range args {
			b.WriteString("$" + strconv.Itoa(len(arg)) + "\r\n" + arg + "\r\n")
		}
		return b.String()
	}
	pipeline, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pipeline.Close() }()
	_ = pipeline.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(pipeline, encode("GET", key)+encode("DEL", key)+encode("GET", key)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(pipeline)
	readValue := func() {
		t.Helper()
		head, err := reader.ReadString('\n')
		if err != nil || head != "$23\r\n" {
			t.Fatalf("ordered Redis bulk header = %q %v", head, err)
		}
		value := make([]byte, 25)
		if _, err := io.ReadFull(reader, value); err != nil || string(value) != "a262-redis-value-canary\r\n" {
			t.Fatalf("ordered Redis value = %q %v", value, err)
		}
	}
	readValue()
	refusal, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(refusal, "TRSTCTL-GATEWAY-REFUSED-") {
		t.Fatalf("pipeline middle refusal = %q %v", refusal, err)
	}
	readValue()
	exists("1")
	_ = pipeline.Close()
	// Refusing MULTI ends the stream before later pipelined commands can run
	// with surprising immediate-execution semantics outside a transaction.
	tx, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	_ = tx.SetDeadline(time.Now().Add(10 * time.Second))
	hiddenKey := key + ":transaction"
	if _, err := io.WriteString(tx, encode("MULTI")+encode("SET", hiddenKey, "must-not-run")+encode("EXEC")); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(tx)
	_ = tx.Close()
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatalf("unsupported transaction did not close: %s", reply)
	}
	if out, err := a201Exec(f.redisID, "redis-cli", "--no-auth-warning", "-a", "a256-admin", "EXISTS", hiddenKey); err != nil || strings.TrimSpace(out) != "0" {
		t.Fatalf("transaction tail executed outside MULTI: %v %s", err, out)
	}
	status, body = secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
	if status != http.StatusOK || json.Unmarshal(body, &page) != nil || len(page.Items) != 4 {
		t.Fatalf("pipeline/transaction source refusal = %d %s", status, body)
	}
	controls := 0
	for _, a := range page.Items {
		if a.Phase == "control" {
			if a.Status != "blocked" || a.Reason != "unsupported_control" || len(a.Operations) != 0 {
				t.Fatal("unsupported transaction gained authority")
			}
			controls++
		}
	}
	if controls != 1 {
		t.Fatalf("transaction source refusals = %d; want 1", controls)
	}

	// Give the exact owned test login script authority. DEL/key authority already
	// exists, proving a real same-login lexical bypass rather than another account.
	if out, err := a201Exec(f.redisID, "redis-cli", "--no-auth-warning", "-a", "a256-admin", "ACL", "SETUSER", users[0], "+eval"); err != nil || strings.TrimSpace(out) != "OK" {
		t.Fatalf("seed owned script authority: %v %s", err, out)
	}
	if out, err := query("EVAL", "return redis.call('DEL',KEYS[1])", "1", key); err != nil || out != "1" {
		t.Fatalf("documented same-login Redis script bypass: %v %s", err, out)
	}
	exists("0")
}

func TestServedRedisCommandReviewWaitsAndCancelsA262(t *testing.T) {
	for _, mode := range []string{"approve", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true, redis: true})
			f.h.srv.pam.recordings = nil
			status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a262-redis-review-template-"+mode, map[string]any{
				"name": "a262-redis-review-" + mode, "reason": "Reviewed maintenance", "required_approvals": 2, "max_ttl_seconds": 120,
				"command_rules": []map[string]any{{"id": uuid.NewString(), "name": "Review direct key deletion", "enabled": true, "protocol": "redis", "operations": []string{"DEL"}, "effect": "require_approval", "required_approvals": 2, "review_ttl_seconds": 40}},
			})
			var template api.PAMAccessTemplate
			if status != http.StatusCreated || json.Unmarshal(body, &template) != nil {
				t.Fatalf("Redis review template = %d %s", status, body)
			}
			t.Cleanup(func() {
				status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a262-redis-review-delete-"+mode, nil)
				if status != http.StatusOK {
					t.Errorf("delete Redis review template = %d %s", status, body)
				}
			})
			session := f.open("a262-redis-review-open-"+mode, map[string]any{"target_type": "redis", "target_id": "redis-gw", "role": "redis-writer", "ttl_seconds": 120, "template_id": template.ID})
			t.Cleanup(func() {
				status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a262-redis-review-revoke-"+mode, map[string]any{"reason": "A262 fixture complete"})
				if status != http.StatusOK && status != http.StatusAccepted {
					t.Errorf("revoke Redis review = %d %s", status, body)
					return
				}
				a201Await(t, "Redis review fixture revoked before target stops", func() bool {
					ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
					defer cancel()
					_ = f.h.srv.Drain(ctx)
					row, err := f.h.store.GetPAMSession(ctx, f.h.tenant, session.ID)
					return err == nil && row.Status == "revoked"
				})
			})
			key := "a256:a262-review-" + uuid.NewString()
			if out, err := a201Exec(f.redisID, "redis-cli", "--no-auth-warning", "-a", "a256-admin", "SET", key, "a262-review-value"); err != nil || out != "OK" {
				t.Fatalf("seed Redis review key: %v %s", err, out)
			}
			exists := func(want string) {
				t.Helper()
				out, err := a201Exec(f.redisID, "redis-cli", "--no-auth-warning", "-a", "a256-admin", "EXISTS", key)
				if err != nil || strings.TrimSpace(out) != want {
					t.Fatalf("independent Redis review readback = %v %s; want %s", err, out, want)
				}
			}
			tunnel, stop := f.connect(session.ID, session.Gateway.Ticket, fixtureRedisCommand.MatchString)
			defer stop()
			port := fixtureRedisCommand.FindStringSubmatch(tunnel)[1]
			conn, err := net.Dial("tcp", "127.0.0.1:"+port)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			// RESP command framing only; this client holds no upstream credential.
			wire := "*2\r\n$3\r\nDEL\r\n$" + strconv.Itoa(len(key)) + "\r\n" + key + "\r\n"
			if _, err := io.WriteString(conn, wire); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				reply, err := bufio.NewReader(conn).ReadString('\n')
				if err == nil && reply != ":1\r\n" {
					err = errors.New("reviewed Redis deletion did not return target count one")
				}
				done <- err
			}()
			var action api.PAMCommandAction
			a201Await(t, "Redis deletion visibly held", func() bool {
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
			exists("1")
			select {
			case err := <-done:
				t.Fatalf("Redis deletion completed before review: %v", err)
			default:
			}
			var request api.ApprovalRequestRecord
			a201Await(t, "Redis action appears in ordinary reviewer queue", func() bool {
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
			if strings.Contains(string(raw), key) || strings.Contains(string(raw), "a262-review-value") {
				t.Fatal("Redis key/value entered review")
			}
			if mode == "disconnect" {
				_ = conn.Close()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("Redis client disconnect did not return")
				}
				a201Await(t, "Redis held action canceled", func() bool {
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
				status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+request.ID+"/approvals", reviewer, "a262-redis-vote-"+mode+strconv.Itoa(i), map[string]any{"intent_digest": request.IntentDigest})
				if mode == "approve" && status != http.StatusOK {
					t.Fatalf("Redis vote = %d %s", status, body)
				}
				if i == 0 || mode == "disconnect" {
					exists("1")
				}
			}
			if mode == "approve" {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("approved Redis deletion did not resume")
				}
				exists("0")
			} else {
				exists("1")
			}
		})
	}
}
