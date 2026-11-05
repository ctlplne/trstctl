// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/store"
)

func TestServedGatewayCommandRuleBlocksAndAuditsPostgresA262(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true})
	// Use the real unrecorded gateway path: command authorization must not be a
	// side effect of enabling the separate recording store.
	f.h.srv.pam.recordings = nil
	ruleID := uuid.NewString()
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a262-block-template", map[string]any{
		"name": "a262-block-truncate", "reason": "Production maintenance", "required_approvals": 2, "max_ttl_seconds": 60,
		"command_rules": []map[string]any{{"id": ruleID, "name": "Refuse direct truncation", "enabled": true, "protocol": "postgres", "operations": []string{"DELETE", "TRUNCATE"}, "effect": "block"}},
	})
	var template struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil || template.ID == "" {
		t.Fatalf("save the enforcing template = %d %s", status, body)
	}
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a262-block-template-cleanup", nil)
		if status != http.StatusOK {
			t.Errorf("delete the exact owned template = %d %s", status, body)
		}
	})
	session := f.open("a262-block-open", map[string]any{"target_type": "postgres", "target_id": "pg-gw", "role": "readonly", "ttl_seconds": 60, "template_id": template.ID})
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a262-block-session-cleanup", map[string]any{"reason": "A262 fixture complete"})
		if status != http.StatusOK && status != http.StatusAccepted {
			t.Errorf("revoke exact fixture session = %d %s", status, body)
			return
		}
		a201Await(t, "the owned rule-bearing session is revoked before target shutdown", func() bool {
			work, cancel := context.WithTimeout(f.ctx, 20*time.Second)
			defer cancel()
			_ = f.h.srv.Drain(work)
			status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID, f.requester, nil)
			var row struct {
				Status string `json:"status"`
			}
			return status == http.StatusOK && json.Unmarshal(body, &row) == nil && row.Status == "revoked"
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
	count := func(want string) {
		t.Helper()
		r := conn.ExecParams(f.ctx, "SELECT count(*) FROM a262_guardrail", nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || len(r.Rows[0]) != 1 || string(r.Rows[0][0]) != want {
			t.Fatalf("target readback = %v, %v; want %s", r.Rows, r.Err, want)
		}
	}
	if err := query("CREATE TEMP TABLE a262_guardrail(value integer); INSERT INTO a262_guardrail VALUES(1)"); err != nil {
		t.Fatal(err)
	}
	// These are direct forms of the same statement, including a batch and an
	// ordinary comment/case variation. A policy error is not a target privilege
	// error: the dynamic-SQL proof below establishes this exact login can truncate.
	for _, sql := range []string{
		"TRUNCATE a262_guardrail",
		"/* harmless prefix */ tRuNcAtE /* split */ a262_guardrail",
		"SELECT 1; TRUNCATE a262_guardrail /* a262-public-canary-must-not-be-audit-text */",
	} {
		err := query(sql)
		if err == nil || !strings.Contains(err.Error(), "TRSTCTL") {
			t.Fatalf("direct truncation was not refused by policy: %v", err)
		}
		count("1")
	}
	// Each prepared binding is checked before it reaches planning. Values
	// never become matcher input or source/API evidence. A rejected duplicate
	// Parse must keep the OLD upstream statement's policy metadata.
	const prepared = "a262_destructive"
	const valueCanary = "a262-bound-value-must-not-be-evidence"
	if _, err := conn.Prepare(f.ctx, prepared, "DELETE FROM a262_guardrail WHERE $1::text IS NOT NULL", nil); err != nil {
		t.Fatalf("prepare real destructive statement: %v", err)
	}
	execute := func() {
		t.Helper()
		result := conn.ExecPrepared(f.ctx, prepared, [][]byte{[]byte(valueCanary)}, nil, nil).Read()
		if result.Err == nil || !strings.Contains(result.Err.Error(), "TRSTCTL") {
			t.Fatalf("prepared destructive action escaped policy: %v", result.Err)
		}
		count("1")
	}
	execute()
	execute()
	if _, err := conn.Prepare(f.ctx, prepared, "SELECT 1", nil); err == nil {
		t.Fatal("the target unexpectedly replaced a named statement without Close")
	}
	execute()
	// SQL-level prepared execution is deliberately unsupported in a guarded
	// connection: it must not bypass the wire statement/portal cache.
	for _, sql := range []string{"PREPARE a262_sql_prepared AS SELECT 1", "EXECUTE a262_sql_prepared"} {
		if err := query(sql); err == nil || !strings.Contains(err.Error(), "TRSTCTL") {
			t.Fatalf("unsupported SQL control escaped refusal: %v", err)
		}
		count("1")
	}
	// A keyword in a quoted value is data, not an operation.
	if err := query("SELECT 'TRUNCATE a262_guardrail'"); err != nil {
		t.Fatalf("quoted value treated as a command: %v", err)
	}
	// Documented guardrail bypass, executed against the same target and login:
	// a function's dynamic SQL is not parsed as a top-level client statement.
	// This is why the feature must not claim containment.
	if err := query("DO $$ BEGIN EXECUTE 'TRUNCATE a262_guardrail'; END $$"); err != nil {
		t.Fatalf("documented dynamic-SQL bypass = %v", err)
	}
	count("0")
	status, body = secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
	var page struct {
		Items []struct {
			Status  string   `json:"status"`
			RuleIDs []string `json:"rule_ids"`
			Digest  string   `json:"message_digest"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &page) != nil || len(page.Items) != 8 {
		t.Fatalf("session action evidence = %d %s", status, body)
	}
	for _, a := range page.Items {
		if a.Status != "blocked" || len(a.RuleIDs) != 1 || a.RuleIDs[0] != ruleID || len(a.Digest) != 64 {
			t.Fatalf("wrong bounded rule decision: %+v", a)
		}
	}
	for _, forbidden := range []string{"a262-public-canary-must-not-be-audit-text", "a262_guardrail", "DO $$", "uncredentialed-client", valueCanary} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("traffic content reached action metadata: %s", forbidden)
		}
	}
}

func TestServedGatewayCommandRuleWaitsForDistinctHumanReviewA262(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true})
	f.h.srv.pam.recordings = nil
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a262-review-template", map[string]any{
		"name": "a262-review-drop", "reason": "Reviewed maintenance", "required_approvals": 2, "max_ttl_seconds": 60,
		"command_rules": []map[string]any{{"id": uuid.NewString(), "name": "Review direct deletion", "enabled": true, "protocol": "postgres", "operations": []string{"DROP"}, "effect": "require_approval", "required_approvals": 2, "review_ttl_seconds": 40}},
	})
	var template struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil || template.ID == "" {
		t.Fatalf("save human-review rule = %d %s", status, body)
	}
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a262-review-template-cleanup", nil)
		if status != http.StatusOK {
			t.Errorf("delete owned review template = %d %s", status, body)
		}
	})
	session := f.open("a262-review-open", map[string]any{"target_type": "postgres", "target_id": "pg-gw", "role": "readonly", "ttl_seconds": 60, "template_id": template.ID})
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a262-review-session-cleanup", map[string]any{"reason": "A262 fixture complete"})
		if status != http.StatusOK && status != http.StatusAccepted {
			t.Errorf("revoke owned review session = %d %s", status, body)
			return
		}
		a201Await(t, "review fixture revoked before target shutdown", func() bool {
			work, cancel := context.WithTimeout(f.ctx, 20*time.Second)
			defer cancel()
			_ = f.h.srv.Drain(work)
			row, err := f.h.store.GetPAMSession(work, f.h.tenant, session.ID)
			return err == nil && row.Status == "revoked"
		})
	})
	local, stop := f.postgresTunnel(session)
	defer stop()
	conn, err := pgconn.Connect(f.ctx, "postgres://uncredentialed-client@"+local+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	observer, err := pgconn.Connect(f.ctx, "postgres://uncredentialed-client@"+local+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = observer.Close(context.Background()) }()
	if _, err := conn.Exec(f.ctx, "CREATE TEMP TABLE a262_review_guardrail(value integer)").ReadAll(); err != nil {
		t.Fatal(err)
	}
	targetExists := func(want string) {
		t.Helper()
		r := observer.ExecParams(f.ctx, "SELECT count(*) FROM pg_catalog.pg_class WHERE relname='a262_review_guardrail' AND relkind='r'", nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != want {
			t.Fatalf("independent relation readback = %v %v; want %s", r.Rows, r.Err, want)
		}
	}
	targetExists("1")
	done := make(chan error, 1)
	go func() {
		_, err := conn.Exec(f.ctx, "DROP TABLE a262_review_guardrail /* a262-review-text-canary */").ReadAll()
		done <- err
	}()
	var actionID string
	a201Await(t, "the exact statement is visibly pending", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
		var page struct {
			Items []struct{ ID, Status string } `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			return false
		}
		for _, a := range page.Items {
			if a.Status == "pending" {
				actionID = a.ID
				return true
			}
		}
		return false
	})
	targetExists("1")
	select {
	case err := <-done:
		t.Fatalf("statement completed before review: %v", err)
	default:
	}
	var request api.ApprovalRequestRecord
	a201Await(t, "command review appears in the genuine reviewer queue", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/approval-requests?status=pending", f.reviewerOne, nil)
		var page struct {
			Items []api.ApprovalRequestRecord `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			return false
		}
		for _, r := range page.Items {
			if r.ResourceKind == "pam_command" && r.ResourceID == "pam-command:"+actionID {
				request = r
				return true
			}
		}
		return false
	})
	if strings.Contains(request.Reason, "a262-review-text-canary") {
		t.Fatal("statement text entered review")
	}
	selfReviewer := seedScopedTokenSubject(t, f.h.store, f.h.tenant, "pam-requester", "access:approve")
	status, body = secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+request.ID+"/approvals", selfReviewer, "a262-self-vote", map[string]any{"intent_digest": request.IntentDigest})
	if status != http.StatusForbidden {
		t.Fatalf("requester approved its own statement = %d %s", status, body)
	}
	for i, reviewer := range []string{f.reviewerOne, f.reviewerTwo} {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+request.ID+"/approvals", reviewer, "a262-command-review-"+reviewer[:8], map[string]any{"intent_digest": request.IntentDigest})
		if status != http.StatusOK {
			t.Fatalf("human review %d = %d %s", i+1, status, body)
		}
		if i == 0 {
			targetExists("1")
			select {
			case err := <-done:
				t.Fatalf("one vote ran a two-vote action: %v", err)
			default:
			}
		}
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("approved statement: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("approved statement did not resume")
	}
	targetExists("0")
	a201Await(t, "authorization is durable and explicitly distinct from target completion", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"authorized"`)
	})
	requestRow, err := f.h.store.GetOperationApproval(f.ctx, f.h.tenant, request.ID)
	if err != nil || requestRow.Status != "consumed" {
		t.Fatalf("exact command review not consumed: %s %v", requestRow.Status, err)
	}
}

func TestServedGatewayCommandReviewDenyA262(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true})
	f.h.srv.pam.recordings = nil
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a262-review-deny-template", map[string]any{
		"name": "a262-review-deny-drop", "reason": "Reviewed maintenance", "required_approvals": 2, "max_ttl_seconds": 60,
		"command_rules": []map[string]any{{"id": uuid.NewString(), "name": "Review direct deletion", "enabled": true, "protocol": "postgres", "operations": []string{"DROP"}, "effect": "require_approval", "required_approvals": 2, "review_ttl_seconds": 5}},
	})
	var template struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil || template.ID == "" {
		t.Fatalf("save human-review rule = %d %s", status, body)
	}
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a262-review-deny-template-cleanup", nil)
		if status != http.StatusOK {
			t.Errorf("delete owned review template = %d %s", status, body)
		}
	})
	session := f.open("a262-review-deny-open", map[string]any{"target_type": "postgres", "target_id": "pg-gw", "role": "readonly", "ttl_seconds": 60, "template_id": template.ID})
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a262-review-deny-session-cleanup", map[string]any{"reason": "A262 fixture complete"})
		if status != http.StatusOK && status != http.StatusAccepted {
			t.Errorf("revoke owned review session = %d %s", status, body)
			return
		}
		a201Await(t, "review fixture revoked before target shutdown", func() bool {
			work, cancel := context.WithTimeout(f.ctx, 20*time.Second)
			defer cancel()
			_ = f.h.srv.Drain(work)
			row, err := f.h.store.GetPAMSession(work, f.h.tenant, session.ID)
			return err == nil && row.Status == "revoked"
		})
	})
	local, stop := f.postgresTunnel(session)
	defer stop()
	conn, err := pgconn.Connect(f.ctx, "postgres://uncredentialed-client@"+local+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	observer, err := pgconn.Connect(f.ctx, "postgres://uncredentialed-client@"+local+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = observer.Close(context.Background()) }()
	if _, err := conn.Exec(f.ctx, "CREATE TEMP TABLE a262_review_guardrail(value integer)").ReadAll(); err != nil {
		t.Fatal(err)
	}
	targetExists := func(want string) {
		t.Helper()
		r := observer.ExecParams(f.ctx, "SELECT count(*) FROM pg_catalog.pg_class WHERE relname='a262_review_guardrail' AND relkind='r'", nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != want {
			t.Fatalf("independent relation readback = %v %v; want %s", r.Rows, r.Err, want)
		}
	}
	targetExists("1")
	done := make(chan error, 1)
	go func() {
		_, err := conn.Exec(f.ctx, "DROP TABLE a262_review_guardrail /* a262-review-deny-text-canary */").ReadAll()
		done <- err
	}()
	var actionID string
	a201Await(t, "the exact statement is visibly pending", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
		var page struct {
			Items []struct{ ID, Status string } `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			return false
		}
		for _, a := range page.Items {
			if a.Status == "pending" {
				actionID = a.ID
				return true
			}
		}
		return false
	})
	targetExists("1")
	select {
	case err := <-done:
		t.Fatalf("statement completed before review: %v", err)
	default:
	}
	var request api.ApprovalRequestRecord
	a201Await(t, "command review appears in the genuine reviewer queue", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/approval-requests?status=pending", f.reviewerOne, nil)
		var page struct {
			Items []api.ApprovalRequestRecord `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			return false
		}
		for _, r := range page.Items {
			if r.ResourceKind == "pam_command" && r.ResourceID == "pam-command:"+actionID {
				request = r
				return true
			}
		}
		return false
	})
	if strings.Contains(request.Reason, "a262-review-deny-text-canary") {
		t.Fatal("statement text entered review")
	}
	status, body = secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+request.ID+"/denials", f.reviewerOne, "a262-command-denial", map[string]any{"intent_digest": request.IntentDigest, "reason": "Maintenance not approved"})
	if status != http.StatusOK {
		t.Fatalf("deny exact command = %d %s", status, body)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "TRSTCTL") {
			t.Fatalf("denied command was not refused: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("denied command did not unblock")
	}

	a201Await(t, "the held command's denied decision is durable", func() bool {
		row, err := f.h.store.GetPAMCommandAction(f.ctx, f.h.tenant, actionID)
		return err == nil && row.Status == "denied"
	})
	targetExists("1")
	status, body = secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+request.ID+"/approvals", f.reviewerTwo, "a262-deny-late-vote", map[string]any{"intent_digest": request.IntentDigest})
	if status != http.StatusConflict {
		t.Fatalf("late review of denied occurrence = %d %s", status, body)
	}
	targetExists("1")
}

func TestServedGatewayCommandReviewExpireA262(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true})
	f.h.srv.pam.recordings = nil
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a262-review-expire-template", map[string]any{
		"name": "a262-review-expire-drop", "reason": "Reviewed maintenance", "required_approvals": 2, "max_ttl_seconds": 60,
		"command_rules": []map[string]any{{"id": uuid.NewString(), "name": "Review direct deletion", "enabled": true, "protocol": "postgres", "operations": []string{"DROP"}, "effect": "require_approval", "required_approvals": 2, "review_ttl_seconds": 5}},
	})
	var template struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil || template.ID == "" {
		t.Fatalf("save human-review rule = %d %s", status, body)
	}
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a262-review-expire-template-cleanup", nil)
		if status != http.StatusOK {
			t.Errorf("delete owned review template = %d %s", status, body)
		}
	})
	session := f.open("a262-review-expire-open", map[string]any{"target_type": "postgres", "target_id": "pg-gw", "role": "readonly", "ttl_seconds": 60, "template_id": template.ID})
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a262-review-expire-session-cleanup", map[string]any{"reason": "A262 fixture complete"})
		if status != http.StatusOK && status != http.StatusAccepted {
			t.Errorf("revoke owned review session = %d %s", status, body)
			return
		}
		a201Await(t, "review fixture revoked before target shutdown", func() bool {
			work, cancel := context.WithTimeout(f.ctx, 20*time.Second)
			defer cancel()
			_ = f.h.srv.Drain(work)
			row, err := f.h.store.GetPAMSession(work, f.h.tenant, session.ID)
			return err == nil && row.Status == "revoked"
		})
	})
	local, stop := f.postgresTunnel(session)
	defer stop()
	conn, err := pgconn.Connect(f.ctx, "postgres://uncredentialed-client@"+local+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	observer, err := pgconn.Connect(f.ctx, "postgres://uncredentialed-client@"+local+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = observer.Close(context.Background()) }()
	if _, err := conn.Exec(f.ctx, "CREATE TEMP TABLE a262_review_guardrail(value integer)").ReadAll(); err != nil {
		t.Fatal(err)
	}
	targetExists := func(want string) {
		t.Helper()
		r := observer.ExecParams(f.ctx, "SELECT count(*) FROM pg_catalog.pg_class WHERE relname='a262_review_guardrail' AND relkind='r'", nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != want {
			t.Fatalf("independent relation readback = %v %v; want %s", r.Rows, r.Err, want)
		}
	}
	targetExists("1")
	done := make(chan error, 1)
	go func() {
		_, err := conn.Exec(f.ctx, "DROP TABLE a262_review_guardrail /* a262-review-expire-text-canary */").ReadAll()
		done <- err
	}()
	var actionID string
	a201Await(t, "the exact statement is visibly pending", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
		var page struct {
			Items []struct{ ID, Status string } `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			return false
		}
		for _, a := range page.Items {
			if a.Status == "pending" {
				actionID = a.ID
				return true
			}
		}
		return false
	})
	targetExists("1")
	select {
	case err := <-done:
		t.Fatalf("statement completed before review: %v", err)
	default:
	}
	var request api.ApprovalRequestRecord
	a201Await(t, "command review appears in the genuine reviewer queue", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/approval-requests?status=pending", f.reviewerOne, nil)
		var page struct {
			Items []api.ApprovalRequestRecord `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			return false
		}
		for _, r := range page.Items {
			if r.ResourceKind == "pam_command" && r.ResourceID == "pam-command:"+actionID {
				request = r
				return true
			}
		}
		return false
	})
	if strings.Contains(request.Reason, "a262-review-expire-text-canary") {
		t.Fatal("statement text entered review")
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "TRSTCTL") {
			t.Fatalf("expired command was not refused: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("held command exceeded its five-second review deadline")
	}

	a201Await(t, "the held command's expired decision is durable", func() bool {
		row, err := f.h.store.GetPAMCommandAction(f.ctx, f.h.tenant, actionID)
		return err == nil && row.Status == "expired"
	})
	targetExists("1")
	status, body = secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+request.ID+"/approvals", f.reviewerTwo, "a262-expire-late-vote", map[string]any{"intent_digest": request.IntentDigest})
	if status != http.StatusConflict {
		t.Fatalf("late review of expired occurrence = %d %s", status, body)
	}
	targetExists("1")
}

func TestServedGatewayCommandReviewDisconnectA262(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true})
	f.h.srv.pam.recordings = nil
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a262-review-disconnect-template", map[string]any{
		"name": "a262-review-disconnect-drop", "reason": "Reviewed maintenance", "required_approvals": 2, "max_ttl_seconds": 60,
		"command_rules": []map[string]any{{"id": uuid.NewString(), "name": "Review direct deletion", "enabled": true, "protocol": "postgres", "operations": []string{"UPDATE"}, "effect": "require_approval", "required_approvals": 2, "review_ttl_seconds": 5}},
	})
	var template struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil || template.ID == "" {
		t.Fatalf("save human-review rule = %d %s", status, body)
	}
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a262-review-disconnect-template-cleanup", nil)
		if status != http.StatusOK {
			t.Errorf("delete owned review template = %d %s", status, body)
		}
	})
	session := f.open("a262-review-disconnect-open", map[string]any{"target_type": "postgres", "target_id": "pg-gw", "role": "readonly", "ttl_seconds": 60, "template_id": template.ID})
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a262-review-disconnect-session-cleanup", map[string]any{"reason": "A262 fixture complete"})
		if status != http.StatusOK && status != http.StatusAccepted {
			t.Errorf("revoke owned review session = %d %s", status, body)
			return
		}
		a201Await(t, "review fixture revoked before target shutdown", func() bool {
			work, cancel := context.WithTimeout(f.ctx, 20*time.Second)
			defer cancel()
			_ = f.h.srv.Drain(work)
			row, err := f.h.store.GetPAMSession(work, f.h.tenant, session.ID)
			return err == nil && row.Status == "revoked"
		})
	})
	local, stop := f.postgresTunnel(session)
	defer stop()
	conn, err := pgconn.Connect(f.ctx, "postgres://uncredentialed-client@"+local+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	observer, err := pgconn.Connect(f.ctx, "postgres://uncredentialed-client@"+local+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = observer.Close(context.Background()) }()
	targetExists := func(want string) {
		t.Helper()
		r := observer.ExecParams(f.ctx, "SELECT value FROM public.a262_counter", nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != want {
			t.Fatalf("independent relation readback = %v %v; want %s", r.Rows, r.Err, want)
		}
	}
	targetExists("1")
	done := make(chan error, 1)
	go func() {
		_, err := conn.Exec(f.ctx, "UPDATE public.a262_counter SET value=2 /* a262-review-disconnect-text-canary */").ReadAll()
		done <- err
	}()
	var actionID string
	a201Await(t, "the exact statement is visibly pending", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
		var page struct {
			Items []struct{ ID, Status string } `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			return false
		}
		for _, a := range page.Items {
			if a.Status == "pending" {
				actionID = a.ID
				return true
			}
		}
		return false
	})
	targetExists("1")
	select {
	case err := <-done:
		t.Fatalf("statement completed before review: %v", err)
	default:
	}
	var request api.ApprovalRequestRecord
	a201Await(t, "command review appears in the genuine reviewer queue", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/approval-requests?status=pending", f.reviewerOne, nil)
		var page struct {
			Items []api.ApprovalRequestRecord `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			return false
		}
		for _, r := range page.Items {
			if r.ResourceKind == "pam_command" && r.ResourceID == "pam-command:"+actionID {
				request = r
				return true
			}
		}
		return false
	})
	if strings.Contains(request.Reason, "a262-review-disconnect-text-canary") {
		t.Fatal("statement text entered review")
	}
	if err := conn.Conn().Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("disconnected command reported target success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("disconnect did not cancel held action")
	}

	a201Await(t, "the held command's canceled decision is durable", func() bool {
		row, err := f.h.store.GetPAMCommandAction(f.ctx, f.h.tenant, actionID)
		return err == nil && row.Status == "canceled"
	})
	targetExists("1")
	status, body = secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+request.ID+"/approvals", f.reviewerTwo, "a262-disconnect-late-vote", map[string]any{"intent_digest": request.IntentDigest})
	if status != http.StatusConflict {
		t.Fatalf("late review of canceled occurrence = %d %s", status, body)
	}
	targetExists("1")

	if _, err := observer.Exec(f.ctx, "DO $$ BEGIN UPDATE public.a262_counter SET value=2; END $$").ReadAll(); err != nil {
		t.Fatalf("same-login target permission control: %v", err)
	}
	targetExists("2")
}

func TestServedGatewayPreparedCommandNeedsFreshReviewForEveryBindingA262(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true})
	f.h.srv.pam.recordings = nil
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a262-prepared-review-template", map[string]any{
		"name": "a262-prepared-review-drop", "reason": "Reviewed maintenance", "required_approvals": 2, "max_ttl_seconds": 60,
		"command_rules": []map[string]any{{"id": uuid.NewString(), "name": "Review direct deletion", "enabled": true, "protocol": "postgres", "operations": []string{"UPDATE"}, "effect": "require_approval", "required_approvals": 2, "review_ttl_seconds": 40}},
	})
	var template struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil || template.ID == "" {
		t.Fatalf("save human-review rule = %d %s", status, body)
	}
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a262-prepared-review-template-cleanup", nil)
		if status != http.StatusOK {
			t.Errorf("delete owned review template = %d %s", status, body)
		}
	})
	session := f.open("a262-prepared-review-open", map[string]any{"target_type": "postgres", "target_id": "pg-gw", "role": "readonly", "ttl_seconds": 60, "template_id": template.ID})
	t.Cleanup(func() {
		owned, err := f.h.store.GetPAMSession(f.ctx, f.h.tenant, session.ID)
		if err != nil {
			t.Errorf("read owned review session before cleanup: %v", err)
			return
		}
		if owned.Status == api.PAMSessionStatusActive {
			status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a262-prepared-review-session-cleanup", map[string]any{"reason": "A262 fixture complete"})
			if status != http.StatusOK && status != http.StatusAccepted {
				t.Errorf("revoke owned review session = %d %s", status, body)
				return
			}
		} else if owned.Status != store.PAMSessionStatusRevoking && owned.Status != store.PAMSessionStatusRevoked && owned.Status != store.PAMSessionStatusExpired {
			t.Errorf("unexpected owned cleanup state %s", owned.Status)
			return
		}

		a201Await(t, "review fixture revoked before target shutdown", func() bool {
			work, cancel := context.WithTimeout(f.ctx, 20*time.Second)
			defer cancel()
			_ = f.h.srv.Drain(work)
			row, err := f.h.store.GetPAMSession(work, f.h.tenant, session.ID)
			return err == nil && row.Status == "revoked"
		})
	})
	local, stop := f.postgresTunnel(session)
	defer stop()
	conn, err := pgconn.Connect(f.ctx, "postgres://uncredentialed-client@"+local+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	observer, err := pgconn.Connect(f.ctx, "postgres://uncredentialed-client@"+local+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = observer.Close(context.Background()) }()
	targetExists := func(want string) {
		t.Helper()
		r := observer.ExecParams(f.ctx, "SELECT value FROM public.a262_counter", nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != want {
			t.Fatalf("independent relation readback = %v %v; want %s", r.Rows, r.Err, want)
		}
	}
	targetExists("1")

	if _, err := conn.Prepare(f.ctx, "a262_reviewed_update", "UPDATE public.a262_counter SET value=$1::integer WHERE $2::text IS NOT NULL RETURNING value", nil); err != nil {
		t.Fatal(err)
	}
	previousID := ""
	for i := range 2 {
		wantBefore, wantAfter := "1", "2"
		if i == 1 {
			wantBefore, wantAfter = "2", "3"
		}
		done := make(chan error, 1)
		boundCanary := "a262-review-bound-values-stay-local"
		go func() {
			r := conn.ExecPrepared(f.ctx, "a262_reviewed_update", [][]byte{[]byte(wantAfter), []byte(boundCanary)}, nil, nil).Read()
			done <- r.Err
		}()
		var action api.PAMCommandAction
		a201Await(t, "each new Bind has its own held occurrence and exact review link", func() bool {
			status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
			var page api.PAMCommandActionList
			if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
				return false
			}
			if strings.Contains(string(body), boundCanary) {
				t.Fatal("bound value entered action evidence")
			}
			for _, a := range page.Items {
				if a.Status == "pending" && a.ApprovalRequestID != "" && a.ApprovalIntentDigest != "" && a.ID != previousID {
					action = a
					return true
				}
			}
			return false
		})
		targetExists(wantBefore)
		for n, reviewer := range []string{f.reviewerOne, f.reviewerTwo} {
			status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+action.ApprovalRequestID+"/approvals", reviewer, "a262-prepared-vote-"+uuid.NewString(), map[string]any{"intent_digest": action.ApprovalIntentDigest})
			if status != http.StatusOK {
				t.Fatalf("prepared occurrence review = %d %s", status, body)
			}
			if n == 0 {
				targetExists(wantBefore)
				select {
				case err := <-done:
					t.Fatalf("held prepared review completed before its second vote: %v", err)
				default:
				}
			}
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("approved Bind: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("approved Bind did not resume")
		}
		targetExists(wantAfter)
		if action.ID == previousID {
			t.Fatal("new binding reused an occurrence")
		}
		previousID = action.ID
	}

	// A recorded grant is historical evidence, not fresh execution authority
	// after the session has entered revocation, even at the same occurrence key.
	action, err := f.h.store.GetPAMCommandAction(f.ctx, f.h.tenant, previousID)
	if err != nil {
		t.Fatal(err)
	}
	active, err := f.h.store.GetPAMSession(f.ctx, f.h.tenant, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	job, held, err := f.h.store.GetAgentJobForRedemption(f.ctx, f.h.tenant, active.GatewayAgentID, action.JobID, time.Now().UTC())
	if err != nil || !held {
		t.Fatalf("retain the exact held source job: %v %v", held, err)
	}
	status, body = secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a262-prepared-end-authority", map[string]any{"reason": "End exact reviewed authority"})
	if status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("end reviewed session: %d %s", status, body)
	}
	_, err = f.h.srv.pam.evaluateGatewayCommand(f.ctx, f.h.tenant, active.GatewayAgentID, job.Payload, action.JobID, action.Attempt, action.ID, action.Observation, false)
	if !errors.Is(err, api.ErrPAMRejected) {
		t.Fatalf("historical grant became current authority after revocation: %v", err)
	}
}
