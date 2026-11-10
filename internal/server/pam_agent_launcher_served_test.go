// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/cli"
)

// TestA257AgentProcessHelper is the agent the A257 proof launches. It reads
// its instructions, does its database task through the launcher's tunnel
// with no credential, then holds a connection open until something ends it.
func TestA257AgentProcessHelper(t *testing.T) {
	out := os.Getenv("A257_AGENT_OUT")
	if out == "" {
		t.Skip("the agent TestServedAgentLauncherA257 launches")
	}
	os.Exit(a257Agent(out))
}

func a257Agent(out string) int {
	if err := os.WriteFile(out+".env", []byte(strings.Join(os.Environ(), "\n")), 0o600); err != nil { // #nosec G703 -- the launched agent writes beside the path its own test named (CWE-22)
		fmt.Println("agent: write environment:", err)
		return 2
	}
	instructions, err := os.ReadFile(os.Getenv("TRSTCTL_ACCESS_INSTRUCTIONS")) // #nosec G304,G703 -- the instructions file the launcher under test wrote (CWE-22)
	if err != nil {
		fmt.Println("agent: no instructions:", err)
		return 2
	}
	if err := os.WriteFile(out+".instructions", instructions, 0o600); err != nil { // #nosec G703 -- the launched agent writes beside the path its own test named (CWE-22)
		fmt.Println("agent: keep instructions:", err)
		return 2
	}
	ctx := context.Background()
	// No password, any user: the gateway signs in as the session's login.
	address := net.JoinHostPort(os.Getenv("PGHOST"), os.Getenv("PGPORT"))
	conn, err := pgconn.Connect(ctx, "postgres://agent@"+address+"/postgres?sslmode=disable&connect_timeout=15")
	if err != nil {
		fmt.Println("agent: connect:", err)
		return 2
	}
	task := conn.ExecParams(ctx, "SELECT count(*) FROM public.pam_smoke", nil, nil, nil, nil).Read()
	if task.Err != nil || len(task.Rows) != 1 {
		fmt.Println("agent: task:", task.Err)
		return 2
	}
	fmt.Printf("agent: task done, pam_smoke rows=%s\n", task.Rows[0][0])
	fmt.Println("agent: holding a connection")
	held := conn.ExecParams(ctx, "SELECT pg_sleep(600)", nil, nil, nil, nil).Read()
	fmt.Printf("agent: held connection ended=%t\n", held.Err != nil)
	return 3
}

var a257OpenedSession = regexp.MustCompile(`opened as session ([0-9a-f-]{36})`)

// TestServedAgentLauncherA257: an operator delegates one account to an
// agent's access bundle and mints a run that acts as the agent; `trstctl
// access agent` launched with that run's token gets the session reviewed and
// opened through the gateway, and the agent completes its database task
// through a loopback tunnel with no credential in its environment, its
// output, the launcher's output or the gateway's log. An account its bundle
// does not delegate is refused. One call revoking the agent's identity (Q4)
// revokes the run and ends the agent's live session.
func TestServedAgentLauncherA257(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{agentBroker: true})
	h := f.h
	// The served broker policy issues identities to agent-7 alone.
	const agent = "agent-7"
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a257-admin", "access:read", "access:write", "access:bundle.run")
	alice := seedScopedTokenSubject(t, h.store, h.tenant, "alice@ops.example", "certs:issue", "certs:read", "identities:write")

	// A257-L4: a bundle naming an account the registry cannot serve is
	// refused when it is saved, not when a run tries to open it.
	for name, tc := range map[string]struct {
		target map[string]any
		want   string
	}{
		"an unregistered target":           {map[string]any{"target_type": "postgres", "target_id": "pg-nowhere", "roles": []string{"readonly"}}, "not a registered privileged access target"},
		"a role the target does not allow": {map[string]any{"target_type": "postgres", "target_id": "pg-gw", "roles": []string{"superuser"}}, "does not allow the role superuser"},
	} {
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/bundles", admin, "a257-refused-"+name, map[string]any{
			"name": "refused", "permissions": []string{"access:sessions.open"}, "max_run_ttl_seconds": 3600,
			"access_targets": []map[string]any{tc.target},
		})
		if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), tc.want) {
			t.Fatalf("a bundle naming %s = %d %s; want 422 naming %q", name, status, body, tc.want)
		}
	}

	// The bundle delegates one account: pg-gw as readonly.
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/bundles", admin, "a257-bundle", map[string]any{
		"name": "nightly-report", "description": "the reporting agent's database", "permissions": []string{"access:sessions.open"},
		"max_run_ttl_seconds": 3600,
		"access_targets":      []map[string]any{{"target_type": "postgres", "target_id": "pg-gw", "roles": []string{"readonly"}}},
	})
	var bundle struct {
		ID            string `json:"id"`
		AccessTargets []struct {
			TargetID string `json:"target_id"`
		} `json:"access_targets"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &bundle) != nil || len(bundle.AccessTargets) != 1 {
		t.Fatalf("create the bundle = %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/bundles/"+bundle.ID+"/grants", admin, "a257-grant",
		map[string]any{"principal_type": "machine", "principal": agent}); status != http.StatusCreated {
		t.Fatalf("grant the bundle = %d %s", status, body)
	}
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/runs", admin, "a257-run",
		map[string]any{"principal": agent, "bundle_ids": []string{bundle.ID}, "ttl_seconds": 1800, "label": "nightly report"})
	var run struct {
		Run struct {
			ID string `json:"id"`
		} `json:"run"`
		Token string `json:"token"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &run) != nil || run.Token == "" {
		t.Fatalf("mint the agent's run = %d %s", status, body)
	}
	identity := servedBrokerIssue(t, h.servedHarness, alice, "a257-identity", servedBrokerAgentIssueBody(t, h.servedHarness, alice, agent), http.StatusCreated)

	// Reviewers approve each request as it arrives.
	approvals, stopApprovals := context.WithCancel(f.ctx)
	defer stopApprovals()
	go f.approvePending(approvals)

	payload := filepath.Join(f.dir, "a257-attestation")
	if err := os.WriteFile(payload, []byte("genuine"), 0o600); err != nil {
		t.Fatal(err)
	}
	launch := func(ctx context.Context, account string, transcript io.Writer) int {
		return cli.Run(ctx, []string{"access", "agent", "--account", account, "--reason", "nightly report", "--method", "stub_pam",
			"--payload-file", payload, "--ttl", "60s", "--approval-wait", "2m", "--", os.Args[0], "-test.run=^TestA257AgentProcessHelper$"},
			cli.Env{Server: f.api.URL, Token: run.Token, Tenant: h.tenant, HTTPClient: f.api.Client()}, strings.NewReader(""), transcript, transcript)
	}

	// The agent does its task, then holds a connection open.
	out := filepath.Join(f.dir, "a257-agent")
	t.Setenv("A257_AGENT_OUT", out)
	var transcript lockedBuffer
	exited := make(chan int, 1)
	go func() { exited <- launch(f.ctx, "postgres/pg-gw:readonly", &transcript) }()
	a201Await(t, "the agent completes its task", func() bool {
		select {
		case code := <-exited:
			t.Fatalf("the launcher exited %d: %s (gateway: %s)", code, transcript.String(), f.gatewayLog.String())
		default:
		}
		return strings.Contains(transcript.String(), "agent: holding a connection")
	})
	if !strings.Contains(transcript.String(), "agent: task done, pam_smoke rows=1") {
		t.Fatalf("the agent's task = %s", transcript.String())
	}
	m := a257OpenedSession.FindStringSubmatch(transcript.String())
	if m == nil {
		t.Fatalf("no session in the transcript: %s", transcript.String())
	}
	sessionID := m[1]
	if read := f.sessionRead(sessionID); read["requested_by"] != "bundle-run:"+agent || read["delivery"] != "gateway" {
		t.Fatalf("the agent's session = %v", read)
	}

	// The credential is nowhere the agent or its logs can see.
	dsn, err := h.srv.pam.gatewaySessionCredential(f.ctx, h.tenant, sessionID)
	if err != nil {
		t.Fatalf("reopen the session credential: %v", err)
	}
	parsed, err := url.Parse(string(dsn))
	if err != nil {
		t.Fatal(err)
	}
	password, _ := parsed.User.Password()
	if password == "" {
		t.Fatal("the session's login has no password")
	}
	environment, err := os.ReadFile(out + ".env") // #nosec G304 -- what the launched agent wrote in the test's temp dir (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	instructions, err := os.ReadFile(out + ".instructions") // #nosec G304 -- what the launched agent wrote in the test's temp dir (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"environment": string(environment), "instructions": string(instructions),
		"transcript": transcript.String(), "gateway log": f.gatewayLog.String()} {
		for what, secret := range map[string]string{"the session's password": password, "the session's DSN": string(dsn), "the run's token": run.Token} {
			if strings.Contains(text, secret) {
				t.Fatalf("%s reached the agent's %s", what, name)
			}
		}
	}
	if strings.Contains(string(environment), "TRSTCTL_TOKEN=") || !strings.Contains(string(environment), "TRSTCTL_ACCESS_1_ADDR=127.0.0.1:") ||
		!strings.Contains(string(instructions), "You hold no credential") {
		t.Fatalf("the agent's environment or instructions are not as launched:\n%s\n%s", environment, instructions)
	}

	// An account the bundle does not delegate is refused.
	var refused lockedBuffer
	if code := launch(f.ctx, "ssh/ssh-gw:user", &refused); code != 1 ||
		!strings.Contains(refused.String(), "is not among the accounts this run's access bundles delegate") {
		t.Fatalf("an undelegated account: exit %d %s", code, refused.String())
	}

	// One call revoking the agent's identity revokes its run and ends its
	// live session.
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/broker/agent-identities/"+identity.CertificateID+"/revoke", alice,
		"a257-revoke", map[string]any{"reason": "keyCompromise"})
	var revoked struct {
		TotalRevoked int      `json:"total_revoked"`
		Runs         []string `json:"runs"`
		Sessions     []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"sessions"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &revoked) != nil || revoked.TotalRevoked != 1 ||
		len(revoked.Runs) != 1 || revoked.Runs[0] != run.Run.ID || len(revoked.Sessions) != 1 || revoked.Sessions[0].ID != sessionID {
		t.Fatalf("one-call revoke = %d %s", status, body)
	}
	select {
	case code := <-exited:
		if code != 3 || !strings.Contains(transcript.String(), "agent: held connection ended=true") {
			t.Fatalf("the agent ended with %d: %s", code, transcript.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("the agent's held connection outlived the revoke: %s", transcript.String())
	}
	a201Await(t, "the gateway acknowledges ending the agent's session", func() bool {
		end, _ := f.sessionRead(sessionID)["gateway_end"].(map[string]any)
		return end != nil && end["ended"] == "recalled"
	})
	a201Await(t, "the session's login no longer signs in", func() bool {
		ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
		defer cancel()
		conn, err := pgconn.Connect(ctx, string(dsn))
		if err == nil {
			_ = conn.Close(ctx)
		}
		return err != nil
	})
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", run.Token, "a257-after-revoke",
		map[string]any{"target_type": "postgres", "target_id": "pg-gw", "role": "readonly"}); status != http.StatusUnauthorized {
		t.Fatalf("the revoked run still requests sessions: %d", status)
	}
}

// approvePending has both reviewers approve every pending request until ctx
// ends; it runs beside the test, so it reports nothing and stops on errors.
func (f *gatewayFixture) approvePending(ctx context.Context) {
	approved := map[string]bool{}
	call := func(method, path, token, key string, body any) (int, []byte) {
		var rdr io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rdr = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(ctx, method, f.h.ts.URL+path, rdr)
		if err != nil {
			return 0, nil
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		resp, err := f.h.ts.Client().Do(req)
		if err != nil {
			return 0, nil
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, raw
	}
	for ctx.Err() == nil {
		status, body := call(http.MethodGet, "/api/v1/approval-requests?status=pending", f.reviewerOne, "", nil)
		var list struct {
			Items []struct {
				ID           string `json:"id"`
				IntentDigest string `json:"intent_digest"`
			} `json:"items"`
		}
		if status == http.StatusOK && json.Unmarshal(body, &list) == nil {
			for _, item := range list.Items {
				if approved[item.ID] {
					continue
				}
				for i, reviewer := range []string{f.reviewerOne, f.reviewerTwo} {
					call(http.MethodPost, "/api/v1/approval-requests/"+item.ID+"/approvals", reviewer, fmt.Sprintf("a257-review-%s-%d", item.ID, i),
						map[string]any{"intent_digest": item.IntentDigest})
				}
				approved[item.ID] = true
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
}
