// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
)

func TestServedSSHCommandRuleBlocksAndRecordsA262(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true})
	f.h.srv.pam.recordings = nil
	ruleID := uuid.NewString()
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a262-ssh-block-template", map[string]any{"name": "a262-ssh-maintenance", "reason": "Reviewed maintenance", "required_approvals": 2, "max_ttl_seconds": 60, "command_rules": []map[string]any{{"id": ruleID, "name": "Block direct file removal", "enabled": true, "protocol": "ssh", "operations": []string{"rm"}, "effect": "block"}}})
	var template api.PAMAccessTemplate
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil || template.ID == "" {
		t.Fatalf("save enforcing SSH rule = %d %s", status, body)
	}
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a262-ssh-template-cleanup", nil)
		if status != http.StatusOK {
			t.Errorf("delete owned SSH template = %d %s", status, body)
		}
	})
	session := f.open("a262-ssh-block-open", map[string]any{"target_type": "ssh", "target_id": "ssh-gw", "role": "user", "ssh_principal": "alice", "ttl_seconds": 60, "template_id": template.ID})
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a262-ssh-session-cleanup", map[string]any{"reason": "A262 fixture complete"})
		if status != http.StatusOK && status != http.StatusAccepted {
			t.Errorf("revoke owned SSH session = %d %s", status, body)
			return
		}
		a201Await(t, "owned SSH session revoked before target stops", func() bool {
			ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
			defer cancel()
			_ = f.h.srv.Drain(ctx)
			row, err := f.h.store.GetPAMSession(ctx, f.h.tenant, session.ID)
			return err == nil && row.Status == "revoked"
		})
	})
	command, stop := f.sshTunnel(session)
	defer stop()
	path := "/tmp/a262-owned-" + uuid.NewString()
	if output, err := command("touch", path).CombinedOutput(); err != nil {
		t.Fatalf("create owned target file: %v %s", err, output)
	}
	if output, err := command("rm", path).CombinedOutput(); err == nil {
		t.Fatalf("direct rm escaped the SSH guardrail: %s", output)
	}
	if output, err := command("test", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("blocked rm changed the target: %v %s", err, output)
	}
	status, body = secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
	var page api.PAMCommandActionList
	if status != http.StatusOK || json.Unmarshal(body, &page) != nil || len(page.Items) != 1 || page.Items[0].Status != "blocked" || len(page.Items[0].RuleIDs) != 1 || page.Items[0].RuleIDs[0] != ruleID || len(page.Items[0].Operations) != 1 || page.Items[0].Operations[0] != "rm" {
		t.Fatalf("SSH refusal evidence = %d %s", status, body)
	}
	if strings.Contains(string(body), path) {
		t.Fatal("command arguments entered policy evidence")
	}
	if output, err := command().CombinedOutput(); err == nil {
		t.Fatalf("unguarded interactive shell accepted: %s", output)
	}
	// A nested interpreter is an explicit guardrail bypass, not containment.
	// It proves this same login can remove the file when the direct verb is hidden.
	if output, err := command("sh", "-c", "'rm "+path+"'").CombinedOutput(); err != nil {
		t.Fatalf("documented nested-shell bypass: %v %s", err, output)
	}
	if _, err := command("test", "-f", path).CombinedOutput(); err == nil {
		t.Fatal("nested-shell bypass did not execute at the real target")
	}
}

func TestServedSSHCommandReviewWaitsAndCancelsA262(t *testing.T) {
	for _, mode := range []string{"approve", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true})
			f.h.srv.pam.recordings = nil
			status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "ssh-review-template-"+mode, map[string]any{
				"name": "a262-ssh-review", "reason": "Reviewed maintenance", "required_approvals": 2, "max_ttl_seconds": 60,
				"command_rules": []map[string]any{{"id": uuid.NewString(), "name": "Review direct file removal", "enabled": true, "protocol": "ssh", "operations": []string{"rm"}, "effect": "require_approval", "required_approvals": 2, "review_ttl_seconds": 40}},
			})
			var template api.PAMAccessTemplate
			if status != http.StatusCreated || json.Unmarshal(body, &template) != nil {
				t.Fatalf("save SSH review template = %d %s", status, body)
			}
			t.Cleanup(func() {
				status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "ssh-review-clean-template-"+mode, nil)
				if status != http.StatusOK {
					t.Errorf("clean SSH template = %d %s", status, body)
				}
			})
			session := f.open("ssh-review-open-"+mode, map[string]any{"target_type": "ssh", "target_id": "ssh-gw", "role": "user", "ssh_principal": "alice", "ttl_seconds": 60, "template_id": template.ID})
			t.Cleanup(func() {
				status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "ssh-review-clean-session-"+mode, map[string]any{"reason": "A262 fixture complete"})
				if status != http.StatusOK && status != http.StatusAccepted {
					t.Errorf("clean SSH session = %d %s", status, body)
					return
				}
				a201Await(t, "SSH review session revoked before target shutdown", func() bool {
					ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
					defer cancel()
					_ = f.h.srv.Drain(ctx)
					row, err := f.h.store.GetPAMSession(ctx, f.h.tenant, session.ID)
					return err == nil && row.Status == "revoked"
				})
			})
			command, stop := f.sshTunnel(session)
			defer stop()
			path := "/tmp/a262-review-" + uuid.NewString()
			if out, err := command("touch", path).CombinedOutput(); err != nil {
				t.Fatalf("create file: %v %s", err, out)
			}
			exists := func(want bool) {
				t.Helper()
				out, err := command("test", "-f", path).CombinedOutput()
				if (err == nil) != want {
					t.Fatalf("independent SSH file readback = %v %s; want exists %v", err, out, want)
				}
			}
			proc := command("rm", path)
			if err := proc.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- proc.Wait() }()
			t.Cleanup(func() {
				if proc.Process != nil {
					_ = proc.Process.Kill()
				}
			})
			var action api.PAMCommandAction
			a201Await(t, "SSH request visibly held", func() bool {
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
			exists(true)
			select {
			case err := <-done:
				t.Fatalf("held SSH command completed early: %v", err)
			default:
			}
			var request api.ApprovalRequestRecord
			a201Await(t, "SSH review in ordinary approval queue", func() bool {
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
			if strings.Contains(string(raw), path) {
				t.Fatal("SSH argument entered human review")
			}
			if mode == "disconnect" {
				if err := proc.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("SSH client did not disconnect")
				}
				a201Await(t, "disconnected SSH action canceled", func() bool {
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
				status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+request.ID+"/approvals", reviewer, fmt.Sprintf("ssh-review-vote-%d", i), map[string]any{"intent_digest": request.IntentDigest})
				if mode == "approve" && status != http.StatusOK {
					t.Fatalf("SSH vote %d = %d %s", i, status, body)
				}
				if i == 0 || mode == "disconnect" {
					exists(true)
				}
			}
			if mode == "approve" {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("approved SSH request did not resume")
				}
				exists(false)
			} else {
				exists(true)
				if out, err := command("sh", "-c", "'rm "+path+"'").CombinedOutput(); err != nil {
					t.Fatalf("remove owned bypass fixture: %v %s", err, out)
				}
			}
		})
	}
}

func TestServedBrowserSSHExecAndHeldRequestCancelA262(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true})
	f.h.srv.pam.recordings = nil
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a262-browser-ssh-template", map[string]any{
		"name": "a262-browser-ssh", "reason": "Reviewed maintenance", "required_approvals": 2, "max_ttl_seconds": 120,
		"command_rules": []map[string]any{{"id": uuid.NewString(), "name": "Review file removal", "enabled": true, "protocol": "ssh", "operations": []string{"rm"}, "effect": "require_approval", "required_approvals": 2, "review_ttl_seconds": 40}},
	})
	var template api.PAMAccessTemplate
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil {
		t.Fatalf("browser SSH template = %d %s", status, body)
	}
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a262-browser-ssh-clean-template", nil)
		if status != http.StatusOK {
			t.Errorf("delete browser SSH template = %d %s", status, body)
		}
	})
	session := f.open("a262-browser-ssh-open", map[string]any{"target_type": "ssh", "target_id": "ssh-gw", "role": "user", "ssh_principal": "alice", "ttl_seconds": 120, "template_id": template.ID, "browser": true})
	observer := f.open("a262-browser-ssh-observer", map[string]any{"target_type": "ssh", "target_id": "ssh-gw", "role": "user", "ssh_principal": "alice", "ttl_seconds": 120})
	t.Cleanup(func() {
		for _, id := range []string{session.ID, observer.ID} {
			status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+id+"/revoke", f.requester, "a262-browser-ssh-revoke-"+id, map[string]any{"reason": "A262 fixture complete"})
			if status != http.StatusOK && status != http.StatusAccepted {
				t.Errorf("revoke browser SSH session = %d %s", status, body)
				continue
			}
			a201Await(t, "browser SSH fixture revoked", func() bool {
				ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
				defer cancel()
				_ = f.h.srv.Drain(ctx)
				row, err := f.h.store.GetPAMSession(ctx, f.h.tenant, id)
				return err == nil && row.Status == "revoked"
			})
		}
	})
	command, stop := f.sshTunnel(observer)
	defer stop()
	path := "/tmp/a262-browser-" + uuid.NewString()
	if out, err := command("touch", path).CombinedOutput(); err != nil {
		t.Fatalf("create browser-owned file: %v %s", err, out)
	}
	defer func() {
		out, err := command("rm", path).CombinedOutput()
		if err != nil {
			t.Errorf("clean owned browser file: %v %s", err, out)
		}
	}()
	terminalPath := "/api/v1/access/sessions/" + session.ID + "/terminals"
	status, body = secretsReqKey(t, f.h.servedHarness, http.MethodPost, terminalPath, f.requester, "a262-browser-ssh-no-shell", map[string]any{"cols": 80, "rows": 24})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("ruled browser shell accepted = %d %s", status, body)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	raw, _ := json.Marshal(map[string]any{"cols": 80, "rows": 24, "ssh_command": "rm " + path})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.h.ts.URL+terminalPath, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+f.requester)
	req.Header.Set("Idempotency-Key", "a262-browser-ssh-held-cancel")
	req.Header.Set("Content-Type", "application/json")
	done := make(chan error, 1)
	go func() {
		resp, err := f.h.ts.Client().Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		done <- err
	}()
	var actionID string
	a201Await(t, "browser exec waits at the real gateway", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
		var page api.PAMCommandActionList
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
	if out, err := command("test", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("pending browser command executed: %v %s", err, out)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled browser request succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("browser HTTP cancel did not return")
	}
	a201Await(t, "browser cancellation cancels held SSH review", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
		var page api.PAMCommandActionList
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			return false
		}
		for _, a := range page.Items {
			if a.ID == actionID {
				return a.Status == "canceled"
			}
		}
		return false
	})
	if out, err := command("test", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("canceled browser command changed target: %v %s", err, out)
	}
	status, body = secretsReqKey(t, f.h.servedHarness, http.MethodPost, terminalPath, f.requester, "a262-browser-ssh-exec", map[string]any{"cols": 80, "rows": 24, "ssh_command": "printf a262-browser-exec-ok"})
	var terminal api.PAMTerminal
	if status != http.StatusCreated || json.Unmarshal(body, &terminal) != nil {
		t.Fatalf("open browser exec = %d %s", status, body)
	}
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, terminalPath+"/"+terminal.ID, f.requester, "a262-browser-ssh-close", nil)
		if status != http.StatusOK {
			t.Errorf("close browser exec = %d %s", status, body)
		}
	})
	next := int64(0)
	var output strings.Builder
	a201Await(t, "browser receives completed exec output", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, terminalPath+"/"+terminal.ID+"/output?from="+strconv.FormatInt(next, 10)+"&wait=1", f.requester, nil)
		var out api.PAMTerminalOutput
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			return false
		}
		next = out.Next
		output.Write(out.Data)
		return out.Closed && out.ExitStatus != nil && *out.ExitStatus == 0 && strings.Contains(output.String(), "a262-browser-exec-ok")
	})
}
