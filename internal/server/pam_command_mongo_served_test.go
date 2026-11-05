// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/binary"
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
	"trstctl.com/trstctl/internal/crypto/mongosignin"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/api"
)

func TestServedMongoCommandRuleBlocksAndRecordsA262(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true, mongoNote: "a262-owned-mongo-note"})
	f.h.srv.pam.recordings = nil
	ruleID := uuid.NewString()
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a262-mongo-template", map[string]any{
		"name": "a262-mongo-block", "reason": "Reviewed maintenance", "required_approvals": 2, "max_ttl_seconds": 120,
		"command_rules": []map[string]any{{"id": ruleID, "name": "Refuse direct document deletion", "enabled": true, "protocol": "mongodb", "operations": []string{"delete"}, "effect": "block"}},
	})
	var template api.PAMAccessTemplate
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil || template.ID == "" {
		t.Fatalf("save MongoDB enforcing template = %d %s", status, body)
	}
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a262-mongo-template-delete", nil)
		if status != http.StatusOK {
			t.Errorf("delete owned Mongo template = %d %s", status, body)
		}
	})
	session := f.open("a262-mongo-open", map[string]any{"target_type": "mongodb", "target_id": "mongo-gw", "role": "mongo-reader", "ttl_seconds": 120, "template_id": template.ID})
	t.Cleanup(func() {
		status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a262-mongo-revoke", map[string]any{"reason": "A262 fixture complete"})
		if status != http.StatusOK && status != http.StatusAccepted {
			t.Errorf("revoke owned Mongo = %d %s", status, body)
			return
		}
		a201Await(t, "owned Mongo rule session revoked before target shutdown", func() bool {
			ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
			defer cancel()
			_ = f.h.srv.Drain(ctx)
			row, err := f.h.store.GetPAMSession(ctx, f.h.tenant, session.ID)
			return err == nil && row.Status == "revoked"
		})
	})
	users := mongoSessionUsers(t, f.mongoID)
	if len(users) != 1 {
		t.Fatal("missing exact owned Mongo login")
	}
	root := func(script string) (string, error) {
		return a201Exec(f.mongoID, "mongosh", "--quiet", "-u", "root", "-p", "a256-admin", "--authenticationDatabase", "admin", "--eval", script)
	}
	// Fixture authority for the exact session login: readWrite on this disposable
	// orders database. The same-login alias below proves actual remove permission.
	if out, err := root(`db.getSiblingDB("orders").grantRolesToUser("` + users[0] + `",[{role:"readWrite",db:"orders"}])`); err != nil {
		t.Fatalf("seed owned Mongo authority: %v %s", err, out)
	}
	tunnel, stop := f.connect(session.ID, session.Gateway.Ticket, fixtureMongoCommand.MatchString)
	defer stop()
	port := fixtureMongoCommand.FindStringSubmatch(tunnel)[1]
	query := func(script string) (string, error) {
		cmd := exec.CommandContext(f.ctx, "docker", "exec", f.mongoID, "mongosh", "--quiet", "mongodb://host.docker.internal:"+port+"/orders?directConnection=true", "--eval", script) // #nosec G204 G702 -- stock Mongo shell against this test's owned tunnel (CWE-78)
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	count := func(want string) {
		t.Helper()
		out, err := root(`db.getSiblingDB("orders").notes.countDocuments({_id:1})`)
		if err != nil || strings.TrimSpace(out) != want {
			t.Fatalf("independent Mongo document readback = %v %s; want %s", err, out, want)
		}
	}
	count("1")
	if out, err := query(`db.notes.deleteOne({_id:1})`); err == nil || !strings.Contains(out, "TRSTCTL_COMMAND_REFUSED") {
		t.Fatalf("direct Mongo deletion escaped guardrail: %v %s", err, out)
	}
	count("1")
	status, body = secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/actions", f.requester, nil)
	var page api.PAMCommandActionList
	if status != http.StatusOK || json.Unmarshal(body, &page) != nil || len(page.Items) != 1 {
		t.Fatalf("Mongo refusal evidence = %d %s", status, body)
	}
	action := page.Items[0]
	if action.Status != "blocked" || action.Protocol != "mongodb" || len(action.RuleIDs) != 1 || action.RuleIDs[0] != ruleID || len(action.Operations) != 1 || action.Operations[0] != "delete" {
		t.Fatalf("Mongo public refusal lost its binding: %+v", action)
	}
	for _, value := range []string{"a262-owned-mongo-note", users[0], "a256-admin"} {
		if strings.Contains(string(body), value) {
			t.Fatalf("Mongo values or sign-in material reached policy evidence: %s", value)
		}
	}
	// findAndModify(remove=true) is another command class with the SAME account's
	// remove authority. A delete-only selector is a guardrail, not containment.
	if out, err := query(`JSON.stringify(db.runCommand({findAndModify:"notes",query:{_id:1},remove:true}))`); err != nil || !strings.Contains(out, "a262-owned-mongo-note") {
		t.Fatalf("documented same-login command-alias bypass: %v %s", err, out)
	}
	count("0")
}

func TestServedMongoCommandReviewWaitsAndCancelsA262(t *testing.T) {
	for _, mode := range []string{"approve", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			f := startGatewayFixture(t, gatewayFixtureOptions{commandRules: true, mongoNote: "a262-review-owned-note"})
			f.h.srv.pam.recordings = nil
			status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a262-mongo-review-template-"+mode, map[string]any{
				"name": "a262-mongo-review-" + mode, "reason": "Reviewed maintenance", "required_approvals": 2, "max_ttl_seconds": 120,
				"command_rules": []map[string]any{{"id": uuid.NewString(), "name": "Review direct document deletion", "enabled": true, "protocol": "mongodb", "operations": []string{"delete"}, "effect": "require_approval", "required_approvals": 2, "review_ttl_seconds": 40}},
			})
			var template api.PAMAccessTemplate
			if status != http.StatusCreated || json.Unmarshal(body, &template) != nil {
				t.Fatalf("Mongo review template = %d %s", status, body)
			}
			t.Cleanup(func() {
				status, body := secretsReqKey(t, f.h.servedHarness, http.MethodDelete, "/api/v1/access/templates/"+template.ID, f.operator, "a262-mongo-review-delete-"+mode, nil)
				if status != http.StatusOK {
					t.Errorf("delete Mongo review template = %d %s", status, body)
				}
			})
			session := f.open("a262-mongo-review-open-"+mode, map[string]any{"target_type": "mongodb", "target_id": "mongo-gw", "role": "mongo-reader", "ttl_seconds": 120, "template_id": template.ID})
			t.Cleanup(func() {
				status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a262-mongo-review-revoke-"+mode, map[string]any{"reason": "A262 fixture complete"})
				if status != http.StatusOK && status != http.StatusAccepted {
					t.Errorf("revoke Mongo review = %d %s", status, body)
					return
				}
				a201Await(t, "Mongo review fixture revoked before target stops", func() bool {
					ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
					defer cancel()
					_ = f.h.srv.Drain(ctx)
					row, err := f.h.store.GetPAMSession(ctx, f.h.tenant, session.ID)
					return err == nil && row.Status == "revoked"
				})
			})
			users := mongoSessionUsers(t, f.mongoID)
			if len(users) != 1 {
				t.Fatal("missing owned Mongo account")
			}
			root := func(script string) (string, error) {
				return a201Exec(f.mongoID, "mongosh", "--quiet", "-u", "root", "-p", "a256-admin", "--authenticationDatabase", "admin", "--eval", script)
			}
			if out, err := root(`db.getSiblingDB("orders").grantRolesToUser("` + users[0] + `",[{role:"readWrite",db:"orders"}])`); err != nil {
				t.Fatalf("seed owned Mongo review authority: %v %s", err, out)
			}
			count := func(want string) {
				t.Helper()
				out, err := root(`db.getSiblingDB("orders").notes.countDocuments({_id:1})`)
				if err != nil || strings.TrimSpace(out) != want {
					t.Fatalf("independent Mongo review readback = %v %s; want %s", err, out, want)
				}
			}
			tunnel, stop := f.connect(session.ID, session.Gateway.Ticket, fixtureMongoCommand.MatchString)
			defer stop()
			port := fixtureMongoCommand.FindStringSubmatch(tunnel)[1]
			conn, err := net.Dial("tcp", "127.0.0.1:"+port)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			doc := mongosignin.Encode([]mongosignin.E{{Key: "delete", Value: "notes"}, {Key: "deletes", Value: mongosignin.A{{Key: "0", Value: []mongosignin.E{{Key: "q", Value: []mongosignin.E{{Key: "_id", Value: int32(1)}}}, {Key: "limit", Value: int32(1)}}}}}, {Key: "ordered", Value: true}, {Key: "comment", Value: "a262-mongo-value-canary"}, {Key: "$db", Value: "orders"}})
			requestBody := append([]byte{0, 0, 0, 0, 0}, doc...)
			if _, err := conn.Write(append(mongosignin.MessageHeader(16+len(requestBody), 271, 0, mongosignin.OpMsg), requestBody...)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				var header [16]byte
				if _, err := io.ReadFull(conn, header[:]); err != nil {
					done <- err
					return
				}
				length := binary.LittleEndian.Uint32(header[:])
				if length < 21 || length > 1<<20 || binary.LittleEndian.Uint32(header[8:]) != 271 {
					done <- errors.New("Mongo reply lost correlation or size bound")
					return
				}
				reply := make([]byte, int(length)-16)
				if _, err := io.ReadFull(conn, reply); err != nil {
					done <- err
					return
				}
				elems, err := mongosignin.Elements(reply[5:])
				if err != nil {
					done <- err
					return
				}
				ok, n := false, false
				for _, e := range elems {
					value, valid := e.Number()
					if e.Key == "ok" {
						ok = valid && value == 1
					}
					if e.Key == "n" {
						n = valid && value == 1
					}
				}
				if !ok || !n {
					done <- errors.New("reviewed Mongo command did not return one actual removal")
					return
				}
				done <- nil
			}()
			var action api.PAMCommandAction
			a201Await(t, "Mongo deletion visibly held", func() bool {
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
				t.Fatalf("Mongo command completed before review: %v", err)
			default:
			}
			var request api.ApprovalRequestRecord
			a201Await(t, "Mongo action in ordinary reviewer queue", func() bool {
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
			for _, private := range []string{"a262-mongo-value-canary", users[0], "a256-admin"} {
				if strings.Contains(string(raw), private) {
					t.Fatal("Mongo values/sign-in material entered review")
				}
			}
			if mode == "disconnect" {
				_ = conn.Close()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("Mongo disconnect did not return")
				}
				a201Await(t, "held Mongo occurrence canceled", func() bool {
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
				status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+request.ID+"/approvals", reviewer, "a262-mongo-vote-"+mode+strconv.Itoa(i), map[string]any{"intent_digest": request.IntentDigest})
				if mode == "approve" && status != http.StatusOK {
					t.Fatalf("Mongo review vote = %d %s", status, body)
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
					t.Fatal("approved Mongo command did not resume")
				}
				count("0")
			} else {
				count("1")
			}
		})
	}
}
