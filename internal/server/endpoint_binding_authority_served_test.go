// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"net/http"
	"testing"

	"context"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/store"
)

func TestEndpointEnrollmentHonorsIssuanceAuthority(t *testing.T) {
	for _, route := range []string{"endpoint enrollment", "target deploy"} {
		for _, scenario := range []string{"configured profile", "requester lacks issuance permission", "dual control required", "policy rejects issuance", "profile changed after preview", "identity changed during policy"} {
			if route == "target deploy" && scenario == "profile changed after preview" {
				continue
			}
			t.Run(route+"/"+scenario, func(t *testing.T) {
				var changeIdentity func(context.Context) error
				h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
					if scenario == "configured profile" || scenario == "profile changed after preview" {
						d.DefaultProfile = "endpoint-short-life"
					}
					d.RequireApproval = scenario == "dual control required"
					d.EnablePolicyGate = scenario == "policy rejects issuance"
					if scenario == "identity changed during policy" {
						d.APIOptions = append(d.APIOptions, api.WithMutationGate(api.MutationGate{Policy: endpointAuthorityPolicy(func(ctx context.Context, _ policy.Input) (policy.Decision, error) {
							if changeIdentity != nil {
								if err := changeIdentity(ctx); err != nil {
									return policy.Decision{}, err
								}
							}
							return policy.Decision{Allow: true}, nil
						})}))
					}
				})
				admin := seedScopedToken(t, h.store, h.tenant, "owners:write", "connectors:write", "certs:issue", "profiles:write", "identities:write")
				create := func(path string, request any) map[string]json.RawMessage {
					t.Helper()
					code, body := secretsReq(t, h, http.MethodPost, path, admin, request)
					if code != http.StatusCreated {
						t.Fatalf("prepare %s: status=%d body=%s", path, code, body)
					}
					var response map[string]json.RawMessage
					if err := json.Unmarshal(body, &response); err != nil {
						t.Fatal(err)
					}
					return response
				}
				decodeID := func(raw json.RawMessage) string {
					t.Helper()
					var id string
					if err := json.Unmarshal(raw, &id); err != nil {
						t.Fatal(err)
					}
					return id
				}
				if scenario == "configured profile" || scenario == "profile changed after preview" {
					create("/api/v1/profiles", map[string]any{"name": "endpoint-short-life", "spec": map[string]any{
						"max_validity": "12m", "allowed_protocols": []string{"api"}, "allowed_dns_suffixes": []string{"endpoint.test"},
					}})
				}
				owner := decodeID(create("/api/v1/owners", map[string]any{"kind": "workload", "name": "endpoint authority fixture"})["id"])
				target := decodeID(create("/api/v1/connectors/targets", map[string]any{
					"name": "endpoint-authority", "connector": "postfix", "enabled": true,
					"config": map[string]any{"executor": "agent", "required_agent_role": "host", "required_agent_id": seedDestinationHost(t, h.store, h.tenant),
						"postfix_cert_path": "/mail/tls/smtp.crt", "postfix_key_path": "/mail/tls/smtp.key",
						"dovecot_cert_path": "/mail/tls/imap.crt", "dovecot_key_path": "/mail/tls/imap.key",
						"verify_address": "127.0.0.1:1465", "verify_server_name": "mail.endpoint.test"},
				})["id"])
				request := map[string]any{"owner_id": owner, "identity_name": "mail.endpoint.test", "target_id": target,
					"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}, "reason": "prove issuance authority"}
				code, body := secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", admin, request)
				if code != http.StatusOK {
					t.Fatalf("preview: status=%d body=%s", code, body)
				}
				var preview struct {
					RequestFingerprint string `json:"request_fingerprint"`
				}
				if err := json.Unmarshal(body, &preview); err != nil {
					t.Fatal(err)
				}
				request["preview_fingerprint"] = preview.RequestFingerprint
				if scenario == "profile changed after preview" {
					create("/api/v1/profiles", map[string]any{"name": "endpoint-short-life", "spec": map[string]any{"max_validity": "10m", "allowed_protocols": []string{"api"}, "allowed_dns_suffixes": []string{"endpoint.test"}}})
				}

				path := "/api/v1/lifecycle/endpoint-bindings"
				successStatus := http.StatusCreated
				if route == "target deploy" {
					identityID := decodeID(create("/api/v1/identities", map[string]any{"kind": "x509_certificate", "name": "mail.endpoint.test", "owner_id": owner})["id"])
					path = "/api/v1/connectors/targets/" + target + "/deploy"
					request = map[string]any{"identity_id": identityID, "reason": "prove issuance authority"}
					successStatus = http.StatusOK
				}

				changeIdentity = func(ctx context.Context) error {
					identity, found, err := h.store.FindIdentityByName(ctx, h.tenant, "mail.endpoint.test")
					if err != nil {
						return err
					}
					if !found {
						return fmt.Errorf("prepared identity not found")
					}
					changed, err := h.store.GetDeploymentTarget(ctx, h.tenant, target)
					if err != nil {
						return err
					}
					changed.Name += " changed during policy evaluation"
					_, err = h.srv.orch.BindIdentityDeploymentTarget(ctx, h.tenant, identity.ID, changed)
					return err
				}
				requester := admin
				if scenario == "requester lacks issuance permission" {
					requester = seedScopedToken(t, h.store, h.tenant, "connectors:write")
				}
				code, body = secretsReqKey(t, h, http.MethodPost, path, requester, "endpoint-authority-attempt", request)
				pending, err := orchestrator.NewOutbox(h.store).Pending(t.Context(), h.tenant)
				if err != nil {
					t.Fatal(err)
				}
				var issuanceJobs []orchestrator.Record
				for _, row := range pending {
					if row.Destination == "ca.issue" {
						issuanceJobs = append(issuanceJobs, row)
					}
				}
				if scenario != "configured profile" {
					wantStatus := http.StatusForbidden
					if scenario == "profile changed after preview" || scenario == "identity changed during policy" {
						wantStatus = http.StatusConflict
					}
					if len(issuanceJobs) != 0 || code != wantStatus {
						t.Fatalf("issuance was queued without required authority: status=%d issuance_jobs=%d", code, len(issuanceJobs))
					}
					if scenario == "dual control required" {
						proveEndpointApprovalContinuation(t, h, admin, request, path, successStatus, route == "endpoint enrollment")
					}
					return
				}
				if code != successStatus || len(issuanceJobs) != 1 {
					t.Fatalf("authorized endpoint: status=%d jobs=%d body=%s", code, len(issuanceJobs), body)
				}
				var intent struct {
					Issuance *store.OperationApprovalIssuanceBinding `json:"issuance"`
				}
				if err := json.Unmarshal(issuanceJobs[0].Payload, &intent); err != nil {
					t.Fatal(err)
				}
				if intent.Issuance == nil || intent.Issuance.ProfileName != "endpoint-short-life" || intent.Issuance.ProfileVersion != 1 || intent.Issuance.EffectiveTTLSeconds != 720 {
					t.Fatalf("endpoint issuance omitted its exact profile and 12-minute validity: %+v", intent.Issuance)
				}
				if err := h.srv.Drain(t.Context()); err != nil {
					t.Fatal(err)
				}
				delivered, err := orchestrator.NewOutbox(h.store).Pending(t.Context(), h.tenant)
				if err != nil {
					t.Fatal(err)
				}
				hostJobs := 0
				for _, job := range delivered {
					if job.Destination != "endpoint.renew" {
						continue
					}
					hostJobs++
					var host struct {
						Issuance *store.OperationApprovalIssuanceBinding `json:"issuance"`
					}
					if err := json.Unmarshal(job.Payload, &host); err != nil {
						t.Fatal(err)
					}
					if host.Issuance == nil || *host.Issuance != *intent.Issuance {
						t.Fatalf("host-agent issuance lost reviewed policy: %+v", host.Issuance)
					}
				}
				if hostJobs != 1 {
					t.Fatalf("expected one host issuance, got %d", hostJobs)
				}

			})
		}
	}
}

// Approval waiting is a continuation of one command, including after a lost
// HTTP result. It must not bind again and invalidate the reviewers' version.
func proveEndpointApprovalContinuation(t *testing.T, h *servedHarness, requester string, request map[string]any, path string, successStatus int, proveLostResponse bool) {
	t.Helper()
	const key = "endpoint-authority-attempt"

	pending, err := h.store.ListOperationApprovals(t.Context(), h.tenant, "pending", 100)
	if err != nil || len(pending) != 1 {
		t.Fatalf("one exact approval: %d %v", len(pending), err)
	}
	approval := pending[0]
	head, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	code, body := secretsReqKey(t, h, http.MethodPost, path, requester, key, request)
	if code != http.StatusForbidden {
		t.Fatalf("pending retry: %d %s", code, body)
	}
	after, err := h.log.LastSequence(t.Context())
	if err != nil || after != head {
		t.Fatalf("pending retry appended work: %d -> %d, %v", head, after, err)
	}
	approvalBody := map[string]any{"action": "issue", "request_id": approval.ID, "intent_digest": approval.IntentDigest}
	approvalPath := "/api/v1/identities/" + approval.ResourceID + "/approvals"
	code, body = secretsReqKey(t, h, http.MethodPost, approvalPath, requester, "endpoint-self-approval", approvalBody)
	if code == http.StatusOK {
		t.Fatalf("requester approved own enrollment: %s", body)
	}
	for i := 1; i <= 2; i++ {
		reviewer := seedScopedTokenSubject(t, h.store, h.tenant, fmt.Sprintf("endpoint-reviewer-%d", i), "certs:issue")
		code, body = secretsReqKey(t, h, http.MethodPost, approvalPath, reviewer, fmt.Sprintf("endpoint-review-%d", i), approvalBody)
		if code != http.StatusOK {
			t.Fatalf("review %d: %d %s", i, code, body)
		}
		if i == 1 {
			code, body = secretsReqKey(t, h, http.MethodPost, path, requester, key, request)
			if code != http.StatusForbidden {
				t.Fatalf("one review authorized issuance: %d %s", code, body)
			}
		}
	}
	code, receipt := secretsReqKey(t, h, http.MethodPost, path, requester, key, request)
	if code != successStatus {
		t.Fatalf("approved enrollment cannot continue: %d %s", code, receipt)
	}
	code, body = secretsReqKey(t, h, http.MethodPost, path, requester, key, request)
	if code != successStatus || !bytes.Equal(body, receipt) {
		t.Fatalf("completed replay changed receipt: %d %s", code, body)
	}
	if !proveLostResponse {
		return
	}
	head, err = h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `UPDATE idempotency_keys SET status='bound', result=NULL, completed_at=NULL WHERE tenant_id=$1 AND key=$2`, h.tenant, key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	code, body = secretsReqKey(t, h, http.MethodPost, path, requester, key, request)
	if code != successStatus || !bytes.Equal(body, receipt) {
		t.Fatalf("receiver committed but HTTP result was lost: %d %s", code, body)
	}
	after, err = h.log.LastSequence(t.Context())
	if err != nil || after != head {
		t.Fatalf("recovery repeated work: %d -> %d %v", head, after, err)
	}
	jobs, err := orchestrator.NewOutbox(h.store).Pending(t.Context(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, job := range jobs {
		if job.Destination == "ca.issue" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("approved enrollment queued %d issues", count)
	}
}

type endpointAuthorityPolicy func(context.Context, policy.Input) (policy.Decision, error)

func (fn endpointAuthorityPolicy) Evaluate(ctx context.Context, input policy.Input) (policy.Decision, error) {
	return fn(ctx, input)
}
