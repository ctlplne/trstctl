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

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/rightsize"
	"trstctl.com/trstctl/internal/store"
)

// A64: a right-size binding that names a network relay hands each operation to
// the relay. The control plane stamps the queued row for the network role and
// leaves it; the relay claims it, redeems the binding's token and endpoint for
// one attempt, runs the shared mutate-and-readback conversation against the
// entitlement service, and its signed report becomes the operation's terminal
// receipt. A relay failure closes the operation honestly.
func TestServedRightSizeBindingOnANetworkRelayExecutesThereAndRecordsTheEvidence(t *testing.T) {
	const (
		token      = "a64-entitlement-token"     // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		secretName = "connectors/right-size/a64" // #nosec G101 -- a secret-store NAME the binding references, not a credential value (CWE-798)
	)
	var mu sync.Mutex
	scopes := map[string][]string{"service-1": {"read", "write"}, "service-2": {"read", "write"}}
	entitlements := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		target := strings.TrimPrefix(r.URL.Path, "/v1/entitlements/")
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPatch:
			body, _ := io.ReadAll(r.Body)
			var req struct {
				RemoveScopes []string `json:"remove_scopes"`
			}
			_ = json.Unmarshal(body, &req)
			kept := []string{}
			for _, scope := range scopes[target] {
				keep := true
				for _, gone := range req.RemoveScopes {
					if gone == scope {
						keep = false
					}
				}
				if keep {
					kept = append(kept, scope)
				}
			}
			scopes[target] = kept
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "applied", "mutation_id": "mutation-" + target, "removed_scopes": req.RemoveScopes, "rollback_ref": "rollback-" + target})
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"scopes": scopes[target]})
		}
	}))
	t.Cleanup(entitlements.Close)

	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{"connector.right_size"}, func(d *Deps) {
		d.ConnectorRightSizeBindings = []config.ConnectorRightSizeBinding{{
			TenantID: "", Connector: "least-privilege", Endpoint: entitlements.URL,
			TokenRef: "secret://" + secretName, Executor: config.RightSizeExecutorNetwork,
		}}
	})
	// The binding is tenant-bound; the harness tenant is known only now.
	dispatcher, ok := h.srv.obHandler.(*issuanceDispatcher)
	if !ok {
		t.Fatal("served outbox handler is not the issuance dispatcher")
	}
	binding := config.ConnectorRightSizeBinding{TenantID: h.tenant, Connector: "least-privilege", Endpoint: entitlements.URL, TokenRef: "secret://" + secretName, Executor: config.RightSizeExecutorNetwork}
	dispatcher.rightSizeBindings = rightSizeBindingMap([]config.ConnectorRightSizeBinding{binding})
	agentSvc, ok := h.srv.agentServiceForTest()
	if !ok || agentSvc.relayCredentials == nil {
		t.Fatal("agent service or its credential resolver is not assembled")
	}
	agentSvc.relayCredentials.rightSizeBindings = dispatcher.rightSizeBindings
	ctx := context.Background()
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, secretName, []byte(token))
	if err != nil {
		t.Fatalf("seal tenant secret: %v", err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, secretName, sealed)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "relay-test", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	seed := func(key, target string) orchestrator.ConnectorRightSizeIdentity {
		t.Helper()
		identity := orchestrator.ConnectorRightSizeIdentityFor(h.tenant, key)
		deliveryID := identity.DeliveryID
		if _, err := h.srv.orch.RecordConnectorRightSizeOperation(ctx, h.tenant, store.RemediationPlaybookRun{
			ID: identity.OperationID, PlaybookID: "nhi-right-size", TargetIdentityID: "10000000-0000-4000-8000-000000000064",
			InventoryID: "identity/10000000-0000-4000-8000-000000000064", Status: "queued", Phase: "right_size_connector_intent_queued",
			Action: "right_size", Reason: "usage-backed right-size", Connector: "least-privilege", Target: target,
			ConnectorDeliveryID: &deliveryID,
			ScopeDelta:          json.RawMessage(`{"remove_scopes":["write"],"recommended_scopes":["read"]}`),
			EvidenceRefs:        []string{"nhi_posture:CAP-POST-01"}, RollbackRefs: []string{"restore write"},
			IdempotencyKey: key, RequestBinding: "binding-" + key,
			InitialHTTPStatus: 201, InitialResponse: json.RawMessage(`{"status":"queued"}`), CreatedBy: "operator",
		}); err != nil {
			t.Fatalf("record right-size operation: %v", err)
		}
		return identity
	}
	first := seed("a64-relay-1", "service-1")
	second := seed("a64-relay-2", "service-2")

	// The control plane sees both rows, stamps them for the relay and does no
	// endpoint I/O.
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	mu.Lock()
	untouched := len(scopes["service-1"]) == 2 && len(scopes["service-2"]) == 2
	mu.Unlock()
	if !untouched {
		t.Fatal("the control plane mutated entitlements for a relay-bound binding")
	}
	var roles []string
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT required_agent_role FROM outbox WHERE tenant_id=$1 AND destination='connector.right_size' ORDER BY id`, h.tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var role string
			if err := rows.Scan(&role); err != nil {
				return err
			}
			roles = append(roles, role)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if len(roles) != 2 || roles[0] != "network" || roles[1] != "network" {
		t.Fatalf("right-size rows stamped %v, want network for both", roles)
	}

	// The relay claims, redeems the binding's token and endpoint, and runs the
	// same conversation the control plane would.
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.right_size"}, Limit: 5, LeaseSeconds: 120})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 2 {
		t.Fatalf("relay claimed %d right-size jobs, want 2", len(claimed.Jobs))
	}
	for _, job := range claimed.Jobs {
		var intent relay.RightSizeIntent
		if err := json.Unmarshal(job.Payload, &intent); err != nil || intent.Action != "right_size" {
			t.Fatalf("claimed intent = %+v %v", intent, err)
		}
		redeemed, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt})
		if err != nil {
			t.Fatalf("redeem for %s: %v", intent.Target, err)
		}
		material := relay.Material{}
		for _, item := range redeemed.Items {
			material[item.Name] = item.Value
		}
		if string(material[relay.RightSizeTokenRef]) != token || string(material[relay.RightSizeEndpointRef]) != entitlements.URL {
			t.Fatalf("redeemed material for %s lacks the binding token or endpoint: %v", intent.Target, redeemed.Items)
		}
		if intent.Target == "service-2" {
			// The second operation fails at the endpoint: the relay reports the
			// closed phrase and the operation closes.
			if _, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeFailed, transport.RightSizeFailedAtEndpoint, "")); err != nil {
				t.Fatalf("report failure: %v", err)
			}
			continue
		}
		mutation, err := rightsize.Apply(ctx, entitlements.Client(), rightsize.Input{
			Endpoint: string(material[relay.RightSizeEndpointRef]), Token: material[relay.RightSizeTokenRef],
			TenantID: string(material["right_size.tenant_id"]), IdempotencyKey: intent.OutboxKey,
			Connector: intent.Connector, Target: intent.Target, InventoryID: intent.InventoryID,
			TargetIdentityID: intent.TargetIdentityID, Reason: intent.Reason, ScopeDelta: intent.ScopeDelta,
		})
		if err != nil {
			t.Fatalf("relay conversation: %v", err)
		}
		result := relay.RightSizeReport{OperationID: intent.ID, Connector: intent.Connector, Target: intent.Target,
			MutationID: mutation.MutationID, RollbackRef: mutation.RollbackRef, ReadbackDigest: mutation.ReadbackDigest}
		encoded, _ := json.Marshal(result)
		if _, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(encoded), result.Digest())); err != nil {
			t.Fatalf("report: %v", err)
		}
	}
	mu.Lock()
	mutated := len(scopes["service-1"]) == 1 && scopes["service-1"][0] == "read"
	mu.Unlock()
	if !mutated {
		t.Fatal("the relay conversation did not remove the write scope")
	}

	succeeded, err := h.store.GetRemediationPlaybookRun(ctx, h.tenant, first.OperationID)
	if err != nil || succeeded.Status != "succeeded" {
		t.Fatalf("first operation = %+v %v, want succeeded", succeeded, err)
	}
	receipt, err := h.store.GetConnectorDeliveryReceipt(ctx, h.tenant, first.DeliveryID)
	if err != nil || receipt.Status != "delivered" || receipt.Reason != "entitlements_mutated" || receipt.Fingerprint == "" ||
		!strings.Contains(receipt.Detail, "network-relay readback") || receipt.RollbackRef != "rollback-service-1" {
		t.Fatalf("first receipt = %+v %v", receipt, err)
	}
	failed, err := h.store.GetRemediationPlaybookRun(ctx, h.tenant, second.OperationID)
	if err != nil || failed.Status != "failed" || failed.TerminalReason != "entitlement_mutation_failed_on_relay" {
		t.Fatalf("second operation = %+v %v, want failed on relay", failed, err)
	}
}
