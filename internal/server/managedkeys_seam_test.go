// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

type fakeManagedKeyService struct{}

func (fakeManagedKeyService) Generate(_ context.Context, _ string, alg crypto.Algorithm, _, _ string) (api.ManagedKey, error) {
	return api.ManagedKey{KeyID: "fake-managed-key-1", Algorithm: alg, Version: 1, State: "active"}, nil
}
func (fakeManagedKeyService) Rotate(context.Context, string, string, string, string, string) (api.ManagedKey, error) {
	return api.ManagedKey{}, nil
}
func (fakeManagedKeyService) Revoke(context.Context, string, string, string, string, string) (api.ManagedKey, error) {
	return api.ManagedKey{}, nil
}
func (fakeManagedKeyService) Zeroize(context.Context, string, string, string, string, string) (api.ManagedKey, error) {
	return api.ManagedKey{}, nil
}

type dualControlManagedKeyService struct {
	checker api.ExactApprovalChecker
	calls   map[string]int
}

func (s *dualControlManagedKeyService) Generate(_ context.Context, _ string, alg crypto.Algorithm, _, _ string) (api.ManagedKey, error) {
	return api.ManagedKey{
		KeyID: "https://managed-hsm.example.test/keys/tenant/root/v1", Algorithm: alg,
		Version: 1, State: "active", PublicDER: []byte("public-key-metadata"),
	}, nil
}

func (s *dualControlManagedKeyService) Rotate(ctx context.Context, tenantID, keyID, requester, _, _ string) (api.ManagedKey, error) {
	if err := s.authorize(ctx, tenantID, keyID, api.ManagedKeyActionRotate, requester); err != nil {
		return api.ManagedKey{}, err
	}
	return api.ManagedKey{KeyID: keyID + "/successor", Algorithm: crypto.RSA2048, Version: 2, State: "active"}, nil
}

func (s *dualControlManagedKeyService) Revoke(ctx context.Context, tenantID, keyID, requester, _, _ string) (api.ManagedKey, error) {
	if err := s.authorize(ctx, tenantID, keyID, api.ManagedKeyActionRevoke, requester); err != nil {
		return api.ManagedKey{}, err
	}
	return api.ManagedKey{KeyID: keyID, Algorithm: crypto.RSA2048, Version: 2, State: "revoked"}, nil
}

func (s *dualControlManagedKeyService) Zeroize(ctx context.Context, tenantID, keyID, requester, _, _ string) (api.ManagedKey, error) {
	if err := s.authorize(ctx, tenantID, keyID, api.ManagedKeyActionZeroize, requester); err != nil {
		return api.ManagedKey{}, err
	}
	return api.ManagedKey{KeyID: keyID, Algorithm: crypto.RSA2048, Version: 2, State: "zeroized"}, nil
}

func (s *dualControlManagedKeyService) authorize(ctx context.Context, tenantID, keyID, action, requester string) error {
	toState := "active"
	switch action {
	case api.ManagedKeyActionRevoke:
		toState = "revoked"
	case api.ManagedKeyActionZeroize:
		toState = "zeroized"
	}
	_, approved, reason := s.checker.AuthorizeApproval(ctx, api.ApprovalIntent{
		TenantID: tenantID, ResourceKind: "managed_key", ResourceID: keyID,
		ResourceName: keyID, Action: action, Requester: requester,
		FromState: "active", ToState: toState, TargetVersion: 1,
		Reason:       "authorize one exact managed-key test command",
		EvidenceRefs: []string{"test-command:" + action}, RequiredApprovals: 2,
	})
	if !approved {
		return fmt.Errorf("%w: %s", api.ErrManagedKeyNotApproved, reason)
	}
	s.calls[action]++
	return nil
}

func TestManagedKeysServedThroughEditionFactory(t *testing.T) {
	var sawSpine bool
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ManagedKeyFactory = func(md ManagedKeyServiceDeps) (api.ManagedKeyService, error) {
			if md.Log == nil || md.Idempotency == nil {
				t.Fatal("managed-key factory did not receive event log and idempotency spine")
			}
			if md.ApprovalChecker == nil {
				t.Fatal("managed-key factory did not receive mandatory destructive-action dual control")
			}
			sawSpine = true
			return fakeManagedKeyService{}, nil
		}
	})
	if !sawSpine {
		t.Fatal("managed-key edition factory was not invoked")
	}
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "cloud-kms-operator", []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/managed-keys", token, "managed-key-seam-generate", map[string]string{
		"algorithm": string(crypto.RSA2048),
	})
	if code != http.StatusCreated {
		t.Fatalf("managed-key generate via factory = %d, want 201; body=%s", code, body)
	}
}

func TestManagedKeyDestructiveActionsRequireTwoServedDistinctApprovals(t *testing.T) {
	var service *dualControlManagedKeyService
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		// Even a weaker shared CA-policy value cannot reduce destructive managed-key
		// custody below the fixed two-person floor.
		d.RequiredApprovals = 1
		d.ManagedKeyFactory = func(md ManagedKeyServiceDeps) (api.ManagedKeyService, error) {
			if md.ApprovalChecker == nil {
				t.Fatal("managed-key factory did not receive the production approval checker")
			}
			service = &dualControlManagedKeyService{checker: md.ApprovalChecker, calls: map[string]int{}}
			return service, nil
		}
	})
	requester := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "managed-key-requester", []string{
		string(authz.KeysWrite), string(authz.KeysApprove),
	})
	approverOne := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "managed-key-custodian-one", []string{
		string(authz.KeysApprove),
	})
	approverTwo := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "managed-key-custodian-two", []string{
		string(authz.KeysApprove),
	})

	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/managed-keys", requester, "managed-key-dual-generate", map[string]string{
		"algorithm": string(crypto.RSA2048),
	})
	if status != http.StatusCreated {
		t.Fatalf("generate managed key = %d body=%s", status, body)
	}
	var key api.ManagedKey
	if err := json.Unmarshal(body, &key); err != nil {
		t.Fatalf("decode generated managed key: %v", err)
	}

	for _, action := range []struct {
		name      string
		path      string
		canonical string
		state     string
	}{
		{name: "rotate", path: "/api/v1/managed-keys/rotate", canonical: api.ManagedKeyActionRotate, state: "active"},
		{name: "revoke", path: "/api/v1/managed-keys/revoke", canonical: api.ManagedKeyActionRevoke, state: "revoked"},
		{name: "zeroize", path: "/api/v1/managed-keys/zeroize", canonical: api.ManagedKeyActionZeroize, state: "zeroized"},
	} {
		idempotencyKey := "managed-key-dual-" + action.name
		status, body = doBearer(t, h.ts, http.MethodPost, action.path, requester, idempotencyKey, map[string]string{"key_id": key.KeyID})
		if status != http.StatusForbidden {
			t.Fatalf("%s before approval = %d body=%s, want 403", action.name, status, body)
		}
		if service.calls[action.canonical] != 0 {
			t.Fatalf("%s reached provider before approval", action.name)
		}

		requests, err := h.store.ListOperationApprovals(context.Background(), h.tenant, store.ApprovalStatusPending, 100)
		if err != nil {
			t.Fatalf("list %s exact approval requests: %v", action.name, err)
		}
		var approval store.OperationApprovalRequest
		for _, candidate := range requests {
			if candidate.ResourceKind == "managed_key" && candidate.ResourceID == key.KeyID &&
				candidate.Action == action.canonical && candidate.Requester == "managed-key-requester" {
				approval = candidate
				break
			}
		}
		if approval.ID == "" || approval.IntentDigest == "" {
			t.Fatalf("requester attempt did not create a genuine %s approval request: %+v", action.name, requests)
		}
		approvalBody := map[string]string{
			"key_id": key.KeyID, "action": action.name,
			"request_id": approval.ID, "intent_digest": approval.IntentDigest,
		}
		status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/managed-keys/approvals", requester,
			idempotencyKey+"-self-approval", approvalBody)
		if status != http.StatusForbidden {
			t.Fatalf("%s requester self-approval = %d body=%s, want 403", action.name, status, body)
		}

		for index, token := range []string{approverOne, approverTwo} {
			status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/managed-keys/approvals", token,
				fmt.Sprintf("%s-approval-%d", idempotencyKey, index+1), approvalBody)
			if status != http.StatusOK {
				t.Fatalf("%s approval %d = %d body=%s", action.name, index+1, status, body)
			}
			var approval struct {
				Resource  string `json:"resource"`
				Action    string `json:"action"`
				Approvals int    `json:"approvals"`
			}
			if err := json.Unmarshal(body, &approval); err != nil {
				t.Fatalf("decode %s approval %d: %v", action.name, index+1, err)
			}
			if approval.Resource != key.KeyID || approval.Action != action.canonical || approval.Approvals != index+1 {
				t.Fatalf("%s approval %d = %+v", action.name, index+1, approval)
			}
			if index == 0 {
				status, body = doBearer(t, h.ts, http.MethodPost, action.path, requester, idempotencyKey, map[string]string{"key_id": key.KeyID})
				if status != http.StatusForbidden {
					t.Fatalf("%s after one approval = %d body=%s, want 403", action.name, status, body)
				}
				if service.calls[action.canonical] != 0 {
					t.Fatalf("%s reached provider after only one approval", action.name)
				}
			}
		}

		status, body = doBearer(t, h.ts, http.MethodPost, action.path, requester, idempotencyKey, map[string]string{"key_id": key.KeyID})
		if status != http.StatusOK {
			t.Fatalf("approved %s = %d body=%s", action.name, status, body)
		}
		if service.calls[action.canonical] != 1 {
			t.Fatalf("approved %s provider calls = %d, want 1", action.name, service.calls[action.canonical])
		}
		var result api.ManagedKey
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("decode %s result: %v", action.name, err)
		}
		if result.State != action.state {
			t.Fatalf("%s state = %q, want %q", action.name, result.State, action.state)
		}
		key = result
	}
}
