// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

// A245-L5: a first issuance is the identity's first lifecycle transition, so
// its approval binds lifecycle version 0, and an edit of the identity's
// attributes never moves that version. An approval asked while the identity
// asked for the default subject key is superseded once the same destination
// and the same issuer are rebound with a post-quantum subject key algorithm
// and a new reviewed preview; the application view names the identity as what
// changed. An identity event that changes nothing the certificate carries (an
// ownership reassignment) leaves a fresh approval standing, and it is used.
func TestServedIssuanceApprovalBindsWhatTheIdentityContributesA245L5(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL/NATS; skipped in -short")
	}
	ctx := context.Background()
	st := newServerTestStore(t)
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const profileName = "a245l5-reviewed-identity"
	storeServerTestProfile(t, st, tenantID, profileName, profile.CertificateProfile{
		Name: profileName, RequiresApproval: true,
		MaxValidity: profile.Duration(6 * time.Hour), AllowedProtocols: []string{"api"},
	})
	owner, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantID, Kind: store.OwnerWorkload, Name: "a245l5-owner"})
	if err != nil {
		t.Fatal(err)
	}
	successor, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantID, Kind: store.OwnerWorkload, Name: "a245l5-successor"})
	if err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	registerServerTestTenant(t, st, log, tenantID, "A245-L5 identity approval tenant")
	srv, err := Build(ctx, Deps{
		Store: st, Log: log, DefaultProfile: profileName, RequiredApprovals: 1,
		APIOptions: []api.Option{api.WithInsecureHeaderResolver()},
	})
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	call := func(method, path, key string, body any) (int, []byte) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(raw))
		req.Header.Set("X-Tenant-ID", tenantID)
		req.Header.Set("X-Roles", "operator")
		req.Header.Set("X-Subject", "alice")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		return doReq(t, ts, req)
	}
	code, body := call(http.MethodPost, "/api/v1/connectors/targets", "a245l5-target", map[string]any{
		"name": "a245l5/lb", "connector": "f5", "enabled": true,
		"config": map[string]any{"endpoint": "https://lb-a245l5.internal", "partition": "Common"},
	})
	if code != http.StatusCreated {
		t.Fatalf("create target: %d %s", code, body)
	}
	var targetRef struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &targetRef); err != nil || targetRef.ID == "" {
		t.Fatalf("decode target: %v %s", err, body)
	}
	identityID := createIdentityServed(t, ts, tenantID, owner.ID)
	target, err := st.GetDeploymentTarget(ctx, tenantID, targetRef.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The reviewed endpoint binding: this target, the platform CA, the
	// default subject key.
	bind := func(algorithm, preview string) {
		t.Helper()
		reviewed, err := st.GetIdentity(ctx, tenantID, identityID)
		if err != nil {
			t.Fatal(err)
		}
		_, version, err := st.IdentityApprovalTarget(ctx, tenantID, identityID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := srv.orch.BindIdentityEndpointAtVersion(ctx, tenantID, identityID, target,
			store.IdentityEndpointIssuer{OwnerID: owner.ID, Source: store.PlatformIssuerSource, ID: store.PlatformIssuerID,
				Name: "trstctl issuing CA", SubjectKeyAlgorithm: algorithm, PreviewFingerprint: strings.Repeat(preview, 64)},
			&version, reviewed); err != nil {
			t.Fatalf("bind the endpoint (%q): %v", algorithm, err)
		}
	}
	bind("", "a")
	issue := func(key string) (int, []byte) {
		return call(http.MethodPost, "/api/v1/identities/"+identityID+"/transitions", key,
			map[string]string{"to": "issued", "reason": "a245l5 reviewed identity"})
	}
	pendingOne := func(stage string, not ...string) store.OperationApprovalRequest {
		t.Helper()
		pending, err := st.ListOperationApprovals(ctx, tenantID, store.ApprovalStatusPending, 10)
		if err != nil || len(pending) != 1 || (len(not) > 0 && pending[0].ID == not[0]) {
			t.Fatalf("%s: pending approvals = (%d, %v)", stage, len(pending), err)
		}
		return pending[0]
	}
	approve := func(request store.OperationApprovalRequest) error {
		_, err := srv.orch.RecordOperationApprovalDecision(ctx, tenantID, orchestrator.OperationApprovalDecision{
			RequestID: request.ID, IntentDigest: request.IntentDigest, Approver: "bob", Decision: store.ApprovalDecisionApprove,
		})
		return err
	}
	changedUnder := func(requestID string) []string {
		t.Helper()
		code, body := call(http.MethodGet, "/api/v1/identities/"+identityID+"/application", "", nil)
		if code != http.StatusOK {
			t.Fatalf("application view: %d %s", code, body)
		}
		var view struct {
			Approvals []struct {
				ID      string   `json:"id"`
				Changed []string `json:"changed"`
			} `json:"approvals"`
		}
		if err := json.Unmarshal(body, &view); err != nil {
			t.Fatalf("decode application view: %v %s", err, body)
		}
		for _, approval := range view.Approvals {
			if approval.ID == requestID {
				return approval.Changed
			}
		}
		t.Fatalf("the application view does not list approval %s: %s", requestID, body)
		return nil
	}

	// Asked for the default subject key ...
	if code, body := issue("a245l5-issue-1"); code != http.StatusForbidden {
		t.Fatalf("an approval-gated issue was not parked: %d %s", code, body)
	}
	first := pendingOne("asked")
	// ... then the same destination and the same CA are rebound with a
	// post-quantum subject key and a new reviewed preview. Neither the
	// destination nor the issuer binding moves, and nor does the lifecycle
	// version.
	bind("ML-DSA-65", "b")
	if got := changedUnder(first.ID); !slices.Equal(got, []string{"identity"}) {
		t.Fatalf("the application view names %v as changed under the approval, want [identity]", got)
	}
	if err := approve(first); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("approving after the identity's subject key changed = %v, want drift", err)
	}
	if got, err := st.GetOperationApproval(ctx, tenantID, first.ID); err != nil || got.Status != store.ApprovalStatusSuperseded {
		t.Fatalf("the approval after the subject key changed = (%+v, %v), want superseded", got.Status, err)
	}

	// A fresh request binds the identity as it is now. An ownership
	// reassignment changes nothing the certificate carries: the request is
	// approved and used.
	if code, body := issue("a245l5-issue-2"); code != http.StatusForbidden {
		t.Fatalf("the second issue was not parked: %d %s", code, body)
	}
	second := pendingOne("fresh", first.ID)
	if code, body := call(http.MethodPost, "/api/v1/ownership/assignments", "a245l5-assign", map[string]any{
		"owner_id": successor.ID, "inventory_ids": []string{"identity/" + identityID},
		"reason": "a245l5 the platform team takes the service over",
	}); code != http.StatusOK {
		t.Fatalf("reassign the identity's owner: %d %s", code, body)
	}
	if moved, err := st.GetIdentity(ctx, tenantID, identityID); err != nil || moved.OwnerID != successor.ID {
		t.Fatalf("the identity's owner after the reassignment = (%q, %v), want %s", moved.OwnerID, err, successor.ID)
	}
	if got := changedUnder(second.ID); len(got) != 0 {
		t.Fatalf("the application view names %v as changed after an ownership reassignment, want nothing", got)
	}
	if err := approve(second); err != nil {
		t.Fatalf("approve the fresh request after an ownership reassignment: %v", err)
	}
	if code, body := issue("a245l5-issue-2"); code != http.StatusOK {
		t.Fatalf("issue under the approval for the identity as it is = %d %s", code, body)
	}
	if got, err := st.GetOperationApproval(ctx, tenantID, second.ID); err != nil || got.Status != store.ApprovalStatusConsumed {
		t.Fatalf("the fresh approval = (%+v, %v), want consumed", got.Status, err)
	}
}
