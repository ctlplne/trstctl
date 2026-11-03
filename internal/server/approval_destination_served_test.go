// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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

// A244: an issuance approval is granted for one destination and one issuer.
// It records the identity's deployment target, that target's configuration
// revision and the issuing authority; the change impact of the target names
// the identity and the open approval; editing the target supersedes the
// approval when it is decided, and a fresh request for the new revision is
// approved and used.
func TestServedChangedDestinationSupersedesTheIssuanceApprovalA244(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL/NATS; skipped in -short")
	}
	ctx := context.Background()
	st := newServerTestStore(t)
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const profileName = "a244-reviewed-destination"
	storeServerTestProfile(t, st, tenantID, profileName, profile.CertificateProfile{
		Name: profileName, RequiresApproval: true,
		MaxValidity: profile.Duration(6 * time.Hour), AllowedProtocols: []string{"api"},
	})
	owner, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantID, Kind: store.OwnerWorkload, Name: "a244-owner"})
	if err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	registerServerTestTenant(t, st, log, tenantID, "A244 destination approval tenant")
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
	code, body := call(http.MethodPost, "/api/v1/connectors/targets", "a244-target", map[string]any{
		"name": "a244/lb", "connector": "f5", "enabled": true,
		"config": map[string]any{"endpoint": "https://lb-a244.internal", "partition": "Common"},
	})
	if code != http.StatusCreated {
		t.Fatalf("create target: %d %s", code, body)
	}
	var target struct {
		ID         string `json:"id"`
		RevisionID string `json:"revision_id"`
	}
	if err := json.Unmarshal(body, &target); err != nil || target.ID == "" {
		t.Fatalf("decode target: %v %s", err, body)
	}
	identityID := createIdentityServed(t, ts, tenantID, owner.ID)
	if code, body := call(http.MethodPost, "/api/v1/identities/"+identityID+"/connector-target", "a244-bind", map[string]any{"target_id": target.ID}); code != http.StatusOK {
		t.Fatalf("bind identity to target: %d %s", code, body)
	}

	issue := func(key string) (int, []byte) {
		return call(http.MethodPost, "/api/v1/identities/"+identityID+"/transitions", key,
			map[string]string{"to": "issued", "reason": "a244 reviewed destination"})
	}
	if code, body := issue("a244-issue-1"); code != http.StatusForbidden {
		t.Fatalf("an approval-gated issue was not parked: %d %s", code, body)
	}
	pending, err := st.ListOperationApprovals(ctx, tenantID, store.ApprovalStatusPending, 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending approvals = (%d, %v)", len(pending), err)
	}
	first := pending[0]
	use, err := store.OperationApprovalUseFromRequest(first)
	if err != nil || use.Issuance == nil || use.Issuance.DestinationTargetID != target.ID || use.Issuance.DestinationRevision != target.RevisionID {
		t.Fatalf("the approval does not bind the destination: (%+v, %v)", use.Issuance, err)
	}

	// The change impact names what an edit to this target would reach.
	code, body = call(http.MethodGet, "/api/v1/connectors/targets/"+target.ID+"/impact", "", nil)
	if code != http.StatusOK || !strings.Contains(string(body), identityID) || !strings.Contains(string(body), first.ID) {
		t.Fatalf("target change impact: %d %s", code, body)
	}

	// Edit the destination: the open approval is superseded when it is decided.
	if code, body := call(http.MethodPut, "/api/v1/connectors/targets/"+target.ID, "a244-edit", map[string]any{
		"name": "a244/lb", "connector": "f5", "enabled": true,
		"config": map[string]any{"endpoint": "https://lb-a244.internal", "partition": "Edge"},
	}); code != http.StatusOK {
		t.Fatalf("edit target: %d %s", code, body)
	}
	_, err = srv.orch.RecordOperationApprovalDecision(ctx, tenantID, orchestrator.OperationApprovalDecision{
		RequestID: first.ID, IntentDigest: first.IntentDigest, Approver: "bob", Decision: store.ApprovalDecisionApprove,
	})
	if !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("approving after a destination change = %v, want drift", err)
	}
	if got, err := st.GetOperationApproval(ctx, tenantID, first.ID); err != nil || got.Status != store.ApprovalStatusSuperseded {
		t.Fatalf("the approval after a destination change = (%+v, %v), want superseded", got.Status, err)
	}

	// A fresh request binds the new revision and is approved and used.
	if code, body := issue("a244-issue-2"); code != http.StatusForbidden {
		t.Fatalf("the second issue was not parked: %d %s", code, body)
	}
	pending, err = st.ListOperationApprovals(ctx, tenantID, store.ApprovalStatusPending, 10)
	if err != nil || len(pending) != 1 || pending[0].ID == first.ID {
		t.Fatalf("pending approvals after the edit = (%d, %v)", len(pending), err)
	}
	second := pending[0]
	if _, err := srv.orch.RecordOperationApprovalDecision(ctx, tenantID, orchestrator.OperationApprovalDecision{
		RequestID: second.ID, IntentDigest: second.IntentDigest, Approver: "bob", Decision: store.ApprovalDecisionApprove,
	}); err != nil {
		t.Fatalf("approve the fresh request: %v", err)
	}
	if code, body := issue("a244-issue-2"); code != http.StatusOK {
		t.Fatalf("issue after approval for the current destination = %d %s", code, body)
	}
	if got, err := st.GetOperationApproval(ctx, tenantID, second.ID); err != nil || got.Status != store.ApprovalStatusConsumed {
		t.Fatalf("the fresh approval = (%+v, %v), want consumed", got.Status, err)
	}
}

// A245 Done-when: an old approval can't authorize a changed issuer, target or
// version. The target is A244's journey above; here an approval asked while
// the identity named no issuer (the platform CA) is superseded once the
// identity moves to another CA, and an approved request does not carry across
// a change of the identity's version.
func TestServedOldApprovalCannotAuthorizeAChangedIssuerOrVersionA245(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL/NATS; skipped in -short")
	}
	ctx := context.Background()
	st := newServerTestStore(t)
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const profileName = "a245-reviewed-issuer"
	storeServerTestProfile(t, st, tenantID, profileName, profile.CertificateProfile{
		Name: profileName, RequiresApproval: true,
		MaxValidity: profile.Duration(6 * time.Hour), AllowedProtocols: []string{"api"},
	})
	owner, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantID, Kind: store.OwnerWorkload, Name: "a245-owner"})
	if err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	registerServerTestTenant(t, st, log, tenantID, "A245 issuer and version approval tenant")
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
	code, body := call(http.MethodPost, "/api/v1/connectors/targets", "a245-target", map[string]any{
		"name": "a245/lb", "connector": "f5", "enabled": true,
		"config": map[string]any{"endpoint": "https://lb-a245.internal", "partition": "Common"},
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
	bindTarget := func(key string) {
		t.Helper()
		if code, body := call(http.MethodPost, "/api/v1/identities/"+identityID+"/connector-target", key, map[string]any{"target_id": targetRef.ID}); code != http.StatusOK {
			t.Fatalf("bind identity to target: %d %s", code, body)
		}
	}
	bindTarget("a245-bind")
	issue := func(key string) (int, []byte) {
		return call(http.MethodPost, "/api/v1/identities/"+identityID+"/transitions", key,
			map[string]string{"to": "issued", "reason": "a245 reviewed issuer"})
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

	// Issuer: asked under the platform CA (the identity names none) ...
	if code, body := issue("a245-issue-1"); code != http.StatusForbidden {
		t.Fatalf("an approval-gated issue was not parked: %d %s", code, body)
	}
	first := pendingOne("issuer")
	use, err := store.OperationApprovalUseFromRequest(first)
	if err != nil || use.Issuance == nil || use.Issuance.IssuerSource != store.PlatformIssuerSource || use.Issuance.IssuerID != store.PlatformIssuerID {
		t.Fatalf("the approval does not bind the platform CA: (%+v, %v)", use.Issuance, err)
	}
	// ... then the identity moves to another CA: the approval is superseded.
	target, err := st.GetDeploymentTarget(ctx, tenantID, targetRef.ID)
	if err != nil {
		t.Fatal(err)
	}
	reviewed, err := st.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		t.Fatal(err)
	}
	_, version, err := st.IdentityApprovalTarget(ctx, tenantID, identityID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.orch.BindIdentityEndpointAtVersion(ctx, tenantID, identityID, target,
		store.IdentityEndpointIssuer{OwnerID: owner.ID, Source: "external", ID: "a245-other-ca", Name: "Another CA",
			PreviewFingerprint: strings.Repeat("a", 64)}, &version, reviewed); err != nil {
		t.Fatalf("move the identity to another CA: %v", err)
	}
	if err := approve(first); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("approving after the issuer changed = %v, want drift", err)
	}
	if got, err := st.GetOperationApproval(ctx, tenantID, first.ID); err != nil || got.Status != store.ApprovalStatusSuperseded {
		t.Fatalf("the approval after an issuer change = (%+v, %v), want superseded", got.Status, err)
	}

	// Version: an approved request no longer authorizes once its profile moves
	// to a new version (the approval binds the version and its spec digest).
	if code, body := issue("a245-issue-2"); code != http.StatusForbidden {
		t.Fatalf("the second issue was not parked: %d %s", code, body)
	}
	second := pendingOne("version", first.ID)
	if err := approve(second); err != nil {
		t.Fatalf("approve the second request: %v", err)
	}
	storeServerTestProfile(t, st, tenantID, profileName, profile.CertificateProfile{
		Name: profileName, RequiresApproval: true,
		MaxValidity: profile.Duration(4 * time.Hour), AllowedProtocols: []string{"api"},
	})
	if code, body := issue("a245-issue-3"); code != http.StatusForbidden {
		t.Fatalf("an approval granted under the previous profile version authorized the issue: %d %s", code, body)
	}
	if got, err := st.GetOperationApproval(ctx, tenantID, second.ID); err != nil || got.Status == store.ApprovalStatusConsumed {
		t.Fatalf("the approval for the previous profile version = (%+v, %v), want unused", got.Status, err)
	}
	third := pendingOne("after the profile version", second.ID)
	secondUse, err1 := store.OperationApprovalUseFromRequest(second)
	thirdUse, err2 := store.OperationApprovalUseFromRequest(third)
	if err1 != nil || err2 != nil || secondUse.Issuance == nil || thirdUse.Issuance == nil ||
		thirdUse.Issuance.ProfileVersion == secondUse.Issuance.ProfileVersion {
		t.Fatalf("the fresh request binds profile version %+v, the old one %+v (%v %v)", thirdUse.Issuance, secondUse.Issuance, err1, err2)
	}
}
