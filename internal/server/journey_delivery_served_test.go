package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/protocols/ari"
)

// TestServedDeployAndRotationPublishReceipts is the JOURNEY-002 proof: the served
// issue->deploy->rotate path exposes connector delivery receipts and rotation-run
// status from real outbox work. On the pre-fix tree the connector delivery and
// lifecycle endpoints are 404s, deploy acks were invisible, and renewals did not
// queue a post-rotation connector.deploy receipt.
func TestServedDeployAndRotationPublishReceipts(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write",
		"identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "lifecycle:read",
	)

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload",
		"name": "journey-002-owner",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatalf("decode owner: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind":     "x509_certificate",
		"name":     "journey-002.served.test",
		"owner_id": owner.ID,
		"attributes": map[string]any{
			"connector": "nginx",
			"target":    "edge-1",
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity: status %d body %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatalf("decode identity: %v", err)
	}

	transition := func(to, reason string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
			"to":     to,
			"reason": reason,
		})
		if status != http.StatusOK {
			t.Fatalf("transition %s: status %d body %s", to, status, body)
		}
	}
	transition("issued", "journey-002 initial issue")
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain issue: %v", err)
	}
	transition("deployed", "journey-002 deploy")
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain deploy: %v", err)
	}

	first := connectorDeliveriesForIdentity(t, h, tok, ident.ID)
	if len(first.Items) != 1 {
		pending, perr := h.srv.outbox.Pending(t.Context(), h.tenant)
		if perr != nil {
			t.Fatalf("connector receipts after deploy = %d, want 1 (%s); pending outbox error: %v", len(first.Items), first.Raw, perr)
		}
		t.Fatalf("connector receipts after deploy = %d, want 1 (%s); pending outbox: %+v", len(first.Items), first.Raw, pending)
	}
	if got := first.Items[0]; got.Status != "unrouted" || got.Connector != "nginx" || got.Target != "edge-1" || got.Fingerprint == "" {
		t.Fatalf("bad deploy receipt: %+v", got)
	}

	queued, err := h.srv.RunLifecycleOnce(t.Context())
	if err != nil {
		t.Fatalf("run lifecycle scheduler: %v", err)
	}
	if queued != 1 {
		t.Fatalf("scheduled renewals = %d, want 1", queued)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain renewal: %v", err)
	}

	runs := rotationRunsForIdentity(t, h, tok, ident.ID)
	if len(runs.Items) != 1 {
		t.Fatalf("rotation runs = %d, want 1 (%s)", len(runs.Items), runs.Raw)
	}
	run := runs.Items[0]
	if run.Status != "succeeded" || run.Trigger != "scheduler" || run.PredecessorFingerprint == "" || run.SuccessorFingerprint == "" || run.RollbackRef == "" {
		t.Fatalf("bad rotation run: %+v", run)
	}

	afterRenew := connectorDeliveriesForIdentity(t, h, tok, ident.ID)
	if len(afterRenew.Items) != 2 {
		t.Fatalf("connector receipts after renewal = %d, want 2 (%s)", len(afterRenew.Items), afterRenew.Raw)
	}
	foundSuccessorReceipt := false
	for _, got := range afterRenew.Items {
		if got.Status != "unrouted" || got.Fingerprint == "" {
			t.Fatalf("bad deploy receipt after renewal: %+v", got)
		}
		if got.Fingerprint == run.SuccessorFingerprint {
			foundSuccessorReceipt = true
		}
	}
	if !foundSuccessorReceipt {
		t.Fatalf("no connector delivery receipt references renewal successor %s: %+v", run.SuccessorFingerprint, afterRenew.Items)
	}

	for _, eventType := range []string{"connector.delivery.recorded", "lifecycle.rotation.recorded"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event", eventType)
		}
	}
}

func TestServedLifecycleSchedulerUsesARIWindowForRenewal(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = time.Hour
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write",
		"identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "lifecycle:read",
	)

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload",
		"name": "clm-01-owner",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatalf("decode owner: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind":     "x509_certificate",
		"name":     "clm-01-ari-renew.served.test",
		"owner_id": owner.ID,
		"attributes": map[string]any{
			"connector": "nginx",
			"target":    "edge-ari",
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity: status %d body %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatalf("decode identity: %v", err)
	}

	transition := func(to, reason string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
			"to":     to,
			"reason": reason,
		})
		if status != http.StatusOK {
			t.Fatalf("transition %s: status %d body %s", to, status, body)
		}
	}
	transition("issued", "clm-01 initial issue")
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain issue: %v", err)
	}
	transition("deployed", "clm-01 deploy")
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain deploy: %v", err)
	}

	certs, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner.ID, "clm-01-ari-renew.served.test")
	if err != nil {
		t.Fatalf("load issued cert: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("issued certs = %d, want 1", len(certs))
	}
	predecessor := certs[0]
	now := time.Now().UTC()
	notBefore := now.Add(-20*24*time.Hour - time.Hour)
	notAfter := now.Add(10 * 24 * time.Hour)
	if !notAfter.After(now.Add(time.Hour)) {
		t.Fatalf("test setup invalid: fixed one-hour threshold would also renew not_after=%s", notAfter.Format(time.RFC3339))
	}
	window := ari.SuggestWindow(notBefore, notAfter, now, false)
	if !ari.RenewNow(ari.RenewalInfo{SuggestedWindow: window}, now) {
		t.Fatalf("test setup invalid: ARI window %s..%s is not due at %s", window.Start.Format(time.RFC3339), window.End.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	predecessor.NotBefore = &notBefore
	predecessor.NotAfter = &notAfter
	if _, err := h.srv.orch.RecordCertificate(t.Context(), h.tenant, predecessor); err != nil {
		t.Fatalf("record ARI validity window: %v", err)
	}

	queued, err := h.srv.RunLifecycleOnce(t.Context())
	if err != nil {
		t.Fatalf("run lifecycle scheduler: %v", err)
	}
	if queued != 1 {
		t.Fatalf("scheduled renewals = %d, want 1 from ARI window even though not_after=%s is outside the fixed one-hour threshold", queued, notAfter.Format(time.RFC3339))
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain ARI renewal: %v", err)
	}

	runs := rotationRunsForIdentity(t, h, tok, ident.ID)
	if len(runs.Items) != 1 {
		t.Fatalf("rotation runs = %d, want 1 (%s)", len(runs.Items), runs.Raw)
	}
	run := runs.Items[0]
	if run.Status != "succeeded" || run.Trigger != "scheduler" {
		t.Fatalf("bad ARI-driven rotation run: %+v", run)
	}
	if run.PredecessorFingerprint != predecessor.Fingerprint || run.SuccessorFingerprint == "" || run.SuccessorFingerprint == predecessor.Fingerprint {
		t.Fatalf("bad ARI-driven successor linkage: predecessor=%s run=%+v", predecessor.Fingerprint, run)
	}
}

func TestServedConnectorTargetJourneyJOURNEY001EndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write",
		"identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read",
	)

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
		"name":      "edge/prod/payments",
		"connector": "nginx",
		"config": map[string]any{
			"host":           "edge-1.internal",
			"credential_ref": "secret://connectors/nginx/edge-1",
			"reload":         "systemctl reload nginx",
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create connector target: status %d body %s", status, body)
	}
	var target struct {
		ID        string          `json:"id"`
		Connector string          `json:"connector"`
		Config    json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(body, &target); err != nil {
		t.Fatalf("decode connector target: %v", err)
	}
	if target.ID == "" || target.Connector != "nginx" || jsonContains(t, target.Config, "password") {
		t.Fatalf("bad target response: %+v body=%s", target, body)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload",
		"name": "journey-001-owner",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatalf("decode owner: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind":     "x509_certificate",
		"name":     "journey-001.served.test",
		"owner_id": owner.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity: status %d body %s", status, body)
	}
	var ident struct {
		ID         string          `json:"id"`
		Attributes json.RawMessage `json:"attributes"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatalf("decode identity: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/connector-target", tok, map[string]any{
		"target_id": target.ID,
	})
	if status != http.StatusOK {
		t.Fatalf("bind identity to target: status %d body %s", status, body)
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatalf("decode bound identity: %v", err)
	}
	if !jsonContains(t, ident.Attributes, target.ID) || !jsonContains(t, ident.Attributes, "edge/prod/payments") {
		t.Fatalf("bound identity attributes = %s, want connector target id and route", ident.Attributes)
	}

	transition := func(to, reason string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
			"to":     to,
			"reason": reason,
		})
		if status != http.StatusOK {
			t.Fatalf("transition %s: status %d body %s", to, status, body)
		}
	}
	transition("issued", "journey-001 issue after target binding")
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain issue: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets/"+target.ID+"/test", tok, nil)
	if status != http.StatusOK || !jsonContains(t, body, "test_succeeded") {
		t.Fatalf("test target: status %d body %s", status, body)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets/"+target.ID+"/deploy", tok, map[string]any{
		"identity_id": ident.ID,
		"reason":      "journey-001 deploy action",
	})
	if status != http.StatusOK || !jsonContains(t, body, `"status":"deployed"`) {
		t.Fatalf("deploy target action: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain deploy: %v", err)
	}
	first := connectorDeliveriesForIdentity(t, h, tok, ident.ID)
	if len(first.Items) != 1 || first.Items[0].Connector != "nginx" || first.Items[0].Target != "edge/prod/payments" || first.Items[0].Fingerprint == "" {
		t.Fatalf("delivery receipt after target deploy = %+v raw=%s", first.Items, first.Raw)
	}

	queued, err := h.srv.RunLifecycleOnce(t.Context())
	if err != nil {
		t.Fatalf("run lifecycle scheduler: %v", err)
	}
	if queued != 1 {
		t.Fatalf("scheduled renewals = %d, want 1", queued)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain renewal: %v", err)
	}
	runs := rotationRunsForIdentity(t, h, tok, ident.ID)
	if len(runs.Items) != 1 || runs.Items[0].SuccessorFingerprint == "" || runs.Items[0].RollbackRef == "" {
		t.Fatalf("rotation run after target deploy = %+v raw=%s", runs.Items, runs.Raw)
	}
	afterRenew := connectorDeliveriesForIdentity(t, h, tok, ident.ID)
	if len(afterRenew.Items) != 2 {
		t.Fatalf("delivery receipts after rotation = %d, want 2 (%s)", len(afterRenew.Items), afterRenew.Raw)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets/"+target.ID+"/rollback", tok, map[string]any{
		"identity_id": ident.ID,
		"reason":      "journey-001 rollback drill",
	})
	if status != http.StatusOK || !jsonContains(t, body, "rollback_recorded") {
		t.Fatalf("rollback target action: status %d body %s", status, body)
	}

	transition("revoked", "keyCompromise")
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain revoke: %v", err)
	}
	transition("retired", "journey-001 offboard target")
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain retire: %v", err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+ident.ID, tok, nil)
	if status != http.StatusOK || !jsonContains(t, body, `"status":"retired"`) {
		t.Fatalf("retired identity: status %d body %s", status, body)
	}

	for _, eventType := range []string{
		"deployment_target.upserted",
		"identity.connector_target_bound",
		"connector.delivery.recorded",
		"lifecycle.rotation.recorded",
		"identity.retired",
	} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event", eventType)
		}
	}
}

type connectorDeliveryList struct {
	Raw   []byte
	Items []struct {
		ID          string `json:"id"`
		IdentityID  string `json:"identity_id"`
		Connector   string `json:"connector"`
		Target      string `json:"target"`
		Fingerprint string `json:"fingerprint"`
		Status      string `json:"status"`
		Reason      string `json:"reason"`
		Detail      string `json:"detail"`
	} `json:"items"`
}

func jsonContains(t *testing.T, raw []byte, needle string) bool {
	t.Helper()
	return strings.Contains(string(raw), needle)
}

type rotationRunList struct {
	Raw   []byte
	Items []struct {
		ID                     string `json:"id"`
		IdentityID             string `json:"identity_id"`
		Status                 string `json:"status"`
		Trigger                string `json:"trigger"`
		PredecessorFingerprint string `json:"predecessor_fingerprint"`
		SuccessorFingerprint   string `json:"successor_fingerprint"`
		RollbackRef            string `json:"rollback_ref"`
	} `json:"items"`
}

func connectorDeliveriesForIdentity(t *testing.T, h *servedHarness, tok, identityID string) connectorDeliveryList {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/connectors/deliveries?identity_id="+identityID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list connector deliveries: status %d body %s", status, body)
	}
	var out connectorDeliveryList
	out.Raw = body
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode connector deliveries: %v (%s)", err, body)
	}
	return out
}

func rotationRunsForIdentity(t *testing.T, h *servedHarness, tok, identityID string) rotationRunList {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/lifecycle/rotation-runs?identity_id="+identityID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list rotation runs: status %d body %s", status, body)
	}
	var out rotationRunList
	out.Raw = body
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode rotation runs: %v (%s)", err, body)
	}
	return out
}
