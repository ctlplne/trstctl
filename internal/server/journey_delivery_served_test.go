// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/acm"
	"trstctl.com/trstctl/internal/connector/acm/acmtest"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/protocols/ari"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// TestEndpointBindingPinsExternalIssuerFromEffectFreePreview is DP-004's
// release oracle. The primary endpoint journey must name a configured CA before
// it can issue, bind execution to the exact effect-free preview, and route the
// real issuance through that CA. A dropdown without this server proof would be
// cosmetic: the old worker silently used the built-in CA regardless of UI.
func TestEndpointBindingPinsExternalIssuerFromEffectFreePreview(t *testing.T) {
	dc, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dc.Close)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
		d.ExternalCAs = []ExternalCA{{
			ID: "corporate-digicert", Type: "digicert", Name: "Corporate DigiCert",
			CA: digicert.New("corporate-digicert", dc.URL(), []byte(dc.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second})),
		}}
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read",
	)

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload", "name": "dp-004-owner",
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
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
		"name": "cloud/acm/dp-004", "connector": "aws-acm", "enabled": true,
		"config": map[string]any{
			"region": "us-east-1", "access_key_id": "AKIDTESTONLY",
			"secret_access_key_ref": "secret://connectors/aws-acm/dp-004",
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create target: status %d body %s", status, body)
	}
	var target struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &target); err != nil {
		t.Fatalf("decode target: %v", err)
	}

	request := map[string]any{
		"owner_id": owner.ID, "identity_name": "dp-004.served.test", "target_id": target.ID,
		"issuer": map[string]any{"source": "external", "id": "corporate-digicert"},
		"reason": "prove the selected CA reaches the destination",
	}
	beforeIdentities := eventCount(t, h.log, h.tenant, projections.EventIdentityCreated)
	beforeOutbox := connectorTargetOutboxRows(t, h)
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", tok, request)
	if status != http.StatusOK {
		t.Fatalf("preview endpoint binding: status %d body %s", status, body)
	}
	var preview struct {
		Ready              bool   `json:"ready"`
		EffectFree         bool   `json:"effect_free"`
		RequestFingerprint string `json:"request_fingerprint"`
		Issuer             struct {
			Source string `json:"source"`
			ID     string `json:"id"`
			Name   string `json:"name"`
		} `json:"issuer"`
		PreviewWrites          []string `json:"preview_writes"`
		PreviewExternalEffects []string `json:"preview_external_effects"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatalf("decode preview: %v body=%s", err, body)
	}
	if !preview.Ready || !preview.EffectFree || preview.RequestFingerprint == "" ||
		preview.Issuer.Source != "external" || preview.Issuer.ID != "corporate-digicert" || preview.Issuer.Name != "Corporate DigiCert" ||
		len(preview.PreviewWrites) != 0 || len(preview.PreviewExternalEffects) != 0 {
		t.Fatalf("preview did not bind exact external CA effect-free: %+v body=%s", preview, body)
	}
	if got := eventCount(t, h.log, h.tenant, projections.EventIdentityCreated); got != beforeIdentities {
		t.Fatalf("preview created identities: before=%d after=%d", beforeIdentities, got)
	}
	if got := connectorTargetOutboxRows(t, h); got != beforeOutbox {
		t.Fatalf("preview queued external work: before=%d after=%d", beforeOutbox, got)
	}

	// Execution cannot skip or reuse a stale preview.
	status, refusal := secretsReqKey(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", tok, "dp-004-no-preview", request)
	if status != http.StatusConflict || !jsonContains(t, refusal, "preview_fingerprint is required") ||
		eventCount(t, h.log, h.tenant, projections.EventIdentityCreated) != beforeIdentities {
		t.Fatalf("missing preview was not refused before mutation: status=%d body=%s", status, refusal)
	}
	request["preview_fingerprint"] = preview.RequestFingerprint
	stale := make(map[string]any, len(request))
	for key, value := range request {
		stale[key] = value
	}
	stale["reason"] = "a changed authorization after preview"
	status, refusal = secretsReqKey(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", tok, "dp-004-stale-preview", stale)
	if status != http.StatusConflict || !jsonContains(t, refusal, "changed after preview") ||
		eventCount(t, h.log, h.tenant, projections.EventIdentityCreated) != beforeIdentities {
		t.Fatalf("stale preview was not refused before mutation: status=%d body=%s", status, refusal)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", tok, "dp-004-bind", request)
	if status != http.StatusCreated {
		t.Fatalf("execute endpoint binding: status %d body %s", status, body)
	}
	var binding struct {
		Identity struct {
			ID string `json:"id"`
		} `json:"identity"`
		Issuer struct {
			Source string `json:"source"`
			ID     string `json:"id"`
		} `json:"issuer"`
	}
	if err := json.Unmarshal(body, &binding); err != nil || binding.Identity.ID == "" ||
		binding.Issuer.Source != "external" || binding.Issuer.ID != "corporate-digicert" {
		t.Fatalf("endpoint binding response lost issuer: err=%v got=%+v body=%s", err, binding, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain selected external CA issue and deploy: %v", err)
	}
	certs, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner.ID, "dp-004.served.test")
	if err != nil || len(certs) != 1 || !strings.Contains(strings.ToLower(certs[0].Issuer), "digicert") {
		var rows, inventory string
		_ = h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
			if err := tx.QueryRow(t.Context(), `SELECT COALESCE(string_agg(destination || ':' || status || ':' || COALESCE(last_error, ''), E'\n' ORDER BY id), '') FROM outbox WHERE tenant_id = $1`, h.tenant).Scan(&rows); err != nil {
				return err
			}
			return tx.QueryRow(t.Context(), `SELECT COALESCE(string_agg(subject || ':' || issuer || ':' || source, E'\n' ORDER BY created_at), '') FROM certificates WHERE tenant_id = $1`, h.tenant).Scan(&inventory)
		})
		t.Fatalf("endpoint did not retain external issuer: certs=%+v err=%v outbox=%s inventory=%s", certs, err, rows, inventory)
	}
	if got := externalCAIntentOutboxCount(t, h, "endpoint-binding:dp-004-bind:external-ca:corporate-digicert"); got != 1 {
		t.Fatalf("selected external CA intent rows = %d, want 1", got)
	}
	firstSerial := certs[0].Serial
	queued, err := h.srv.RunLifecycleOnce(t.Context())
	if err != nil || queued != 1 {
		t.Fatalf("schedule pinned external-CA renewal: queued=%d err=%v", queued, err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain pinned external-CA renewal: %v", err)
	}
	renewed, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner.ID, "dp-004.served.test")
	if err != nil || len(renewed) != 1 || renewed[0].Serial == firstSerial || !strings.Contains(strings.ToLower(renewed[0].Issuer), "digicert") {
		t.Fatalf("renewal did not preserve selected external issuer: first=%s renewed=%+v err=%v", firstSerial, renewed, err)
	}
	var externalIntents int
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'external-ca.issue'`, h.tenant).Scan(&externalIntents)
	}); err != nil || externalIntents != 2 {
		t.Fatalf("external CA issue intents after renewal = %d, want 2 (err=%v)", externalIntents, err)
	}
}

// The preview is the last safe point before issuance and deployment. A target
// that verifies one hostname cannot safely receive a certificate for another:
// the files may be replaced, but the listener proof will fail after the write.
func TestEndpointBindingPreviewRejectsTargetHostnameMismatchBeforeMutation(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		withAgentChannel(d)
		d.AgentClaimableJobKinds = []string{"endpoint.renew"}
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write",
		"certs:issue", "connectors:read", "connectors:write",
	)

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload", "name": "endpoint-hostname-preview-owner",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
		"name": "hostname-bound-apache", "connector": "apache", "enabled": true,
		"config": map[string]any{
			"cert_path": "/srv/tls/site.crt", "key_path": "/srv/tls/site.key", "required_agent_id": seedDestinationHost(t, h.store, h.tenant),
			"verify_address": "127.0.0.1:443", "verify_server_name": "payments.served.test",
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create target: status %d body %s", status, body)
	}
	var target struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &target); err != nil {
		t.Fatal(err)
	}

	beforeIdentities := eventCount(t, h.log, h.tenant, projections.EventIdentityCreated)
	beforeOutbox := connectorTargetOutboxRows(t, h)
	request := map[string]any{
		"owner_id": owner.ID, "identity_name": "other.served.test", "target_id": target.ID,
		"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"},
		"reason": "mismatch must stop before files are replaced",
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", tok, request)
	if status != http.StatusConflict || !jsonContains(t, body, "other.served.test") ||
		!jsonContains(t, body, "payments.served.test") || !jsonContains(t, body, "nothing was queued or changed") {
		t.Fatalf("hostname mismatch did not fail closed: status %d body %s", status, body)
	}
	if got := eventCount(t, h.log, h.tenant, projections.EventIdentityCreated); got != beforeIdentities {
		t.Fatalf("hostname mismatch created an identity: before=%d after=%d", beforeIdentities, got)
	}
	if got := connectorTargetOutboxRows(t, h); got != beforeOutbox {
		t.Fatalf("hostname mismatch queued external work: before=%d after=%d", beforeOutbox, got)
	}

	request["identity_name"] = "payments.served.test"
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", tok, request)
	if status != http.StatusOK || !jsonContains(t, body, `"ready":true`) {
		t.Fatalf("exact target hostname was not previewable: status %d body %s", status, body)
	}
}

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
			"connector": "aws-acm",
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
		if to == "deployed" && status == http.StatusConflict && strings.Contains(string(body), "deployed") {
			return
		}
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
	if got := first.Items[0]; got.Status != "failed" || got.Connector != "aws-acm" || got.Target != "edge-1" || got.Fingerprint == "" {
		t.Fatalf("bad deploy receipt: %+v", got)
	}

	active, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner.ID, "journey-002.served.test")
	if err != nil || len(active) != 1 || active[0].NotAfter == nil {
		t.Fatalf("load signed renewal predecessor: %+v %v", active, err)
	}
	queued, err := h.srv.runLifecycleOnceAt(t.Context(), active[0].NotAfter.Add(-12*time.Hour))
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
		if got.Status != "failed" || got.Fingerprint == "" {
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
	h := newServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	}, func(d *Deps) {
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
		if to == "deployed" && status == http.StatusConflict && strings.Contains(string(body), "deployed") {
			return
		}
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
	// Keep the real signed certificate unchanged. Evaluate its actual ARI
	// window later using only the scheduler's source-test clock.
	notBefore, notAfter := *predecessor.NotBefore, *predecessor.NotAfter
	window := ari.SuggestWindow(notBefore, notAfter, time.Now().UTC(), false)
	now := window.Start.Add(time.Second)
	if !notAfter.After(now.Add(time.Hour)) || !ari.RenewNow(ari.RenewalInfo{SuggestedWindow: window}, now) {
		t.Fatal("actual ARI window does not precede the fixed one-hour deadline")
	}

	before := ariPostureForTenant(t, h, tok)
	if before.PublicationStatus != "served" || before.SchedulerStatus != "enabled" {
		t.Fatalf("ARI runtime posture before renewal = publication:%q scheduler:%q, want served/enabled (%s)",
			before.PublicationStatus, before.SchedulerStatus, before.Raw)
	}
	beforeItem, ok := findARIPostureCertificate(before, predecessor.ID)
	if !ok {
		t.Fatalf("ARI posture does not contain deployed certificate %s before scheduling: %s", predecessor.ID, before.Raw)
	}
	if beforeItem.SchedulerConsumed {
		t.Fatalf("ARI window was marked consumed before the scheduler ran: %+v", beforeItem)
	}
	if !beforeItem.SuggestedWindow.Start.Equal(window.Start) || !beforeItem.SuggestedWindow.End.Equal(window.End) {
		t.Fatalf("served ARI window = %s..%s, want %s..%s",
			beforeItem.SuggestedWindow.Start.Format(time.RFC3339Nano),
			beforeItem.SuggestedWindow.End.Format(time.RFC3339Nano),
			window.Start.Format(time.RFC3339Nano),
			window.End.Format(time.RFC3339Nano))
	}

	queued, err := h.srv.runLifecycleOnceAt(t.Context(), now)
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

	after := ariPostureForTenant(t, h, tok)
	afterItem, ok := findARIPostureCertificate(after, predecessor.ID)
	if !ok {
		t.Fatalf("ARI posture lost consumed predecessor %s: %s", predecessor.ID, after.Raw)
	}
	if !afterItem.SchedulerConsumed || afterItem.RotationRunID != run.ID || afterItem.SchedulerStatus != "succeeded" {
		t.Fatalf("ARI scheduler-consumption evidence = %+v, want consumed run %s succeeded", afterItem, run.ID)
	}
	if !afterItem.SuggestedWindow.Start.Equal(beforeItem.SuggestedWindow.Start) ||
		!afterItem.SuggestedWindow.End.Equal(beforeItem.SuggestedWindow.End) {
		t.Fatalf("ARI window changed after scheduler consumption: before=%+v after=%+v", beforeItem.SuggestedWindow, afterItem.SuggestedWindow)
	}

	const tenantB = "22222222-2222-2222-2222-222222222222"
	if _, err := h.store.CreateOwner(context.Background(), store.Owner{
		TenantID: tenantB, Kind: store.OwnerWorkload, Name: "ari-posture-tenant-b",
	}); err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}
	tenantBToken := seedScopedToken(t, h.store, tenantB, "lifecycle:read")
	tenantBPosture := ariPostureForTenant(t, h, tenantBToken)
	if tenantBPosture.PublicationStatus != "not_served" {
		t.Fatalf("tenant B publication posture = %q, want not_served because ACME is bound to tenant A", tenantBPosture.PublicationStatus)
	}
	if len(tenantBPosture.Items) != 0 ||
		strings.Contains(string(tenantBPosture.Raw), predecessor.ID) ||
		strings.Contains(string(tenantBPosture.Raw), predecessor.Fingerprint) {
		t.Fatalf("tenant B read tenant A ARI evidence: %s", tenantBPosture.Raw)
	}
}

func TestServedWildcardIdentityRequiresAcknowledgementAndRenewsTRACE017(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write",
		"identities:read", "identities:write",
		"certs:read", "certs:issue", "lifecycle:read",
	)

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload",
		"name": "trace017-owner",
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
		"name":     "*.missing-ack.trace017.test",
		"owner_id": owner.ID,
	})
	if status != http.StatusBadRequest {
		t.Fatalf("wildcard identity without blast-radius acknowledgment: status %d body %s, want 400", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind":     "x509_certificate",
		"name":     "*.http.trace017.test",
		"owner_id": owner.ID,
		"attributes": map[string]any{
			"wildcard_blast_radius_acknowledged": true,
			"validation_method":                  "http-01",
		},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("wildcard identity with non-DNS validation method: status %d body %s, want 400", status, body)
	}

	const wildcardName = "*.trace017.test"
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind":     "x509_certificate",
		"name":     wildcardName,
		"owner_id": owner.ID,
		"attributes": map[string]any{
			"wildcard_blast_radius_acknowledged": true,
			"validation_method":                  "dns-01",
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create acknowledged wildcard identity: status %d body %s", status, body)
	}
	var ident struct {
		ID         string          `json:"id"`
		Attributes json.RawMessage `json:"attributes"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatalf("decode wildcard identity: %v", err)
	}
	if ident.ID == "" || !jsonContains(t, ident.Attributes, "wildcard_blast_radius_acknowledged") || !jsonContains(t, ident.Attributes, "dns-01") {
		t.Fatalf("wildcard identity response lost acknowledgment/DNS-01 attributes: %s", ident.Attributes)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
		"to":     "issued",
		"reason": "TRACE-017 wildcard issuance",
	})
	if status != http.StatusOK {
		t.Fatalf("issue wildcard identity: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain wildcard issue: %v", err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
		"to":     "deployed",
		"reason": "TRACE-017 wildcard deployed for renewal",
	})
	if status != http.StatusOK {
		t.Fatalf("deploy wildcard identity: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain wildcard deploy: %v", err)
	}
	certs, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner.ID, wildcardName)
	if err != nil {
		t.Fatalf("load wildcard certificate: %v", err)
	}
	if len(certs) != 1 || !containsString(certs[0].SANs, wildcardName) {
		t.Fatalf("issued wildcard certs = %+v, want one active cert retaining %s SAN", certs, wildcardName)
	}
	predecessor := certs[0]
	if predecessor.NotBefore == nil || predecessor.NotAfter == nil {
		t.Fatal("wildcard certificate lacks signed validity")
	}
	// Evaluate the actual leaf near expiry without rewriting its signed dates.
	queued, err := h.srv.runLifecycleOnceAt(t.Context(), predecessor.NotAfter.Add(-12*time.Hour))
	if err != nil {
		t.Fatalf("run wildcard lifecycle scheduler: %v", err)
	}
	if queued != 1 {
		t.Fatalf("scheduled wildcard renewals = %d, want 1", queued)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain wildcard renewal: %v", err)
	}
	runs := rotationRunsForIdentity(t, h, tok, ident.ID)
	if len(runs.Items) != 1 {
		t.Fatalf("wildcard rotation runs = %d, want 1 (%s)", len(runs.Items), runs.Raw)
	}
	run := runs.Items[0]
	if run.Status != "succeeded" || run.Trigger != "scheduler" || run.PredecessorFingerprint != predecessor.Fingerprint || run.SuccessorFingerprint == "" {
		t.Fatalf("bad wildcard renewal run: %+v", run)
	}
	renewed, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner.ID, wildcardName)
	if err != nil {
		t.Fatalf("load renewed wildcard certificate: %v", err)
	}
	if len(renewed) != 1 || !containsString(renewed[0].SANs, wildcardName) || renewed[0].Fingerprint != run.SuccessorFingerprint {
		t.Fatalf("renewed wildcard cert = %+v, want active successor %s retaining wildcard SAN", renewed, run.SuccessorFingerprint)
	}
	if !h.hasEvent(t, "lifecycle.rotation.recorded") {
		t.Fatal("wildcard renewal did not append lifecycle.rotation.recorded evidence")
	}
}

func TestServedConnectorTargetJourneyJOURNEY001EndToEnd(t *testing.T) {
	const (
		awsAccessKey = "AKIDJOURNEY001"
		awsSecretKey = "JOURNEY001SecretKeyForSigV4Only" // #nosec G101 -- fabricated test-only credential (CWE-798)
		acmARN       = "arn:aws:acm:us-east-1:123456789012:certificate/journey-001"
	)
	provider := acmtest.New(awsAccessKey, awsSecretKey)
	t.Cleanup(provider.Close)
	registry := connector.NewRegistry(func(string) connector.Ops {
		return connector.NewHTTPOps(provider.Client())
	})
	registry.Register(acm.New("us-east-1", acm.Credentials{
		AccessKeyID: awsAccessKey, SecretAccessKey: []byte(awsSecretKey),
	}, acm.WithEndpoint(provider.URL())))
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
		d.ConnectorRegistry = registry
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write",
		"identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read",
	)

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
		"name":      acmARN,
		"connector": "aws-acm",
		"config": map[string]any{
			"region":                "us-east-1",
			"access_key_id":         awsAccessKey,
			"secret_access_key_ref": "secret://connectors/aws-acm/access-key",
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
	if target.ID == "" || target.Connector != "aws-acm" || jsonContains(t, target.Config, "password") {
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
	if !jsonContains(t, ident.Attributes, target.ID) || !jsonContains(t, ident.Attributes, acmARN) {
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

	// A control-plane cloud target queues an effect-free provider preview. The
	// request itself still contacts nothing; only the bounded outbox worker may
	// perform the authenticated read-only operation.
	writesBeforePreview := provider.Calls()
	previewsBefore := provider.PreviewCalls()
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets/"+target.ID+"/test", tok, nil)
	if status != http.StatusAccepted || !jsonContains(t, body, servedstatus.ConnectorTestQueued) {
		t.Fatalf("test target: status %d body %s", status, body)
	}
	if provider.Calls() != writesBeforePreview || provider.PreviewCalls() != previewsBefore {
		t.Fatal("target-test request handler contacted the ACM provider")
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain target preview: %v", err)
	}
	if provider.Calls() != writesBeforePreview || provider.PreviewCalls() != previewsBefore+1 {
		t.Fatalf("provider calls after target preview = writes:%d previews:%d, want %d/%d",
			provider.Calls(), provider.PreviewCalls(), writesBeforePreview, previewsBefore+1)
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
	if len(first.Items) != 1 || first.Items[0].Status != "delivered" || first.Items[0].Connector != "aws-acm" || first.Items[0].Target != acmARN || first.Items[0].Fingerprint == "" {
		t.Fatalf("delivery receipt after target deploy = %+v raw=%s", first.Items, first.Raw)
	}

	servedLeaf, err := h.store.GetCertificateByFingerprint(t.Context(), h.tenant, first.Items[0].Fingerprint)
	if err != nil || servedLeaf.NotAfter == nil {
		t.Fatalf("load delivered signed leaf: %+v %v", servedLeaf, err)
	}
	queued, err := h.srv.runLifecycleOnceAt(t.Context(), servedLeaf.NotAfter.Add(-12*time.Hour))
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
	for _, receipt := range afterRenew.Items {
		if receipt.Status != "delivered" {
			t.Fatalf("successful connector journey recorded a non-delivered receipt: %+v", receipt)
		}
	}
	if provider.Calls() != 2 {
		t.Fatalf("ACM imports after deploy and rotation = %d, want 2", provider.Calls())
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets/"+target.ID+"/rollback", tok, map[string]any{
		"identity_id": ident.ID,
		"reason":      "journey-001 rollback drill",
	})
	if status != http.StatusConflict || jsonContains(t, body, "rollback_recorded") ||
		!jsonContains(t, body, "no executable rollback route") {
		t.Fatalf("unsupported rollback was not honestly refused: status %d body %s", status, body)
	}
	afterRefusal := connectorDeliveriesForIdentity(t, h, tok, ident.ID)
	if len(afterRefusal.Items) != len(afterRenew.Items) {
		t.Fatalf("unsupported rollback wrote a rollback-shaped receipt: before=%d after=%d raw=%s",
			len(afterRenew.Items), len(afterRefusal.Items), afterRefusal.Raw)
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

func TestServedEndpointBindingAutomationCAPLIFE01(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write",
		"identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read",
	)

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload",
		"name": "cap-life-01-owner",
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

	bindingRequest := previewPlatformEndpointBinding(t, h, tok, map[string]any{
		"owner_id":      owner.ID,
		"identity_name": "cap-life-01.served.test",
		"reason":        "CAP-LIFE-01 endpoint lifecycle automation",
		"target": map[string]any{
			"name":      "cloud/acm/cap-life-01",
			"connector": "aws-acm",
			"config": map[string]any{
				"region":                "us-east-1",
				"access_key_id":         "AKIDTESTONLY",
				"secret_access_key_ref": "secret://connectors/aws-acm/access-key",
			},
		},
	})
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", tok, "cap-life-01-bind", bindingRequest)
	if status != http.StatusCreated {
		t.Fatalf("create endpoint binding automation: status %d body %s", status, body)
	}
	var binding struct {
		Identity struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"identity"`
		Target struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Connector string `json:"connector"`
		} `json:"target"`
		Queued        []string `json:"queued_lifecycle_intents"`
		RenewalIntent string   `json:"renewal_intent"`
	}
	if err := json.Unmarshal(body, &binding); err != nil {
		t.Fatalf("decode endpoint binding: %v (%s)", err, body)
	}
	if binding.Identity.ID == "" || binding.Identity.Status != "issued" {
		t.Fatalf("binding identity = %+v, want issued before outbox deployment", binding.Identity)
	}
	if binding.Target.ID == "" || binding.Target.Name != "cloud/acm/cap-life-01" || binding.Target.Connector != "aws-acm" {
		t.Fatalf("binding target = %+v", binding.Target)
	}
	for _, want := range []string{"ca.issue", "connector.deploy"} {
		if !containsLifecycleIntent(binding.Queued, want) {
			t.Fatalf("queued intents = %+v, missing %s", binding.Queued, want)
		}
	}
	if binding.RenewalIntent != "ca.renew" {
		t.Fatalf("renewal_intent = %q, want ca.renew", binding.RenewalIntent)
	}

	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain initial issue/deploy: %v", err)
	}
	certs, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner.ID, "cap-life-01.served.test")
	if err != nil {
		t.Fatalf("load issued certs: %v", err)
	}
	if len(certs) != 1 || certs[0].Fingerprint == "" {
		t.Fatalf("issued certs after endpoint binding = %+v", certs)
	}
	first := connectorDeliveriesForIdentity(t, h, tok, binding.Identity.ID)
	if len(first.Items) != 1 || first.Items[0].Connector != "aws-acm" || first.Items[0].Target != "cloud/acm/cap-life-01" || first.Items[0].Fingerprint != certs[0].Fingerprint {
		t.Fatalf("initial delivery receipt = %+v raw=%s cert=%s", first.Items, first.Raw, certs[0].Fingerprint)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+binding.Identity.ID, tok, nil)
	if status != http.StatusOK || !jsonContains(t, body, `"status":"deployed"`) {
		t.Fatalf("deployed identity after endpoint binding drain: status %d body %s", status, body)
	}

	if certs[0].NotAfter == nil {
		t.Fatal("endpoint certificate lacks signed expiry")
	}
	queued, err := h.srv.runLifecycleOnceAt(t.Context(), certs[0].NotAfter.Add(-12*time.Hour))
	if err != nil {
		t.Fatalf("run lifecycle scheduler: %v", err)
	}
	if queued != 1 {
		t.Fatalf("scheduled renewals = %d, want 1", queued)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain renewal/deploy: %v", err)
	}
	runs := rotationRunsForIdentity(t, h, tok, binding.Identity.ID)
	if len(runs.Items) != 1 || runs.Items[0].Status != "succeeded" || runs.Items[0].SuccessorFingerprint == "" || runs.Items[0].RollbackRef == "" {
		t.Fatalf("rotation run = %+v raw=%s", runs.Items, runs.Raw)
	}
	afterRenew := connectorDeliveriesForIdentity(t, h, tok, binding.Identity.ID)
	if len(afterRenew.Items) != 2 {
		t.Fatalf("delivery receipts after renewal = %d, want 2 (%s)", len(afterRenew.Items), afterRenew.Raw)
	}
	if !deliveryFingerprintsContain(afterRenew, runs.Items[0].SuccessorFingerprint) {
		t.Fatalf("no delivery receipt binds renewal successor %s: %+v", runs.Items[0].SuccessorFingerprint, afterRenew.Items)
	}

	for _, eventType := range []string{
		"deployment_target.upserted",
		"identity.created",
		"identity.connector_target_bound",
		"identity.issued",
		"identity.deployed",
		"connector.delivery.recorded",
		"lifecycle.rotation.recorded",
	} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event", eventType)
		}
	}
}

// TestDisabledConnectorTargetRefusesEveryLifecycleMutation is the fail-closed
// contract for prepared destinations. A target may be recorded before its
// agent, relay, endpoint, and rollback path are independently verified, but it
// must be inert until an operator explicitly enables it. Refusal happens before
// an identity is bound or created and before any external-call intent exists.
func TestDisabledConnectorTargetRefusesEveryLifecycleMutation(t *testing.T) {
	role := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	h := role.servedHarness
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write",
		"identities:read", "identities:write",
		"connectors:read", "connectors:write", "certs:issue",
	)

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload", "name": "prepared-target-owner",
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
		"kind": "x509_certificate", "name": "prepared-target.served.test", "owner_id": owner.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity: status %d body %s", status, body)
	}
	var identity struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &identity); err != nil {
		t.Fatalf("decode identity: %v", err)
	}

	targetRequest := map[string]any{
		"name":      "prepared/apache/payments",
		"connector": "apache",
		"enabled":   false,
		"config": map[string]any{
			"credential_ref": "secret://connectors/apache/payments",
			"proof_state":    "prepared_not_contacted",
		},
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, targetRequest)
	if status != http.StatusCreated || !jsonContains(t, body, `"enabled":false`) {
		t.Fatalf("create disabled target: status %d body %s", status, body)
	}
	var target struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(body, &target); err != nil {
		t.Fatalf("decode disabled target: %v (%s)", err, body)
	}
	if target.ID == "" || target.Enabled {
		t.Fatalf("disabled target response = %+v", target)
	}

	// An older client that edits name/config without the new field must not
	// accidentally arm a target that an operator deliberately disabled.
	status, body = secretsReq(t, h, http.MethodPut, "/api/v1/connectors/targets/"+target.ID, tok, map[string]any{
		"name":      "prepared/apache/payments",
		"connector": "apache",
		"config": map[string]any{
			"credential_ref": "secret://connectors/apache/payments",
			"proof_state":    "prepared_not_contacted",
			"note":           "edited by a client that predates readiness",
		},
	})
	if status != http.StatusOK || !jsonContains(t, body, `"enabled":false`) {
		t.Fatalf("legacy-shaped update re-enabled target: status %d body %s", status, body)
	}

	beforeOutbox := connectorTargetOutboxRows(t, h)
	blocked := []struct {
		name string
		path string
		body any
	}{
		{name: "bind", path: "/api/v1/identities/" + identity.ID + "/connector-target", body: map[string]any{"target_id": target.ID}},
		{name: "test", path: "/api/v1/connectors/targets/" + target.ID + "/test", body: nil},
		{name: "deploy", path: "/api/v1/connectors/targets/" + target.ID + "/deploy", body: map[string]any{"identity_id": identity.ID, "reason": "disabled target negative control"}},
		{name: "rollback", path: "/api/v1/connectors/targets/" + target.ID + "/rollback", body: map[string]any{"identity_id": identity.ID, "reason": "disabled target negative control"}},
		{name: "existing endpoint binding", path: "/api/v1/lifecycle/endpoint-bindings", body: map[string]any{
			"owner_id": owner.ID, "identity_name": "must-not-exist.served.test", "target_id": target.ID, "reason": "disabled target negative control",
			"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"},
		}},
		{name: "inline endpoint binding", path: "/api/v1/lifecycle/endpoint-bindings", body: map[string]any{
			"owner_id": owner.ID, "identity_name": "inline-must-not-exist.served.test", "reason": "disabled target negative control",
			"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"},
			"target": map[string]any{
				"name": "prepared/iis/portal", "connector": "iis", "enabled": false,
				"config": map[string]any{"credential_ref": "secret://connectors/iis/portal", "proof_state": "prepared_not_contacted"},
			},
		}},
	}
	for _, tc := range blocked {
		t.Run(tc.name, func(t *testing.T) {
			status, response := secretsReq(t, h, http.MethodPost, tc.path, tok, tc.body)
			if status != http.StatusConflict || !jsonContains(t, response, "deployment target is disabled") ||
				!jsonContains(t, response, "nothing was queued") {
				t.Fatalf("disabled target action was not refused before mutation: status %d body %s", status, response)
			}
		})
	}

	if got := eventCount(t, h.log, h.tenant, projections.EventIdentityConnectorTargetBound); got != 0 {
		t.Fatalf("disabled target emitted %d identity binding events, want 0", got)
	}
	if got := eventCount(t, h.log, h.tenant, projections.EventConnectorDeliveryRecorded); got != 0 {
		t.Fatalf("disabled target emitted %d delivery events, want 0", got)
	}
	if got := eventCount(t, h.log, h.tenant, projections.EventIdentityIssued); got != 0 {
		t.Fatalf("disabled target emitted %d issuance transitions, want 0", got)
	}
	if got := eventCount(t, h.log, h.tenant, projections.EventIdentityCreated); got != 1 {
		t.Fatalf("disabled endpoint binding created identities: identity.created=%d, want original 1", got)
	}
	if got := connectorTargetOutboxRows(t, h); got != beforeOutbox {
		t.Fatalf("disabled target queued external work: outbox before=%d after=%d", beforeOutbox, got)
	}
	storedIdentity, err := h.store.GetIdentity(t.Context(), h.tenant, identity.ID)
	if err != nil {
		t.Fatalf("load identity after refusals: %v", err)
	}
	if storedIdentity.Status != "requested" || jsonContains(t, storedIdentity.Attributes, target.ID) {
		t.Fatalf("disabled target changed identity = status %q attributes %s", storedIdentity.Status, storedIdentity.Attributes)
	}
	targets, err := h.store.ListDeploymentTargets(t.Context(), h.tenant)
	if err != nil {
		t.Fatalf("list targets after inline refusal: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("disabled inline endpoint binding created a target: got %d targets, want 1", len(targets))
	}

	// The readiness transition is deliberate and auditable. Once enabled, the
	// same server route can bind the identity normally.
	targetConfig := targetRequest["config"].(map[string]any)
	targetConfig["required_agent_id"] = registeredRoleAgentID(t, role)
	targetConfig["required_agent_role"] = mtls.AgentRoleHost
	targetConfig["executor"] = "agent"
	targetRequest["enabled"] = true
	status, body = secretsReq(t, h, http.MethodPut, "/api/v1/connectors/targets/"+target.ID, tok, targetRequest)
	if status != http.StatusOK || !jsonContains(t, body, `"enabled":true`) {
		t.Fatalf("enable target: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+identity.ID+"/connector-target", tok, map[string]any{
		"target_id": target.ID,
	})
	if status != http.StatusOK || !jsonContains(t, body, target.ID) {
		t.Fatalf("bind explicitly enabled target: status %d body %s", status, body)
	}

	// The browser exposes intended-connector guidance, but API and CLI callers
	// must receive the same fail-closed contract. A client cannot route an IIS
	// identity to an Apache destination by bypassing the GUI.
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind": "x509_certificate", "name": "iis-only.served.test", "owner_id": owner.ID,
		"attributes": map[string]any{"intended_connector": "iis"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create connector-constrained identity: status %d body %s", status, body)
	}
	var constrainedIdentity struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &constrainedIdentity); err != nil {
		t.Fatalf("decode connector-constrained identity: %v (%s)", err, body)
	}
	beforeBound := eventCount(t, h.log, h.tenant, projections.EventIdentityConnectorTargetBound)
	beforeDeliveries := eventCount(t, h.log, h.tenant, projections.EventConnectorDeliveryRecorded)
	beforeOutbox = connectorTargetOutboxRows(t, h)
	for _, tc := range []struct {
		name string
		path string
		body any
	}{
		{name: "bind", path: "/api/v1/identities/" + constrainedIdentity.ID + "/connector-target", body: map[string]any{"target_id": target.ID}},
		{name: "deploy", path: "/api/v1/connectors/targets/" + target.ID + "/deploy", body: map[string]any{"identity_id": constrainedIdentity.ID, "reason": "mismatch negative control"}},
		{name: "rollback", path: "/api/v1/connectors/targets/" + target.ID + "/rollback", body: map[string]any{"identity_id": constrainedIdentity.ID, "reason": "mismatch negative control"}},
	} {
		t.Run("connector mismatch "+tc.name, func(t *testing.T) {
			status, response := secretsReq(t, h, http.MethodPost, tc.path, tok, tc.body)
			if status != http.StatusConflict || !jsonContains(t, response, "intended for iis") ||
				!jsonContains(t, response, "uses apache") || !jsonContains(t, response, "nothing was queued") {
				t.Fatalf("connector mismatch did not fail closed: status %d body %s", status, response)
			}
		})
	}
	if got := eventCount(t, h.log, h.tenant, projections.EventIdentityConnectorTargetBound); got != beforeBound {
		t.Fatalf("connector mismatch emitted binding event: before=%d after=%d", beforeBound, got)
	}
	if got := eventCount(t, h.log, h.tenant, projections.EventConnectorDeliveryRecorded); got != beforeDeliveries {
		t.Fatalf("connector mismatch emitted delivery event: before=%d after=%d", beforeDeliveries, got)
	}
	if got := connectorTargetOutboxRows(t, h); got != beforeOutbox {
		t.Fatalf("connector mismatch queued external work: before=%d after=%d", beforeOutbox, got)
	}
	storedConstrained, err := h.store.GetIdentity(t.Context(), h.tenant, constrainedIdentity.ID)
	if err != nil {
		t.Fatalf("load connector-constrained identity: %v", err)
	}
	if storedConstrained.Status != "requested" || jsonContains(t, storedConstrained.Attributes, target.ID) {
		t.Fatalf("connector mismatch changed identity = status %q attributes %s", storedConstrained.Status, storedConstrained.Attributes)
	}
}

func connectorTargetOutboxRows(t *testing.T, h *servedHarness) int {
	t.Helper()
	count := 0
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM outbox WHERE tenant_id = $1`, h.tenant).Scan(&count)
	}); err != nil {
		t.Fatalf("count connector target outbox rows: %v", err)
	}
	return count
}

func previewPlatformEndpointBinding(t *testing.T, h *servedHarness, token string, request map[string]any) map[string]any {
	t.Helper()
	request["issuer"] = map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", token, request)
	if status != http.StatusOK {
		t.Fatalf("preview platform endpoint binding: status %d body %s", status, body)
	}
	var preview struct {
		RequestFingerprint string `json:"request_fingerprint"`
	}
	if err := json.Unmarshal(body, &preview); err != nil || preview.RequestFingerprint == "" {
		t.Fatalf("decode platform endpoint preview: err=%v body=%s", err, body)
	}
	request["preview_fingerprint"] = preview.RequestFingerprint
	return request
}

// A private key exists only while issuance builds the sealed connector effect.
// An already-issued record cannot be pushed later by inventing a keyless
// lifecycle transition and claiming that "deployed" means external success.
func TestIssuedConnectorTargetDeployFailsClosedWithoutCredentialMaterial(t *testing.T) {
	role := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	h := role.servedHarness
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write", "certs:issue", "connectors:read", "connectors:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload", "name": "issued-deploy-refusal-owner",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind": "x509_certificate", "name": "issued-deploy-refusal.served.test", "owner_id": owner.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity: status %d body %s", status, body)
	}
	var identity struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &identity); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
		"name": "issued-deploy-refusal-target", "connector": "apache", "enabled": true,
		"config": map[string]any{"profile": "apache", "cert_path": "/srv/tls/site.crt", "key_path": "/srv/tls/site.key",
			"executor": "agent", "required_agent_role": mtls.AgentRoleHost, "required_agent_id": registeredRoleAgentID(t, role)},
	})
	if status != http.StatusCreated {
		t.Fatalf("create target: status %d body %s", status, body)
	}
	var target struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &target); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+identity.ID+"/connector-target", tok, map[string]any{"target_id": target.ID})
	if status != http.StatusOK {
		t.Fatalf("bind target: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+identity.ID+"/transitions", tok, map[string]any{
		"to": "issued", "reason": "fixture stops before the credential-bearing issuer runs",
	})
	if status != http.StatusOK {
		t.Fatalf("mark issued fixture: status %d body %s", status, body)
	}

	beforeOutbox := connectorTargetOutboxRows(t, h)
	beforeBindings := eventCount(t, h.log, h.tenant, projections.EventIdentityConnectorTargetBound)
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets/"+target.ID+"/deploy", tok, map[string]any{
		"identity_id": identity.ID, "reason": "must not create a keyless deployment",
	})
	if status != http.StatusConflict || !jsonContains(t, body, "does not retain the private key") || !jsonContains(t, body, "nothing was queued or changed") {
		t.Fatalf("issued deploy did not fail closed: status %d body %s", status, body)
	}
	stored, err := h.store.GetIdentity(t.Context(), h.tenant, identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "issued" {
		t.Fatalf("issued deploy changed identity state to %q", stored.Status)
	}
	if got := connectorTargetOutboxRows(t, h); got != beforeOutbox {
		t.Fatalf("issued deploy queued a keyless effect: before=%d after=%d", beforeOutbox, got)
	}
	if got := eventCount(t, h.log, h.tenant, projections.EventIdentityConnectorTargetBound); got != beforeBindings {
		t.Fatalf("issued deploy rebound before refusing: before=%d after=%d", beforeBindings, got)
	}
}

type connectorDeliveryList struct {
	Raw   []byte
	Items []struct {
		ID             string `json:"id"`
		IdentityID     string `json:"identity_id"`
		Destination    string `json:"destination"`
		Connector      string `json:"connector"`
		Target         string `json:"target"`
		Fingerprint    string `json:"fingerprint"`
		Status         string `json:"status"`
		Reason         string `json:"reason"`
		Detail         string `json:"detail"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"items"`
}

func containsLifecycleIntent(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func deliveryFingerprintsContain(deliveries connectorDeliveryList, fingerprint string) bool {
	for _, item := range deliveries.Items {
		if item.Fingerprint == fingerprint {
			return true
		}
	}
	return false
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

type ariPostureList struct {
	PublicationStatus string           `json:"publication_status"`
	SchedulerStatus   string           `json:"scheduler_status"`
	Items             []ariPostureItem `json:"items"`
	Raw               []byte           `json:"-"`
}

type ariPostureItem struct {
	CertificateID     string     `json:"certificate_id"`
	ARICertificateID  string     `json:"ari_certificate_id"`
	CertificateStatus string     `json:"certificate_status"`
	PublicationStatus string     `json:"publication_status"`
	SchedulerConsumed bool       `json:"scheduler_consumed"`
	RotationRunID     string     `json:"rotation_run_id"`
	SchedulerStatus   string     `json:"scheduler_status"`
	SuggestedWindow   ari.Window `json:"suggested_window"`
}

func ariPostureForTenant(t *testing.T, h *servedHarness, token string) ariPostureList {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/acme/ari/posture", token, nil)
	if status != http.StatusOK {
		t.Fatalf("get ARI posture: status %d body %s", status, body)
	}
	var out ariPostureList
	out.Raw = body
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode ARI posture: %v (%s)", err, body)
	}
	return out
}

func findARIPostureCertificate(posture ariPostureList, certificateID string) (ariPostureItem, bool) {
	for _, item := range posture.Items {
		if item.CertificateID == certificateID {
			return item, true
		}
	}
	return ariPostureItem{}, false
}
