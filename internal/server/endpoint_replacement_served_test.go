// SPDX-License-Identifier: MPL-2.0

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
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

// This is a served API/worker test with real PostgreSQL and NATS and local CA
// and connector API doubles. Real listener qualification is a separate journey.
func TestEndpointReplacementServedPreservesSameOwnerAndExternalCA(t *testing.T) {
	const access = "AKIDREPLACEMENTTEST"
	const secret = "ReplacementFixtureSigV4Only" // #nosec G101 -- fabricated test-only credential (CWE-798)
	const arn = "arn:aws:acm:us-east-1:123456789012:certificate/replacement-test"
	provider := acmtest.New(access, secret)
	t.Cleanup(provider.Close)
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(provider.Client()) })
	registry.Register(acm.New("us-east-1", acm.Credentials{AccessKeyID: access, SecretAccessKey: []byte(secret)}, acm.WithEndpoint(provider.URL())))
	dc, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dc.Close)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ConnectorRegistry = registry
		d.ExternalCAs = []ExternalCA{{ID: "replacement-ca", Type: "digicert", Name: "Replacement CA",
			CA: digicert.New("replacement-ca", dc.URL(), []byte(dc.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))}}
	})
	originalHandler := h.srv.obHandler
	h.srv.obHandler = orchestrator.HandlerFunc(func(ctx context.Context, m orchestrator.Message) error {
		err := originalHandler.Deliver(ctx, m)
		if err != nil {
			t.Logf("fixture receiver %s attempt %d: %v", m.Destination, m.Attempts, err)
		}
		return err
	})
	tok := seedScopedToken(t, h.store, h.tenant, "owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read", "profiles:write")
	create := func(path string, request any) map[string]json.RawMessage {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, path, tok, request)
		if status != http.StatusCreated {
			t.Fatalf("create %s: %d %s", path, status, body)
		}
		var result map[string]json.RawMessage
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	decodeID := func(raw json.RawMessage) string {
		t.Helper()
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	owner := decodeID(create("/api/v1/owners", map[string]any{"kind": "workload", "name": "replacement owner"})["id"])
	target := decodeID(create("/api/v1/connectors/targets", map[string]any{"name": arn, "connector": "aws-acm", "config": map[string]any{"target": arn, "credential_ref": "secret://connectors/aws-acm/replacement-test"}})["id"])
	request := map[string]any{"owner_id": owner, "identity_name": "replace.served.test", "target_id": target,
		"issuer": map[string]any{"source": "external", "id": "replacement-ca"}, "reason": "first enrollment"}
	preview := func() map[string]json.RawMessage {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", tok, request)
		if status != http.StatusOK {
			t.Fatalf("preview: %d %s", status, body)
		}
		var result map[string]json.RawMessage
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		request["preview_fingerprint"] = decodeID(result["request_fingerprint"])
		return result
	}
	preview()
	first := create("/api/v1/lifecycle/endpoint-bindings", request)
	var original struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(first["identity"], &original); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	// The external CA callback can deploy before the original asynchronous
	// ca.issue attempt reaches its retry. Wait for real worker completion,
	// rather than treating identity.status=deployed as proof of quiescence.
	deadline := time.Now().Add(20 * time.Second)
	for {
		var pending bool
		if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
			var err error
			pending, err = h.store.EndpointReplacementWorkPendingTx(t.Context(), tx, h.tenant, original.ID, target)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if !pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("original asynchronous issuance did not settle")
		}
		time.Sleep(50 * time.Millisecond)
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	originalState, err := h.store.GetIdentity(t.Context(), h.tenant, original.ID)
	if err != nil || originalState.Status != "deployed" {
		t.Fatalf("original not deployed: %+v %v", originalState, err)
	}
	before := eventCount(t, h.log, h.tenant, projections.EventIdentityCreated)
	create("/api/v1/profiles", map[string]any{"name": "replacement-web", "spec": map[string]any{
		"max_validity": "24h", "allowed_protocols": []string{"api"}, "allowed_dns_suffixes": []string{"replace.served.test"},
	}})
	request["replace_identity_id"] = original.ID
	request["profile_name"] = "replacement-web"
	request["reason"] = "replace then independently verify before revoking original"
	planned := preview()
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(planned["replaced_identity"], &source); err != nil || source.ID != original.ID || planned["existing_identity"] != nil {
		t.Fatalf("preview did not distinguish original from reused identity: %v %v", planned, err)
	}
	if eventCount(t, h.log, h.tenant, projections.EventIdentityCreated) != before {
		t.Fatal("preview created an identity")
	}
	// The reviewed original is an exact object, including its lifecycle version.
	request["identity_name"] = "wrong.served.test"
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", tok, "wrong-replacement-name", request)
	if status != http.StatusConflict {
		t.Fatalf("wrong name accepted: %d %s", status, body)
	}
	request["identity_name"] = "replace.served.test"
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", tok, "explicit-replacement", request)
	if status != http.StatusCreated {
		_ = h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
			var diagnostic string
			if err := tx.QueryRow(t.Context(), `SELECT coalesce(string_agg(destination || ':' || status || ':' || coalesce(last_error, ''), E'\n'), '') FROM outbox WHERE tenant_id = $1`, h.tenant).Scan(&diagnostic); err != nil {
				return err
			}
			t.Log(diagnostic)
			return nil
		})
		t.Fatalf("replacement: %d %s", status, body)
	}
	var created struct {
		Identity struct {
			ID string `json:"id"`
		} `json:"identity"`
		OriginalID string `json:"replaced_identity_id"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.Identity.ID == original.ID || created.OriginalID != original.ID {
		t.Fatalf("original reused: %s", body)
	}
	status, replay := secretsReqKey(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", tok, "explicit-replacement", request)
	if status != http.StatusCreated || string(body) != string(replay) {
		t.Fatalf("retry differs: %d %s", status, replay)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	replacement, err := h.store.GetIdentity(t.Context(), h.tenant, created.Identity.ID)
	if err != nil || replacement.Status != "deployed" || replacement.OwnerID != owner {
		t.Fatalf("replacement not deployed with same owner: %+v %v", replacement, err)
	}
	var replacementAttrs map[string]any
	if err := json.Unmarshal(replacement.Attributes, &replacementAttrs); err != nil {
		t.Fatal(err)
	}
	if replacementAttrs["profile_name"] != "replacement-web" {
		t.Fatalf("replacement lost selected profile: %s", replacement.Attributes)
	}
	retained, err := h.srv.orch.ProfileApprovalRequirement(t.Context(), h.tenant, replacement.ID)
	if err != nil || retained.ProfileName != "replacement-web" || retained.EffectiveTTLSeconds != 86400 {
		t.Fatalf("replacement renewal policy: %+v %v", retained, err)
	}
	_, version, err := h.store.IdentityApprovalTarget(t.Context(), h.tenant, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	heldRenewal := map[string]any{"to": "renewing", "reason": "original must not overwrite its replacement", "expected_version": version}
	for _, suffix := range []string{"/preview", ""} {
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+original.ID+"/transitions"+suffix, tok, heldRenewal)
		if status != http.StatusConflict || !strings.Contains(string(body), replacement.ID) {
			t.Fatalf("renewal hold %s did not explain exact successor: %d %s", suffix, status, body)
		}
	}
	certs, err := h.store.IdentityRevocationCertificates(t.Context(), h.tenant, replacement.ID, 10)
	if err != nil || len(certs) != 1 || !strings.Contains(strings.ToLower(certs[0].Issuer), "digicert") {
		t.Fatalf("replacement CA changed or issuance duplicated: %+v %v", certs, err)
	}
	originalCerts, err := h.store.IdentityRevocationCertificates(t.Context(), h.tenant, original.ID, 10)
	if err != nil || len(originalCerts) != 1 || originalCerts[0].ID == certs[0].ID {
		t.Fatalf("same owner/name confused revocation bindings: %+v %v", originalCerts, err)
	}
	if got := eventCount(t, h.log, h.tenant, projections.EventIdentityCreated); got != before+1 {
		t.Fatalf("replacement created %d identities", got-before)
	}
	// A lost response before the HTTP cache commit must still resume the same
	// successor; a fresh HTTP key exercises the receiver's own duplicate guard.
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", tok, "replacement-receiver-retry", request)
	if status != http.StatusCreated || !strings.Contains(string(body), replacement.ID) {
		t.Fatalf("receiver retry: %d %s", status, body)
	}
	if got := eventCount(t, h.log, h.tenant, projections.EventIdentityCreated); got != before+1 {
		t.Fatal("receiver retry created a twin")
	}
	// Reviewing the same immutable request must remain recoverable, including
	// a receiver retry with a fresh HTTP key. A different request cannot create
	// another successor, and must explain that conflict before authorization.
	acceptedReason := request["reason"]
	preview()
	request["reason"] = "a separate replacement while the accepted successor is active"
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", tok, request)
	if status != http.StatusConflict || !strings.Contains(string(body), replacement.ID) {
		t.Fatalf("conflicting replacement preview did not identify active successor: %d %s", status, body)
	}
	if got := eventCount(t, h.log, h.tenant, projections.EventIdentityCreated); got != before+1 {
		t.Fatal("conflicting preview changed identities")
	}
	request["reason"] = acceptedReason
	got, err := h.store.GetIdentity(t.Context(), h.tenant, original.ID)
	if err != nil || got.Status != "deployed" {
		t.Fatalf("original revoked before operator verification: %+v %v", got, err)
	}
	// Once the original is revoked or retired, its state itself forbids renewal.
	// Never suggest revoking the healthy successor to recover a closed original.
	for _, state := range []string{"revoked", "retired"} {
		reason := "replacement verified; close original"
		if state == "revoked" {
			reason = "superseded"
		}
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+original.ID+"/transitions", tok,
			map[string]any{"to": state, "reason": reason})
		if status != http.StatusOK {
			t.Fatalf("close original as %s: %d %s", state, status, body)
		}
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatal(err)
		}
		status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+original.ID+"/transitions/preview", tok,
			map[string]any{"to": "renewing", "reason": "closed original must not renew"})
		if status < 400 || !strings.Contains(string(body), state) || strings.Contains(string(body), "revoke that replacement") {
			t.Fatalf("%s renewal preview gave unsafe recovery advice: %d %s", state, status, body)
		}
	}
}
