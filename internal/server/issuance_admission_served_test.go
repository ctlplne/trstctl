// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

// A tenant whose default certificate profile permits only ACME accepted an
// identity issuance through the API, then every mint refused it ("does not
// permit enrollment protocol api"), retried it as an external failure, and
// opened the tenant's ca.issue circuit, delaying every other issuance. The
// transition now runs the profile's key-free checks first: it is refused with
// 409 profile_refused naming the profile before anything is recorded, and the
// preview says so. Work queued before a profile change is refused at the mint
// as a definite no-effect that never opens the circuit.
func TestServedIdentityIssuanceIsRefusedUpFrontWhenTheProfileForbidsTheAPI(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.DefaultProfile = "acme-only" })
	ctx := t.Context()
	storeServerTestProfile(t, h.store, h.tenant, "acme-only", profile.CertificateProfile{
		Name: "acme-only", MaxValidity: profile.Duration(2160 * time.Hour), AllowedProtocols: []string{"acme"},
	})
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "alice@customer.test", "owners:read", "owners:write",
		"identities:read", "identities:write", "certs:read", "certs:issue")
	owner, err := h.store.CreateOwner(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerWorkload, Name: "profile-admission"})
	if err != nil {
		t.Fatal(err)
	}
	identityWithCSR := func(name string) (string, string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{"owner_id": owner.ID, "kind": "x509", "name": name})
		var ident struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &ident) != nil {
			t.Fatalf("create identity %s = %d: %s", name, status, body)
		}
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: badSubjectCSR(t, key,
			crypto.CertificateRequestTemplate{CommonName: name, DNSNames: []string{name}})})
		return ident.ID, string(csr)
	}
	id, csr := identityWithCSR("admission.example.test")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions/preview", tok,
		map[string]any{"to": "issued", "reason": "requester key", "subject_csr_pem": csr})
	var preview struct {
		Ready          bool   `json:"ready"`
		ProfileRefused bool   `json:"profile_refused"`
		ProfileRefusal string `json:"profile_refusal"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &preview) != nil || preview.Ready || !preview.ProfileRefused ||
		!strings.Contains(preview.ProfileRefusal, `"acme-only"`) || !strings.Contains(preview.ProfileRefusal, `"api"`) {
		t.Fatalf("preview under an ACME-only profile = %d %s, want not ready naming the profile and the protocol", status, body)
	}
	before, err := h.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions", tok, "issue-refused",
		map[string]any{"to": "issued", "reason": "requester key", "subject_csr_pem": csr})
	if status != http.StatusConflict || !strings.Contains(string(body), "profile_refused") ||
		!strings.Contains(string(body), "acme-only") || !strings.Contains(string(body), `\"api\"`) {
		t.Fatalf("issue under an ACME-only profile = %d %s, want 409 profile_refused naming the profile and protocol", status, body)
	}
	if after, err := h.log.LastSequence(ctx); err != nil || after != before {
		t.Fatalf("the refused issue recorded events: %d -> %d (%v)", before, after, err)
	}
	if got, err := h.store.GetIdentity(ctx, h.tenant, id); err != nil || got.Status != "requested" {
		t.Fatalf("the refused issue moved the identity: %s %v", got.Status, err)
	}

	// A version that permits the API issues, and the transition queues the mint.
	storeServerTestProfile(t, h.store, h.tenant, "acme-only", profile.CertificateProfile{
		Name: "acme-only", MaxValidity: profile.Duration(2160 * time.Hour), AllowedProtocols: []string{"acme", "api"},
	})
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions", tok, "issue-allowed",
		map[string]any{"to": "issued", "reason": "requester key", "subject_csr_pem": csr}); status != http.StatusOK {
		t.Fatalf("issue once the profile permits the API = %d %s", status, body)
	}

	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the admitted issuance: %v", err)
	}

	// The transition pins the profile revision it admitted, so a later edit
	// cannot strand queued work; what can still refuse at the mint is a check
	// that needs the key. That refusal is a definite no-effect, and it does not
	// open the tenant's circuit for the issuance that follows it.
	storeServerTestProfile(t, h.store, h.tenant, "acme-only", profile.CertificateProfile{
		Name: "acme-only", MaxValidity: profile.Duration(2160 * time.Hour), AllowedProtocols: []string{"acme", "api"},
		AllowedKeyAlgorithms: []string{"RSA"},
	})
	ecID, ecCSR := identityWithCSR("ecdsa-refused.example.test")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+ecID+"/transitions", tok, "issue-ecdsa",
		map[string]any{"to": "issued", "reason": "requester key", "subject_csr_pem": ecCSR}); status != http.StatusOK {
		t.Fatalf("issue an ECDSA request under an RSA-only profile = %d %s, want it admitted (the key is checked at the mint)", status, body)
	}
	pending := pendingServedOutboxByDestination(t, h, "ca.issue")
	message := orchestrator.Message{ID: pending.ID, TenantID: h.tenant, Destination: pending.Destination, Payload: pending.Payload, IdempotencyKey: pending.IdempotencyKey}
	fenced, release, err := h.store.BeginTenantService(ctx, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	err = h.srv.obHandler.Deliver(fenced, message)
	release()
	if !errors.Is(err, orchestrator.ErrIssuanceProfileRefused) || !orchestrator.IsDefiniteNoEffect(err) ||
		!strings.Contains(err.Error(), "key algorithm") {
		t.Fatalf("mint of an ECDSA key under an RSA-only profile = %v, want a definite no-effect profile refusal", err)
	}
	for i := 0; i < 5; i++ {
		_ = h.srv.Drain(ctx)
	}
	for _, circuit := range h.srv.outbox.CircuitStates() {
		if circuit.TenantID == h.tenant && strings.HasPrefix(circuit.Destination, "ca.issue") && circuit.State == orchestrator.CircuitOpen {
			t.Fatalf("the profile refusal opened the tenant's ca.issue circuit: %+v", circuit)
		}
	}
}
