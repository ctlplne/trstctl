// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/assurance"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/protocols/ari"
	"trstctl.com/trstctl/internal/store"
)

// TestServedExternalObserverA180 is A180's served contract with a lab
// stand-in observer: after a renewal the rotation event reaches the observer,
// signed with its tenant credential; a matching observation is recorded as
// independent evidence on the renewed certificate's assurance record; a
// mismatching one raises a finding, and so does an unhealthy endpoint after
// the rotation.
func TestServedExternalObserverA180(t *testing.T) {
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.LifecycleRenewBefore = time.Hour
		d.AuditSigningKey = auditKey
	})
	ctx := t.Context()
	sink := newFamilySink(t)
	if h.srv.observerEvents == nil {
		t.Fatal("the served outbox has no observer event delivery")
	}
	h.srv.observerEvents.skipEndpointValidation = true
	h.srv.observerEvents.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Hostname() != "observer.example.test" {
			return nil, errors.New("unexpected observer host " + req.URL.Hostname())
		}
		local, err := url.Parse(sink.srv.URL + req.URL.Path)
		if err != nil {
			return nil, err
		}
		clone := req.Clone(req.Context())
		clone.URL, clone.Host = local, local.Host
		return sink.srv.Client().Do(clone)
	})}

	operator := seedScopedToken(t, h.store, h.tenant,
		"owners:write", "identities:read", "identities:write", "certs:read", "certs:issue",
		"connectors:read", "lifecycle:read", "notifications:read", "notifications:write", "secrets:write", "discovery:read")
	const hmacKey = "a180-observer-hmac-key" // #nosec G101 -- fabricated fixture credential (CWE-798)
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", operator, map[string]any{"name": "observers/lab/hmac", "value": hmacKey}); status != http.StatusCreated {
		t.Fatalf("store observer credential: %d %s", status, body)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/observers", operator, "a180-register", map[string]any{
		"name": "lab-observer", "events_url": "https://observer.example.test/events",
		"credential_ref": "secret://observers/lab/hmac",
	})
	if status != http.StatusCreated {
		t.Fatalf("register observer: %d %s", status, body)
	}
	var observer struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &observer)
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/observers", operator, "a180-register-dup", map[string]any{"name": "lab-observer"}); status != http.StatusConflict {
		t.Fatalf("a second observer of the same name: %d %s", status, body)
	}

	// A deployed identity, renewed by the scheduler.
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/owners", operator, map[string]any{"kind": "workload", "name": "a180-owner"})
	if status != http.StatusCreated {
		t.Fatalf("owner: %d %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &owner)
	const name = "observed.served.test"
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", operator, map[string]any{
		"kind": "x509_certificate", "name": name, "owner_id": owner.ID,
		"attributes": map[string]any{"connector": "nginx", "target": "edge-observed"},
	})
	if status != http.StatusCreated {
		t.Fatalf("identity: %d %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &ident)
	for _, to := range []string{"issued", "deployed"} {
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", operator, map[string]any{"to": to, "reason": "a180 fixture"})
		alreadyDeployed := to == "deployed" && status == http.StatusConflict && strings.Contains(string(body), "deployed")
		if status != http.StatusOK && !alreadyDeployed {
			t.Fatalf("transition %s: %d %s", to, status, body)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
	}
	certs, err := h.store.ListActiveIssuedCertificatesForIdentity(ctx, h.tenant, owner.ID, name)
	if err != nil || len(certs) != 1 {
		t.Fatalf("issued = %d, %v", len(certs), err)
	}
	predecessor := certs[0]
	const address = "edge-observed.example.test:443"
	if err := h.srv.orch.RecordEndpointVerification(ctx, h.tenant, projections.EndpointVerificationObserved{
		EndpointID: "edge-observed", Address: address, Vantage: "relay", Reached: true,
		ExpectedFingerprint: predecessor.Fingerprint, ObservedFingerprint: predecessor.Fingerprint, ObservedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	window := ari.SuggestWindow(*predecessor.NotBefore, *predecessor.NotAfter, time.Now().UTC(), false)
	if queued, err := h.srv.runLifecycleOnceAt(ctx, window.Start.Add(time.Second)); err != nil || queued != 1 {
		t.Fatalf("scheduled renewals = %d, %v", queued, err)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	runs := rotationRunsForIdentity(t, h, operator, ident.ID)
	if len(runs.Items) != 1 || runs.Items[0].Status != "succeeded" {
		t.Fatalf("runs = %s", runs.Raw)
	}
	run := runs.Items[0]

	// The rotation event reached the observer, signed.
	event, headers := sink.one(t, "/events")
	mac := hex.EncodeToString(crypto.HMACSHA256([]byte(hmacKey), event))
	if headers.Get("X-Trstctl-Signature") != "sha256="+mac {
		t.Fatalf("rotation event signature = %q", headers.Get("X-Trstctl-Signature"))
	}
	var rotated store.ObserverEvent
	if err := json.Unmarshal(event, &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Type != store.ObserverEventRotationCompleted || rotated.ID != "rotation:"+run.ID || rotated.TenantID != h.tenant ||
		rotated.CurrentFingerprint != run.SuccessorFingerprint || rotated.PreviousFingerprint != predecessor.Fingerprint ||
		!slices.Contains(rotated.Endpoints, address) || rotated.IdentityID != ident.ID {
		t.Fatalf("rotation event = %+v", rotated)
	}

	// The relay now expects the successor there; the observer reports.
	if err := h.srv.orch.RecordEndpointVerification(ctx, h.tenant, projections.EndpointVerificationObserved{
		EndpointID: "edge-observed", Address: address, Vantage: "relay", Reached: true,
		ExpectedFingerprint: run.SuccessorFingerprint, ObservedFingerprint: run.SuccessorFingerprint, ObservedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	reporter := seedScopedToken(t, h.store, h.tenant, "discovery:write")
	observedAt := time.Now().UTC().Format(time.RFC3339Nano)
	report := func(key string, served, health string, reachable bool) map[string]any {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/observations", reporter, key, map[string]any{
			"observer_id": observer.ID, "endpoint": strings.ToUpper("edge-observed.example.test") + ":443", "vantage": "lab",
			"observed_at": observedAt, "reachable": reachable, "health": health,
			"served_fingerprint": served,
		})
		if status != http.StatusCreated {
			t.Fatalf("observation %s: %d %s", key, status, body)
		}
		var out map[string]any
		_ = json.Unmarshal(body, &out)
		return out
	}
	if got := report("a180-match", run.SuccessorFingerprint, "healthy", true); got["verdict"] != store.ObservationMatch || got["endpoint"] != address {
		t.Fatalf("matching observation = %v", got)
	}
	if again := report("a180-match", run.SuccessorFingerprint, "healthy", true); again["verdict"] != store.ObservationMatch {
		t.Fatalf("a retried observation = %v", again)
	}
	other := strings.Repeat("9f", 32)
	if got := report("a180-mismatch", other, "healthy", true); got["verdict"] != store.ObservationMismatch {
		t.Fatalf("mismatching observation = %v", got)
	}
	if got := report("a180-unhealthy", run.SuccessorFingerprint, "unhealthy", true); got["verdict"] != store.ObservationMatch || got["health"] != "unhealthy" {
		t.Fatalf("unhealthy observation = %v", got)
	}

	// The match is independent evidence on the renewed certificate's record.
	successor, err := certificateByFingerprint(t, h, run.SuccessorFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+successor.ID+"/assurance-record", operator, nil)
	if status != http.StatusOK {
		t.Fatalf("assurance record: %d %s", status, body)
	}
	keys, err := jose.ParseJWKSet(mustPublicJWKS(t, auditKey))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := assurance.Verify(body, keys)
	if err != nil {
		t.Fatal(err)
	}
	var matched *assurance.ExternalObservation
	for i := range verified.Record.ExternalObservations {
		if verified.Record.ExternalObservations[i].Verdict == store.ObservationMatch && verified.Record.ExternalObservations[i].Health == "healthy" {
			matched = &verified.Record.ExternalObservations[i]
		}
	}
	if matched == nil || matched.Observer != "lab-observer" || matched.Basis != assurance.BasisObserved || !strings.HasPrefix(matched.EvidenceID, "external-observation:") {
		t.Fatalf("external observations on the record = %+v", verified.Record.ExternalObservations)
	}
	if !slices.Contains(verified.Record.IndependentlyObserved, "verification") {
		t.Fatalf("an observer's match does not count as independent verification: %v", verified.Record.IndependentlyObserved)
	}

	// The mismatch and the unhealthy endpoint after the rotation are findings.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?limit=100", operator, nil)
	if status != http.StatusOK {
		t.Fatalf("findings: %d %s", status, body)
	}
	for _, kind := range []string{"external-observation-mismatch", "endpoint-unhealthy-after-rotation"} {
		if !strings.Contains(string(body), kind) {
			t.Fatalf("finding %s was not raised: %s", kind, body)
		}
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/observations", reporter, "a180-unknown", map[string]any{
		"observer_id": "18000000-0000-4000-8000-0000000000ff", "endpoint": address, "observed_at": time.Now().UTC(), "reachable": true,
	}); status != http.StatusConflict {
		t.Fatalf("an unregistered observer reported: %d", status)
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/observers", reporter, "a180-reporter-register", map[string]any{"name": "sneaky"}); status != http.StatusForbidden {
		t.Fatalf("a reporting token registered an observer: %d", status)
	}
}

func mustPublicJWKS(t *testing.T, key *jose.SigningKey) []byte {
	t.Helper()
	doc, err := key.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	return doc
}
