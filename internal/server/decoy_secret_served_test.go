// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// Q6: a stored secret registered as bait raises one critical alert per reader,
// naming the reader, on every served value read (native, history, reference
// resolution, Vault KV); listing, metadata, the access preview, inventory and the
// graph read no value through those paths and raise nothing. The decoy's state
// and the alerts survive a full read-model rebuild without duplicating.
func TestServedDecoySecretReadsAlertNamingEachReaderQ6(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.EnableSecretsAPI = true })
	planter := seedScopedTokenSubject(t, h.store, h.tenant, "decoy-planter", "secrets:read", "secrets:write", "nhi:read", "graph:read")
	thief := seedScopedTokenSubject(t, h.store, h.tenant, "ci-runner-7", "secrets:read")
	insider := seedScopedTokenSubject(t, h.store, h.tenant, "contractor-2", "secrets:read")
	builder := seedScopedTokenSubject(t, h.store, h.tenant, "build-bot", "secrets:read")
	const bait = "prod/payments/db-password"
	const baitValue = "pg-7Qm2vXk9-decoy-shaped-like-a-password"
	for key, body := range map[string]map[string]any{
		"q6-bait":     {"name": bait, "value": baitValue},
		"q6-real":     {"name": "prod/payments/api-key", "value": "real-value-1"},
		"q6-template": {"name": "prod/payments/dsn", "value": "postgres://app:${secret." + bait + "}@db/payments"},
	} {
		if status, out := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", planter, key, body); status != http.StatusCreated {
			t.Fatalf("create %s: HTTP %d %s", body["name"], status, out)
		}
	}
	alerts := func() []string {
		t.Helper()
		rows, err := h.store.SystemPool().Query(t.Context(),
			`SELECT convert_from(payload, 'UTF8')::jsonb->>'detail' FROM outbox
			  WHERE tenant_id = $1 AND destination = 'notification.honeytoken'
			    AND convert_from(payload, 'UTF8')::jsonb->>'severity' = 'critical' ORDER BY id`, h.tenant)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var detail string
			if err := rows.Scan(&detail); err != nil {
				t.Fatal(err)
			}
			out = append(out, detail)
		}
		return out
	}
	register := map[string]any{"secret_name": bait, "name": "payments db password bait", "placement": "payments repo .env.example"}
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/secrets", thief, "q6-thief-register", register); status != http.StatusForbidden {
		t.Fatalf("a secrets:read caller registered a decoy: HTTP %d", status)
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/secrets", planter, "q6-missing",
		map[string]any{"secret_name": "prod/nope", "name": "x", "placement": "y"}); status != http.StatusNotFound {
		t.Fatalf("registering a missing secret: HTTP %d, want 404", status)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/secrets", planter, "q6-register", register)
	if status != http.StatusCreated {
		t.Fatalf("register decoy: HTTP %d %s", status, body)
	}
	var decoy struct {
		ID             string `json:"id"`
		Kind           string `json:"kind"`
		SecretName     string `json:"secret_name"`
		State          string `json:"state"`
		TriggerSubject string `json:"trigger_subject"`
		TriggerMethod  string `json:"trigger_method"`
		TriggerPath    string `json:"trigger_path"`
	}
	if err := json.Unmarshal(body, &decoy); err != nil || decoy.Kind != "secret" || decoy.SecretName != bait || decoy.State != "active" {
		t.Fatalf("registered decoy = %+v (%v)", decoy, err)
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/secrets", planter, "q6-register-again", register); status != http.StatusConflict {
		t.Fatalf("registering the same secret twice: HTTP %d, want 409", status)
	}
	// The likely thief holds secrets:read; it must not learn which secrets are bait.
	for _, path := range []string{"/api/v1/secrets/honeytokens/secrets", "/api/v1/secrets/honeytokens/secrets/" + decoy.ID} {
		if status, _ := secretsReq(t, h, http.MethodGet, path, thief, nil); status != http.StatusForbidden {
			t.Fatalf("secrets:read caller read the decoy registry %s: HTTP %d", path, status)
		}
	}
	if status, out := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens", thief, nil); status != http.StatusOK || strings.Contains(string(out), bait) {
		t.Fatalf("the bearer-decoy list exposed the decoy secret: HTTP %d %s", status, out)
	}

	// No false alarms: names, metadata, the access preview, a template read
	// without resolution, inventory and the graph serve no decoy value.
	for _, read := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/secrets/store"},
		{http.MethodGet, "/api/v1/secrets/store/prod/payments/api-key"},
		{http.MethodGet, "/api/v1/secrets/store/prod/payments/dsn"},
		{http.MethodGet, "/api/v1/nhi/inventory"},
		{http.MethodGet, "/api/v1/graph"},
	} {
		if status, out := secretsReq(t, h, read.method, read.path, planter, nil); status != http.StatusOK {
			t.Fatalf("%s %s: HTTP %d %s", read.method, read.path, status, out)
		}
	}
	if status, out := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/access/preview", thief,
		map[string]any{"name": bait, "env_var": "DB_PASSWORD", "resolve": false}); status != http.StatusOK || strings.Contains(string(out), baitValue) {
		t.Fatalf("access preview: HTTP %d %s", status, out)
	}
	if status, out := q6VaultRequest(t, h, insider, http.MethodGet, "/v1/secret/metadata/"+bait); status != http.StatusOK || strings.Contains(string(out), baitValue) {
		t.Fatalf("Vault metadata read: HTTP %d %s", status, out)
	}
	if got := alerts(); len(got) != 0 {
		t.Fatalf("listing, metadata, preview, inventory or the graph raised alerts: %v", got)
	}

	// The thief reads the bait: it gets the value, and exactly one alert names it.
	status, out := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+bait, thief, nil)
	if status != http.StatusOK || !strings.Contains(string(out), baitValue) {
		t.Fatalf("decoy read must serve the bait value: HTTP %d %s", status, out)
	}
	secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+bait, thief, nil)
	secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/history/"+bait+"?version=1", thief, nil)
	if got := alerts(); len(got) != 1 || !strings.Contains(got[0], "read by ci-runner-7") || !strings.Contains(got[0], bait) {
		t.Fatalf("after three reads by one reader, alerts = %v; want one naming ci-runner-7", got)
	}
	// A second reader through the Vault-compatible API raises its own alert.
	if status, out := q6VaultRequest(t, h, insider, http.MethodGet, "/v1/secret/data/"+bait); status != http.StatusOK || !strings.Contains(string(out), baitValue) {
		t.Fatalf("Vault KV read of the decoy: HTTP %d %s", status, out)
	}
	// A third reader reaches the bait through a resolved reference.
	status, out = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/prod/payments/dsn?resolve=true", builder, nil)
	if status != http.StatusOK || !strings.Contains(string(out), baitValue) {
		t.Fatalf("resolved template read: HTTP %d %s", status, out)
	}
	got := alerts()
	if len(got) != 3 || !strings.Contains(got[1], "read by contractor-2") || !strings.Contains(got[2], "read by build-bot") {
		t.Fatalf("alerts = %v; want ci-runner-7, contractor-2, build-bot once each", got)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/secrets/"+decoy.ID, planter, nil)
	if err := json.Unmarshal(body, &decoy); status != http.StatusOK || err != nil || decoy.State != "triggered" ||
		decoy.TriggerSubject != "ci-runner-7" || decoy.TriggerMethod != http.MethodGet || decoy.TriggerPath != "/api/v1/secrets/store/{name...}" {
		t.Fatalf("triggered decoy = %+v (HTTP %d)", decoy, status)
	}
	if !h.hasEvent(t, "honeytoken.triggered") {
		t.Fatal("decoy reads appended no trigger event")
	}

	// A full rebuild keeps the investigation and adds no alert.
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("projection rebuild: %v", err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/secrets/"+decoy.ID, planter, nil)
	var rebuilt struct {
		State          string `json:"state"`
		TriggerSubject string `json:"trigger_subject"`
	}
	if err := json.Unmarshal(body, &rebuilt); status != http.StatusOK || err != nil || rebuilt.State != "triggered" || rebuilt.TriggerSubject != "ci-runner-7" {
		t.Fatalf("after rebuild decoy = %+v (HTTP %d)", rebuilt, status)
	}
	if n := len(alerts()); n != 3 {
		t.Fatalf("rebuild changed the alert count to %d", n)
	}

	// Retired, the secret stays and reads no longer alert.
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/secrets/"+decoy.ID+"/retire", planter, "q6-retire", nil); status != http.StatusOK {
		t.Fatalf("retire decoy: HTTP %d", status)
	}
	latecomer := seedScopedTokenSubject(t, h.store, h.tenant, "late-reader", "secrets:read")
	if status, _ := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+bait, latecomer, nil); status != http.StatusOK {
		t.Fatalf("retired decoy's secret is gone: HTTP %d", status)
	}
	if n := len(alerts()); n != 3 {
		t.Fatalf("a retired decoy alerted: %d alerts", n)
	}
}

func q6VaultRequest(t *testing.T, h *servedHarness, token, method, path string) (int, []byte) {
	t.Helper()
	u, err := url.JoinPath(h.ts.URL, path)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}
