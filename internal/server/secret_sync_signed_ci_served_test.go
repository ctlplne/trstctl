// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
)

// OD-12 (B14-L2): a generic CI push target built from config with a
// signing_key_ref signs every push like the signed webhook. The receiver
// verifies the signature before it accepts the envelope (the bearer token
// still rides along), a replay with one byte changed is refused, and the
// catalog reports the signed target as signed and the unsigned one as not.
func TestServedSecretSyncToASignedGenericCIPushOD12(t *testing.T) {
	ctx := context.Background()
	key := []byte("ci-receiver-shared-signing-key")
	var mu sync.Mutex
	var accepted [][]byte
	var headers []http.Header
	refused := 0
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		mu.Lock()
		defer mu.Unlock()
		if req.URL.Path != "/secrets" || req.Header.Get("Authorization") != "Bearer ci-bearer-token" ||
			secretsync.VerifyWebhookSignature(key, req.Header.Get(secretsync.WebhookTimestampHeader), body,
				req.Header.Get(secretsync.WebhookSignatureHeader), time.Now(), 0) != nil {
			refused++
			http.Error(w, "refused", http.StatusUnauthorized)
			return
		}
		accepted = append(accepted, body)
		headers = append(headers, req.Header.Clone())
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(receiver.Close)
	registry, minter, err := secretSyncTargetsFromConfig(ctx, []config.SecretSyncTargetConfig{{
		TenantID: servedTestTenant, ID: "signed-ci", Type: "generic-ci-json", Provider: "example-ci", Endpoint: receiver.URL,
		AllowInsecureLoopback: true,
		TokenRef:              writeServedCredentialFile(t, "ci-bearer-token", "ci-bearer-token"),
		SigningKeyRef:         writeServedCredentialFile(t, "ci-signing-key", string(key)),
	}, {
		TenantID: servedTestTenant, ID: "plain-ci", Type: "generic-ci-json", Provider: "example-ci", Endpoint: receiver.URL,
		AllowInsecureLoopback: true,
		TokenRef:              writeServedCredentialFile(t, "ci-plain-token", "ci-bearer-token"),
	}}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(minter.Close)
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantSecretSyncTargets = registry
	})
	registerServedTenant(t, h, "signed ci tenant")
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "ci-syncer", "secrets:read", "secrets:write")
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{"name": "app/deploy", "value": "de\"ploy\nkey"}); status != http.StatusCreated {
		t.Fatalf("create secret: %d %s", status, body)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs", tok, "signed-ci-sync-1",
		map[string]any{"name": "app/deploy", "target": "signed-ci", "remote_key": "DEPLOY_KEY"})
	if status != http.StatusOK {
		t.Fatalf("queue the sync: %d %s", status, body)
	}
	job := drainSecretSyncUntil(t, h, currentSecretSyncJobIDForTest(t, h.store, h.tenant, "signed-ci-sync-1"), store.SecretSyncJobDelivered, 3)
	if job.Status != store.SecretSyncJobDelivered {
		t.Fatalf("the sync = %+v, want delivered", job)
	}
	mu.Lock()
	gotBodies, gotHeaders, gotRefused := append([][]byte(nil), accepted...), append([]http.Header(nil), headers...), refused
	mu.Unlock()
	if len(gotBodies) != 1 || gotRefused != 0 {
		t.Fatalf("the receiver accepted %d and refused %d pushes", len(gotBodies), gotRefused)
	}
	var envelope struct {
		Provider     string `json:"provider"`
		Key          string `json:"key"`
		EncodedValue string `json:"encoded_value"`
	}
	if err := json.Unmarshal(gotBodies[0], &envelope); err != nil {
		t.Fatal(err)
	}
	value, _ := base64.StdEncoding.DecodeString(envelope.EncodedValue)
	if envelope.Provider != "example-ci" || envelope.Key != "DEPLOY_KEY" || string(value) != "de\"ploy\nkey" ||
		gotHeaders[0].Get(secretsync.WebhookDeliveryHeader) == "" {
		t.Fatalf("pushed envelope %+v headers %v", envelope, gotHeaders[0])
	}

	// Replay the exact push with one byte of the body changed: refused.
	tampered := bytes.Replace(gotBodies[0], []byte("DEPLOY_KEY"), []byte("DEPLOY_KEZ"), 1)
	req, _ := http.NewRequest(http.MethodPost, receiver.URL+"/secrets", bytes.NewReader(tampered))
	for _, name := range []string{"Authorization", secretsync.WebhookTimestampHeader, secretsync.WebhookSignatureHeader, secretsync.WebhookDeliveryHeader} {
		req.Header.Set(name, gotHeaders[0].Get(name))
	}
	resp, err := receiver.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a tampered push = %d, want 401", resp.StatusCode)
	}

	// The catalog says which configured CI target signs.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/syncs/targets", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("catalog: %d %s", status, body)
	}
	var catalog struct {
		Targets []struct {
			ID           string   `json:"id"`
			DeliveryMode string   `json:"delivery_mode"`
			Capabilities []string `json:"capabilities"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		t.Fatal(err)
	}
	rows := map[string][]string{}
	for _, row := range catalog.Targets {
		rows[row.ID] = row.Capabilities
	}
	if !slices.Contains(rows["signed-ci"], "signed-payload") || slices.Contains(rows["plain-ci"], "signed-payload") {
		t.Fatalf("catalog signed-payload: signed-ci %v, plain-ci %v", rows["signed-ci"], rows["plain-ci"])
	}
	t.Logf("OD12_SIGNED_CI_OK delivery=%s", gotHeaders[0].Get(secretsync.WebhookDeliveryHeader))
}
