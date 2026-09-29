// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

// F264: the person opening a CA key ceremony must not decide how many custodians
// have to agree. TRSTCTL_CA_CEREMONY_MIN_APPROVALS (ca.ceremony_min_approvals)
// sets a floor that the production-assembled preview and start routes enforce,
// with the shipped signer process behind the CA hierarchy surface.
func TestServedCeremonyApprovalFloorComesFromDeploymentConfig(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: servedTestTenant, Name: "F264 tenant", EventSeq: 1}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	token := seedScopedToken(t, st, servedTestTenant, "issuers:write", "issuers:read")
	env := map[string]string{"TRSTCTL_CA_CEREMONY_MIN_APPROVALS": "2"}
	cfg, err := config.Load(func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("load config with a ceremony approval floor: %v", err)
	}
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(root, "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(root, "secrets-kek")
	cfg.Signer.AuthSecretFile = filepath.Join(root, "sign-auth.bin")
	cfg.Signer.KeyStoreDir = filepath.Join(root, "signer-keys")
	cfg.CA.CertFile = filepath.Join(root, "issuing-ca.crt")
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatalf("audit key: %v", err)
	}
	log, err := openHistoryAwareEventLog(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")}, st, auditKey)
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatalf("egress guard: %v", err)
	}
	secrets, err := loadRunSecrets(cfg)
	if err != nil {
		_ = log.Close()
		t.Fatalf("run secrets: %v", err)
	}
	t.Cleanup(secrets.Close)
	// The CA hierarchy surface needs a real signer: start the shipped trstctl-signer.
	signerAuthFile := filepath.Join(root, "signer-auth.bin")
	signerAuthorizer, err := signing.LoadOrCreateAuthorizer(signerAuthFile)
	if err != nil {
		_ = log.Close()
		t.Fatalf("signer authorizer: %v", err)
	}
	t.Cleanup(signerAuthorizer.Destroy)
	signer := dodStartShippedSignerProcess(t, root, "f264", signerAuthFile, "", signerAuthorizer)
	deps, err := buildRunDeps(ctx, cfg, st, log, signer, secrets, slog.New(slog.NewTextHandler(io.Discard, nil)), guard, auditKey)
	if err != nil {
		_ = log.Close()
		t.Fatalf("production buildRunDeps: %v", err)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	spec := map[string]any{
		"common_name":         "floor-checked root",
		"max_path_len":        1,
		"ttl_seconds":         int64((365 * 24 * time.Hour).Seconds()),
		"extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	post := func(path, idem string, threshold int) (int, string) {
		body, _ := json.Marshal(map[string]any{"operation": "create_root", "threshold": threshold, "spec": spec})
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		if idem != "" {
			req.Header.Set("Idempotency-Key", idem)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, body := post("/api/v1/ca/ceremonies/preview", "", 1); code != http.StatusUnprocessableEntity || !strings.Contains(body, "ca.ceremony_min_approvals") {
		t.Errorf("preview with 1 approval under a floor of 2 = %d body=%s; want 422 naming ca.ceremony_min_approvals", code, body)
	}
	if code, body := post("/api/v1/ca/ceremonies", "f264-start-one", 1); code != http.StatusUnprocessableEntity {
		t.Errorf("start with 1 approval under a floor of 2 = %d body=%s; want 422", code, body)
	}
	if code, body := post("/api/v1/ca/ceremonies/preview", "", 2); code != http.StatusOK {
		t.Errorf("preview at the floor = %d body=%s; want 200", code, body)
	}
	if code, body := post("/api/v1/ca/ceremonies", "f264-start-three", 3); code != http.StatusCreated {
		t.Errorf("start above the floor = %d body=%s; want 201", code, body)
	}
	started := 0
	if err := log.Replay(ctx, 0, func(e events.Event) error {
		if e.Type != projections.EventCACeremonyStarted || e.TenantID != servedTestTenant {
			return nil
		}
		var c projections.CACeremonyStarted
		if err := json.Unmarshal(e.Data, &c); err != nil {
			return err
		}
		started++
		if c.Threshold < 2 {
			t.Errorf("ceremony %s was recorded with threshold %d below the configured floor", c.CeremonyID, c.Threshold)
		}
		return nil
	}); err != nil {
		t.Fatalf("replay events: %v", err)
	}
	if started != 1 {
		t.Errorf("recorded ceremony starts = %d, want 1 (only the start above the floor)", started)
	}
}
