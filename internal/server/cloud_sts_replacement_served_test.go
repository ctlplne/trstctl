// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/dynsecret"
)

func TestServedCloudReplacementSTSIdentityProofA264(t *testing.T) {
	endpoint, path := os.Getenv("TRSTCTL_A264_IAM_ENDPOINT"), os.Getenv("TRSTCTL_A264_IAM_SESSION_FILE")
	if endpoint == "" || path == "" {
		t.Skip("owned STS endpoint/session file and a264-replacement553 role required")
	}
	raw, err := secretfile.LoadBounded(path, 64<<10)
	if err != nil {
		t.Fatal("owned session file could not be read")
	}
	defer secret.Wipe(raw)
	var bootstrap struct {
		Credentials struct {
			AccessKeyID     string           `json:"AccessKeyId"`
			SecretAccessKey secret.JSONBytes `json:"SecretAccessKey"`
			SessionToken    secret.JSONBytes `json:"SessionToken"`
		}
	}
	if json.Unmarshal(raw, &bootstrap) != nil {
		t.Fatal("owned bootstrap document invalid")
	}
	defer secret.Wipe(bootstrap.Credentials.SecretAccessKey)
	defer secret.Wipe(bootstrap.Credentials.SessionToken)
	dir := t.TempDir()
	keyPath, tokenPath := filepath.Join(dir, "authority"), filepath.Join(dir, "session")
	if os.WriteFile(keyPath, bootstrap.Credentials.SecretAccessKey, 0600) != nil || os.WriteFile(tokenPath, bootstrap.Credentials.SessionToken, 0600) != nil {
		t.Fatal("private test authority files could not be written")
	}
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "replacement-sts", Type: "aws-sts", Endpoint: endpoint, IAMEndpoint: endpoint, Region: "us-east-1", AccessKeyID: bootstrap.Credentials.AccessKeyID, SecretAccessRef: "file:" + keyPath, SessionTokenRef: "file:" + tokenPath, AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "arn:aws:iam::000000000000:role/a264-replacement553"}, MaxTTL: "20m", AllowInsecureLoopback: true}
	registry, err := dynamicSecretProvidersFromConfig(t.Context(), []config.DynamicSecretProviderConfig{cfg}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) { d.TenantDynamicSecretProviders = registry })
	startServedExternalCADispatcher(t, h)
	operator := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", operator, "a264-native-replacement-session", map[string]any{"provider": cfg.ID, "role": "reader", "ttl_seconds": 900})
	defer secret.Wipe(body)
	if status != http.StatusCreated {
		t.Fatalf("native replacement lease status: %d", status)
	}
	var lease struct {
		ID         string           `json:"id"`
		Credential secret.JSONBytes `json:"credential"`
	}
	if json.Unmarshal(body, &lease) != nil || lease.ID == "" || len(lease.Credential) == 0 {
		t.Fatal("native replacement lease was not delivered")
	}
	defer secret.Wipe(lease.Credential)
	verifier, ok := registry.ForTenant(h.tenant)[0].(dynsecret.LeaseCredentialVerifier)
	if !ok {
		t.Fatal("replacement provider has no credential proof")
	}
	mode, err := verifier.VerifyLeaseCredential(t.Context(), lease.Credential)
	if err != nil || mode != "authenticated" {
		t.Fatalf("native STS session identity proof unavailable: mode=%s err=%v", mode, err)
	}
	wrong := cfg
	wrong.RoleBindings = map[string]string{"reader": "arn:aws:iam::000000000000:role/not-the-approved-role"}
	other, err := dynamicSecretProvidersFromConfig(t.Context(), []config.DynamicSecretProviderConfig{wrong}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.ForTenant(h.tenant)[0].(dynsecret.LeaseCredentialVerifier).VerifyLeaseCredential(t.Context(), lease.Credential); err == nil {
		t.Fatal("issued session for a different allowed role passed replacement proof")
	}
	// Publish a temporary credential through the existing durable rotation
	// surface. This is preparation; reviewed old-key retirement remains separate.
	status, seedBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", operator, "a264-sts-publication-seed", map[string]any{"name": "reader", "value": secret.JSONBytes([]byte("owned-fixture-placeholder"))})
	secret.Wipe(seedBody)
	if status != http.StatusCreated {
		t.Fatalf("publication seed status: %d", status)
	}
	status, queued := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", operator, "a264-sts-publication", map[string]any{"provider": "dynamic-lease:replacement-sts", "key": "reader", "old_ref": "none", "ttl_seconds": 900})
	var command struct {
		ID string `json:"command_id"`
	}
	if status != http.StatusOK || json.Unmarshal(queued, &command) != nil || command.ID == "" {
		t.Fatalf("native STS publication unavailable: status=%d", status)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations/"+command.ID, operator, nil)
		var progress struct {
			Phase      string `json:"phase"`
			Terminal   bool   `json:"terminal"`
			VerifyMode string `json:"verify_mode"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &progress) != nil {
			t.Fatal("publication command unavailable")
		}
		if progress.Terminal {
			if progress.Phase != "completed" || progress.VerifyMode != "authenticated" {
				t.Fatalf("publication did not prove native STS identity: phase=%s mode=%s", progress.Phase, progress.VerifyMode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native STS publication did not finish")
		}
		time.Sleep(50 * time.Millisecond)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/reader", operator, nil)
	defer secret.Wipe(body)
	var published struct {
		Value   secret.JSONBytes `json:"value"`
		Version int              `json:"version"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &published) != nil || published.Version != 2 {
		t.Fatal("native STS credential was not published as the next sealed secret version")
	}
	defer secret.Wipe(published.Value)
	if mode, err := verifier.VerifyLeaseCredential(t.Context(), published.Value); err != nil || mode != "authenticated" {
		t.Fatalf("published replacement failed independent native identity readback: %v", err)
	}

}
