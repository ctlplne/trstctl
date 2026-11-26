// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretscan"
	"trstctl.com/trstctl/internal/store"
)

// CR-090. A process working directory grants no served filesystem authority.
func TestServedSecretScanningRequiresConfiguredRoots(t *testing.T) {
	workspace := t.TempDir()
	binary := filepath.Join(t.TempDir(), "scanner-file")
	if err := os.WriteFile(binary, []byte("fixture scanner"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.SecretScanGitleaksBin = binary
	})
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:write", "discovery:read")
	t.Chdir(workspace)
	for _, check := range []struct {
		path string
		key  string
		body map[string]string
	}{
		{"/api/v1/secrets/scans/preview", "fixture-preview", map[string]string{"path": workspace}},
		{"/api/v1/secrets/scans", "fixture-scan", map[string]string{"path": workspace}},
		{"/api/v1/secrets/scans/repositories/github/webhook", "fixture-checkout", map[string]string{
			"repository": "fixture/checkout", "checkout_path": workspace,
		}},
		{"/api/v1/secrets/scans/third-party/slack/ingest", "fixture-third-party", map[string]string{
			"source": "fixture/export", "artifact_path": binary,
		}},
	} {
		status, _ := secretsReqKey(t, h, http.MethodPost, check.path, tok, check.key, check.body)
		if status != http.StatusBadRequest {
			t.Errorf("%s returned %d without operator roots, want %d", check.path, status, http.StatusBadRequest)
		}
	}
	for _, eventType := range []string{"discovery.run.queued", "discovery.finding.recorded", "discovery.run.completed"} {
		if h.hasEvent(t, eventType) {
			t.Errorf("refused path request recorded %s", eventType)
		}
	}
}

// CR-090. An already-queued checkout must use the current worker allowlist.
func TestRepositoryWorkerRefusesRetainedCheckoutWithoutRoots(t *testing.T) {
	workspace := t.TempDir()
	binary := filepath.Join(t.TempDir(), "scanner-file")
	if err := os.WriteFile(binary, []byte("fixture scanner"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(workspace)
	dispatcher := issuanceDispatcher{secretRepoScanner: secretScannerFromDeps(Deps{SecretScanGitleaksBin: binary})}
	body, err := json.Marshal(secretscan.RepositoryScanConfig{Repository: "fixture/checkout", CheckoutPath: workspace})
	if err != nil {
		t.Fatal(err)
	}
	report, status, _, err := dispatcher.executeSecretRepositoryDiscoveryRun(t.Context(), servedTestTenant, store.DiscoverySource{
		Kind: secretscan.RepositorySourceKind, Config: body,
	}, projections.DiscoveryRunQueued{})
	if err != nil || status != "failed" || report.Targets != 0 {
		t.Fatalf("worker did not terminalize refused checkout before scan: status=%q targets=%d err=%v", status, report.Targets, err)
	}
}

// A source retained before root admission was added must still be refused by
// the worker before it opens an out-of-root signature file.
func TestThirdPartyWorkerRefusesRetainedSignatureOutsideRoots(t *testing.T) {
	root := t.TempDir()
	artifact := writeSecretArtifact(t, root, "export.jsonl", `{}`)
	signature := writeSecretArtifact(t, t.TempDir(), "export.sig", "not a signature")
	dispatcher := issuanceDispatcher{secretRepoScanner: secretscan.NewServedGitleaksRunner("", []string{root})}
	body, err := json.Marshal(secretscan.ThirdPartyScanConfig{
		Provider: secretscan.ThirdPartyProviderSlack, Source: "retained", ArtifactPath: artifact,
		SignaturePath: signature, SignerPublicKeyPEM: "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----",
	})
	if err != nil {
		t.Fatal(err)
	}
	report, status, reason, err := dispatcher.executeThirdPartySecretDiscoveryRun(t.Context(), servedTestTenant, store.DiscoverySource{
		Kind: secretscan.ThirdPartySourceKind, Config: body,
	}, projections.DiscoveryRunQueued{})
	if err != nil || status != "failed" || report.Targets != 0 || reason != "artifact path is outside configured scan roots or is not a regular file" {
		t.Fatalf("worker accepted retained signature path: status=%q reason=%q targets=%d err=%v", status, reason, report.Targets, err)
	}
}
