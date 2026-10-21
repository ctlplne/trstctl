// SPDX-License-Identifier: BUSL-1.1

package reconcile_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/reconcile"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers"
)

// vaultDouble is a Vault/OpenBao HTTP API double: KV v2 metadata (nested, one
// soft-deleted secret), two PKI-issued certificates (one revoked) and two
// Transit keys (symmetric and asymmetric version shapes). It refuses any read
// of secret DATA and records every path it was asked for.
type vaultDouble struct {
	t     *testing.T
	mu    sync.Mutex
	paths []string
	certA string
	certB string
}

func (d *vaultDouble) record(p string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.paths = append(d.paths, p)
}

func (d *vaultDouble) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.paths...)
}

func (d *vaultDouble) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.record(r.Method + " " + r.URL.Path + "?" + r.URL.RawQuery)
	if r.Header.Get("X-Vault-Token") != "lab-double-token" {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		return
	}
	if strings.Contains(r.URL.Path, "/data/") {
		d.t.Errorf("observation read secret data: %s", r.URL.Path)
		http.Error(w, `{"errors":["data path refused"]}`, http.StatusInternalServerError)
		return
	}
	list := r.URL.Query().Get("list") == "true"
	write := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": v})
	}
	switch {
	case list && r.URL.Path == "/v1/secret/metadata":
		write(map[string]any{"keys": []string{"app/", "root-token"}})
	case list && r.URL.Path == "/v1/secret/metadata/app":
		write(map[string]any{"keys": []string{"db", "gone"}})
	case r.URL.Path == "/v1/secret/metadata/root-token":
		write(map[string]any{"created_time": "2026-09-01T00:00:00Z", "current_version": 3, "versions": map[string]any{
			"3": map[string]any{"created_time": "2026-10-01T00:00:00Z", "deletion_time": "", "destroyed": false}}})
	case r.URL.Path == "/v1/secret/metadata/app/db":
		write(map[string]any{"created_time": "2026-09-02T00:00:00Z", "current_version": 1, "versions": map[string]any{
			"1": map[string]any{"created_time": "2026-09-02T00:00:00Z", "deletion_time": "", "destroyed": false}}})
	case r.URL.Path == "/v1/secret/metadata/app/gone":
		write(map[string]any{"created_time": "2026-09-03T00:00:00Z", "current_version": 2, "versions": map[string]any{
			"2": map[string]any{"created_time": "2026-09-04T00:00:00Z", "deletion_time": "2026-10-05T00:00:00Z", "destroyed": false}}})
	case list && r.URL.Path == "/v1/pki/certs":
		write(map[string]any{"keys": []string{"0a-11", "0b-22"}})
	case r.URL.Path == "/v1/pki/cert/0a-11":
		write(map[string]any{"certificate": d.certA, "revocation_time": 0})
	case r.URL.Path == "/v1/pki/cert/0b-22":
		write(map[string]any{"certificate": d.certB, "revocation_time": 1760000000})
	case list && r.URL.Path == "/v1/transit/keys":
		write(map[string]any{"keys": []string{"sym", "sign"}})
	case r.URL.Path == "/v1/transit/keys/sym":
		write(map[string]any{"type": "aes256-gcm96", "latest_version": 2, "keys": map[string]any{"1": 1750000000, "2": 1760000000}})
	case r.URL.Path == "/v1/transit/keys/sign":
		write(map[string]any{"type": "ecdsa-p256", "latest_version": 1, "keys": map[string]any{"1": map[string]any{"creation_time": "2026-08-01T00:00:00Z", "name": "P-256"}}})
	case list && r.URL.Path == "/v1/empty/metadata":
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	default:
		http.Error(w, `{"errors":["no handler for `+r.URL.Path+`"]}`, http.StatusNotFound)
	}
}

func newVaultDouble(t *testing.T) (*vaultDouble, *httptest.Server, string) {
	t.Helper()
	certA, err := os.ReadFile(filepath.Join("testdata", "vault-pki-a.pem"))
	if err != nil {
		t.Fatal(err)
	}
	certB, err := os.ReadFile(filepath.Join("testdata", "vault-pki-b.pem"))
	if err != nil {
		t.Fatal(err)
	}
	d := &vaultDouble{t: t, certA: string(certA), certB: string(certB)}
	ts := httptest.NewServer(d)
	t.Cleanup(ts.Close)
	tokenFile := filepath.Join(t.TempDir(), "vault-token")
	if err := os.WriteFile(tokenFile, []byte("lab-double-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return d, ts, tokenFile
}

// A configured Vault authority is observed through the production runtime
// registry: KV metadata, PKI certificates and Transit keys land on the shared
// canonical vocabulary, secret data is never read, and the unconfigured
// "vault" placeholder still fails closed.
func TestRuntime_VaultAuthorityObservesConfiguredServer(t *testing.T) {
	d, ts, tokenFile := newVaultDouble(t)
	rt, err := reconcile.NewRuntime(reconcile.RuntimeConfig{VaultSources: []reconcile.VaultSourceConfig{{
		AuthorityID:           "vault-lab",
		Address:               ts.URL,
		TokenFile:             tokenFile,
		KVMounts:              []string{"secret", "empty"},
		PKIMounts:             []string{"pki"},
		TransitMounts:         []string{"transit"},
		AllowInsecureLoopback: true,
	}}})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	const tenant = "11111111-1111-1111-1111-111111111111"
	obs, err := rt.Reducers.Observe(context.Background(), "vault-lab", tenant)
	if err != nil {
		t.Fatalf("observe vault-lab: %v", err)
	}
	if obs.AuthorityID != "vault-lab" || obs.Denied != 0 || !strings.HasPrefix(obs.Watermark.Position, "vault:vault-lab@") {
		t.Fatalf("observation header: %+v", obs)
	}
	byType := map[string]int{}
	byStatus := map[string]int{}
	algorithms := map[string]bool{}
	for _, rec := range obs.Set.Records {
		byType[rec.RecordType]++
		byStatus[rec.Status]++
		algorithms[rec.Algorithm] = true
	}
	if byType[canon.RecordTypeSecretRef] != 3 || byType[canon.RecordTypeX509Certificate] != 2 || byType[canon.RecordTypeKey] != 2 {
		t.Fatalf("record types = %v (want 3 secret refs, 2 certificates, 2 keys)", byType)
	}
	if byStatus[canon.StatusPendingDeletion] != 1 || byStatus[canon.StatusRevoked] != 1 || byStatus[canon.StatusActive] != 5 {
		t.Fatalf("statuses = %v", byStatus)
	}
	// canon keeps a deliberately narrow algorithm vocabulary; the Transit
	// symmetric key type maps to a deterministic unknown-<digest> label that
	// two authorities observing the same type still agree on.
	for _, want := range []string{"rsa-2048", "ecdsa-p256"} {
		if !algorithms[want] {
			t.Fatalf("algorithm %q missing from %v", want, algorithms)
		}
	}
	if !algorithms[canon.NormalizeAlgorithm("aes256-gcm96")] {
		t.Fatalf("symmetric transit key type not observed in %v", algorithms)
	}
	for _, p := range d.seen() {
		if strings.Contains(p, "/data/") {
			t.Fatalf("secret data was requested: %s", p)
		}
	}
	if _, err := rt.Reducers.Observe(context.Background(), "vault", tenant); !errors.Is(err, reducers.ErrMissingSource) {
		t.Fatalf("unconfigured vault authority must fail closed, got %v", err)
	}
}

// A token the server rejects, or a missing token file, fails the observation
// instead of producing an empty (falsely agreeing) set.
func TestRuntime_VaultAuthorityFailsClosedOnBadCredentials(t *testing.T) {
	_, ts, tokenFile := newVaultDouble(t)
	if err := os.WriteFile(tokenFile, []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	rt, err := reconcile.NewRuntime(reconcile.RuntimeConfig{VaultSources: []reconcile.VaultSourceConfig{{
		AuthorityID: "vault-lab", Address: ts.URL, TokenFile: tokenFile, KVMounts: []string{"secret"}, AllowInsecureLoopback: true,
	}}})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if _, err := rt.Reducers.Observe(context.Background(), "vault-lab", "11111111-1111-1111-1111-111111111111"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("rejected token must fail the observation, got %v", err)
	}
	if _, err := reconcile.NewRuntime(reconcile.RuntimeConfig{VaultSources: []reconcile.VaultSourceConfig{{
		AuthorityID: "vault-plain", Address: "http://vault.internal:8200", TokenFile: tokenFile, KVMounts: []string{"secret"},
	}}}); err == nil || !strings.Contains(err.Error(), "allow_insecure_loopback") {
		t.Fatalf("plain http without the loopback allowance must be refused at build, got %v", err)
	}
}
