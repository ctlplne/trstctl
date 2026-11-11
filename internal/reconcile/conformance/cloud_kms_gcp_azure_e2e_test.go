// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package conformance

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
	eereconcile "trstctl.com/trstctl/internal/reconcile"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/cloudkmstest"
	"trstctl.com/trstctl/internal/reconcile/rounds"
	"trstctl.com/trstctl/internal/reconcile/witness"
)

// A168-L1 Done-when: GCP Cloud KMS and Azure Key Vault are cloud-kms sources
// too. A round between each and the tenant's managed-key inventory for that
// provider witnesses exactly the drift: a key trstctl created that the
// inventory does not hold, a managed key the provider no longer holds, and a
// key disabled at the provider while trstctl holds it active. Keys that agree
// (an active key, a revoked key the provider shows disabled, a key whose
// deletion both sides await) raise nothing, and a key another tenant created
// or one trstctl did not create is not asserted.
func TestE2E_GCPAndAzureKeysRoundAgainstManagedKeysA168L1(t *testing.T) {
	const (
		token = "stand-in-kms-token" // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
		ring  = "projects/a168l1/locations/us-east1/keyRings/trstctl"
		other = "22222222-3333-4444-8555-777777777777"
	)
	h := newE2EHarness(t)
	now := time.Now().UTC()
	if _, err := h.store.SystemPool().Exec(h.ctx, `INSERT INTO tenants (tenant_id, name) VALUES ($1, 'a168l1 tenant') ON CONFLICT DO NOTHING`, h.tenant); err != nil {
		t.Fatalf("register tenant: %v", err)
	}
	gcp := cloudkmstest.NewGCP(ring, token)
	t.Cleanup(gcp.Close)
	own := map[string]string{"trstctl-tenant": h.tenant}
	for id, v := range map[string]cloudkmstest.GCPVersion{
		"trstctl-g-agree":     {Number: 1, State: "ENABLED", Algorithm: "EC_SIGN_P256_SHA256"},
		"trstctl-g-revoked":   {Number: 1, State: "DISABLED", Algorithm: "RSA_SIGN_PKCS1_3072_SHA256"},
		"trstctl-g-deleting":  {Number: 1, State: "DESTROY_SCHEDULED", Algorithm: "EC_SIGN_P384_SHA384"},
		"trstctl-g-drift":     {Number: 1, State: "DISABLED", Algorithm: "EC_SIGN_P256_SHA256"},
		"trstctl-g-only-here": {Number: 1, State: "ENABLED", Algorithm: "EC_SIGN_P256_SHA256"},
	} {
		gcp.Put(cloudkmstest.GCPKey{ID: id, Labels: own, Versions: []cloudkmstest.GCPVersion{v}})
	}
	gcp.Put(cloudkmstest.GCPKey{ID: "trstctl-g-other", Labels: map[string]string{"trstctl-tenant": other},
		Versions: []cloudkmstest.GCPVersion{{Number: 1, State: "ENABLED", Algorithm: "EC_SIGN_P256_SHA256"}}})
	gcp.Put(cloudkmstest.GCPKey{ID: "billing", Versions: []cloudkmstest.GCPVersion{{Number: 1, State: "ENABLED", Algorithm: "GOOGLE_SYMMETRIC_ENCRYPTION"}}})

	azure := cloudkmstest.NewAzure(token)
	t.Cleanup(azure.Close)
	azure.Put(cloudkmstest.AzureKey{Name: "trstctl-generate-agree", Tags: own, Versions: []cloudkmstest.AzureVersion{{ID: "v1", Enabled: true, Crv: "P-256"}}})
	azure.Put(cloudkmstest.AzureKey{Name: "trstctl-generate-revoked", Tags: own, Versions: []cloudkmstest.AzureVersion{{ID: "v1", Enabled: false, RSABits: 3072}}})
	azure.Put(cloudkmstest.AzureKey{Name: "trstctl-generate-deleting", Tags: own, Deleted: true, Versions: []cloudkmstest.AzureVersion{{ID: "v1", Enabled: true, Crv: "P-384"}}})
	azure.Put(cloudkmstest.AzureKey{Name: "trstctl-generate-drift", Tags: own, Versions: []cloudkmstest.AzureVersion{{ID: "v1", Enabled: false, Crv: "P-256"}}})
	azure.Put(cloudkmstest.AzureKey{Name: "trstctl-generate-only-here", Tags: own, Versions: []cloudkmstest.AzureVersion{{ID: "v1", Enabled: true, Crv: "P-256"}}})
	azure.Put(cloudkmstest.AzureKey{Name: "trstctl-generate-other", Tags: map[string]string{"trstctl-tenant": other},
		Versions: []cloudkmstest.AzureVersion{{ID: "v1", Enabled: true, Crv: "P-256"}}})
	azure.Put(cloudkmstest.AzureKey{Name: "billing", Versions: []cloudkmstest.AzureVersion{{ID: "v1", Enabled: true, RSABits: 2048}}})

	seed := func(provider, keyID, algorithm, state string) {
		t.Helper()
		if _, err := h.store.SystemPool().Exec(h.ctx, `INSERT INTO managed_keys
			(tenant_id, provider, key_id, algorithm, version, state, public_der, created_at, updated_at)
			VALUES ($1, $2, $3, $4, 1, $5, '\x30'::bytea, $6, $6)`, h.tenant, provider, keyID, algorithm, state, now); err != nil {
			t.Fatalf("seed managed key %s: %v", keyID, err)
		}
	}
	for _, row := range []struct{ id, algorithm, state string }{
		{"trstctl-g-agree", "ECDSA-P256", "active"},
		{"trstctl-g-revoked", "RSA-3072", "revoked"},
		{"trstctl-g-deleting", "ECDSA-P384", "deletion_pending"},
		{"trstctl-g-drift", "ECDSA-P256", "active"},
		{"trstctl-g-only-recorded", "ECDSA-P256", "active"},
	} {
		seed("gcp-kms", gcp.VersionName(row.id, 1), row.algorithm, row.state)
	}
	for _, row := range []struct{ name, algorithm, state string }{
		{"trstctl-generate-agree", "ECDSA-P256", "active"},
		{"trstctl-generate-revoked", "RSA-3072", "revoked"},
		{"trstctl-generate-deleting", "ECDSA-P384", "deletion_pending"},
		{"trstctl-generate-drift", "ECDSA-P256", "active"},
		{"trstctl-generate-only-recorded", "ECDSA-P256", "active"},
	} {
		seed("azure-key-vault", azure.Kid(row.name, "v1"), row.algorithm, row.state)
	}
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	plane := func(id string) rounds.PlaneConfig { return rounds.PlaneConfig{AuthorityID: id, Liveness: time.Hour} }
	rt, err := eereconcile.NewRuntime(eereconcile.RuntimeConfig{
		Store:       h.store,
		Log:         h.log,
		Idempotency: orchestrator.NewIdempotency(h.store),
		Signer:      e2eSignerProvider{client: h.client},
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Schedules: []rounds.Config{
			{TenantID: h.tenant, Cadence: 2 * time.Second, Liveness: time.Hour, Planes: []rounds.PlaneConfig{plane("gcp-kms-lab"), plane("managed-keys-gcp")}},
			{TenantID: h.tenant, Cadence: 2 * time.Second, Liveness: time.Hour, Planes: []rounds.PlaneConfig{plane("azure-kv-lab"), plane("managed-keys-azure")}},
		},
		RoundInterval:     200 * time.Millisecond,
		GCPKMSSources:     []eereconcile.GCPKMSSourceConfig{{AuthorityID: "gcp-kms-lab", KeyRing: ring, Address: gcp.URL(), TokenFile: tokenFile, AllowInsecureLoopback: true}},
		AzureKVKeySources: []eereconcile.AzureKVKeySourceConfig{{AuthorityID: "azure-kv-lab", VaultURL: azure.URL(), TokenFile: tokenFile, AllowInsecureLoopback: true}},
		ManagedKeyAuthorities: []eereconcile.ManagedKeyAuthorityConfig{
			{AuthorityID: "managed-keys-gcp", Provider: "gcp-kms"}, {AuthorityID: "managed-keys-azure", Provider: "azure-key-vault"},
		},
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	workerCtx, cancel := context.WithCancel(h.ctx)
	done := make(chan error, 1)
	go func() { done <- rt.BackgroundWorkers[0].Run(workerCtx) }()
	var byPair map[string]witness.WitnessRecorded
	deadline := time.Now().Add(2 * time.Minute)
	for {
		byPair = firstWitnessPerPair(t, h.log)
		if len(byPair) == 2 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("no witness for both pairs within 2 minutes (have %v)", byPair)
		}
		time.Sleep(200 * time.Millisecond)
	}
	cancel()
	<-done
	stable := func(keyID string) string {
		t.Helper()
		id, err := canon.KeyStableID(keyID, nil)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	for pair, expected := range map[string]map[string]struct{ class, holder string }{
		"gcp-kms-lab|managed-keys-gcp": {
			stable(gcp.VersionName("trstctl-g-drift", 1)):         {witness.ClassAttributeConflict, ""},
			stable(gcp.VersionName("trstctl-g-only-here", 1)):     {witness.ClassPresence, "gcp-kms-lab"},
			stable(gcp.VersionName("trstctl-g-only-recorded", 1)): {witness.ClassPresence, "managed-keys-gcp"},
		},
		"azure-kv-lab|managed-keys-azure": {
			stable("keys/trstctl-generate-drift/v1"):         {witness.ClassAttributeConflict, ""},
			stable("keys/trstctl-generate-only-here/v1"):     {witness.ClassPresence, "azure-kv-lab"},
			stable("keys/trstctl-generate-only-recorded/v1"): {witness.ClassPresence, "managed-keys-azure"},
		},
	} {
		recorded, ok := byPair[pair]
		if !ok {
			t.Fatalf("no witness for %s (have %v)", pair, byPair)
		}
		entries := recorded.Evidence.Body.Entries
		if len(entries) != len(expected) {
			var seen []string
			for _, entry := range entries {
				seen = append(seen, entry.RecordKey.StableID+" "+entry.Class+" held by "+entry.PresentAuthority)
			}
			t.Fatalf("%s witness entries = %q; want exactly the disabled drift, the provider-only and the record-only key", pair, seen)
		}
		for _, entry := range entries {
			w, ok := expected[entry.RecordKey.StableID]
			if !ok || entry.Class != w.class || (w.holder != "" && entry.PresentAuthority != w.holder) {
				t.Fatalf("%s entry %+v; want one of %+v", pair, entry, expected)
			}
		}
	}
}
