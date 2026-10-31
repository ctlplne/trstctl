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
	"trstctl.com/trstctl/internal/reconcile/awskmstest"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/rounds"
	"trstctl.com/trstctl/internal/reconcile/witness"
)

// A168 Done-when: the cloud-kms reducer has a source. A round between an AWS
// KMS account and the tenant's managed-key inventory witnesses exactly the
// drift between them: a key trstctl tagged as its own that the inventory does
// not hold, a managed key the account no longer holds, and a key disabled at
// the provider while trstctl still holds it active. Keys that agree — a larger
// curve the two sides spell differently, a revoked key the provider shows
// disabled, a key scheduled for deletion on both — raise nothing, and an
// untagged or AWS-managed key is not asserted at all.
func TestE2E_CloudKMSAccountRoundsAgainstManagedKeys(t *testing.T) {
	const (
		accessKey = "AKIAA168E2E"
		secretKey = "a168-e2e-secret" // #nosec G101 -- fabricated fixture credential (CWE-798)
	)
	h := newE2EHarness(t)
	tagged := map[string]string{"trstctl-managed-key-operation": "op"}
	stand := awskmstest.New("us-east-1", accessKey, secretKey, 100)
	t.Cleanup(stand.Close)
	stand.Put(
		awskmstest.Key{ID: "agree-p256", Spec: "ECC_NIST_P256", State: "Enabled", Tags: tagged},
		awskmstest.Key{ID: "agree-p384", Spec: "ECC_NIST_P384", State: "Enabled", Tags: tagged},
		awskmstest.Key{ID: "agree-revoked", Spec: "RSA_3072", State: "Disabled", Tags: tagged},
		awskmstest.Key{ID: "agree-deleting", Spec: "ECC_NIST_P256", State: "PendingDeletion", Tags: tagged},
		awskmstest.Key{ID: "drift-disabled", Spec: "ECC_NIST_P256", State: "Disabled", Tags: tagged},
		awskmstest.Key{ID: "only-in-kms", Spec: "ECC_NIST_P256", State: "Enabled", Tags: tagged},
		awskmstest.Key{ID: "untagged", Spec: "SYMMETRIC_DEFAULT", State: "Enabled"},
		awskmstest.Key{ID: "aws-managed", Spec: "SYMMETRIC_DEFAULT", State: "Enabled", Manager: "AWS", Tags: tagged},
	)
	now := time.Now().UTC()
	if _, err := h.store.SystemPool().Exec(h.ctx, `INSERT INTO tenants (tenant_id, name) VALUES ($1, 'a168 tenant') ON CONFLICT DO NOTHING`, h.tenant); err != nil {
		t.Fatalf("register tenant: %v", err)
	}
	for _, row := range []struct{ keyID, algorithm, state string }{
		{"agree-p256", "ECDSA-P256", "active"},
		{"agree-p384", "ECDSA-P384", "superseded"},
		{"agree-revoked", "RSA-3072", "revoked"},
		{"agree-deleting", "ECDSA-P256", "deletion_pending"},
		{"drift-disabled", "ECDSA-P256", "active"},
		{"only-in-inventory", "ECDSA-P256", "active"},
	} {
		if _, err := h.store.SystemPool().Exec(h.ctx, `INSERT INTO managed_keys
			(tenant_id, provider, key_id, algorithm, version, state, public_der, created_at, updated_at)
			VALUES ($1, 'aws', $2, $3, 1, $4, '\x30'::bytea, $5, $5)`, h.tenant, row.keyID, row.algorithm, row.state, now); err != nil {
			t.Fatalf("seed managed key %s: %v", row.keyID, err)
		}
	}
	dir := t.TempDir()
	accessFile, secretFile := filepath.Join(dir, "access"), filepath.Join(dir, "secret")
	if err := os.WriteFile(accessFile, []byte(accessKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte(secretKey), 0o600); err != nil {
		t.Fatal(err)
	}

	plane := func(id string) rounds.PlaneConfig { return rounds.PlaneConfig{AuthorityID: id, Liveness: time.Hour} }
	rt, err := eereconcile.NewRuntime(eereconcile.RuntimeConfig{
		Store:         h.store,
		Log:           h.log,
		Idempotency:   orchestrator.NewIdempotency(h.store),
		Signer:        e2eSignerProvider{client: h.client},
		Logger:        slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Schedules:     []rounds.Config{{TenantID: h.tenant, Cadence: 2 * time.Second, Liveness: time.Hour, Planes: []rounds.PlaneConfig{plane("aws-kms-lab"), plane("managed-keys-aws")}}},
		RoundInterval: 200 * time.Millisecond,
		CloudKMSSources: []eereconcile.AWSKMSSourceConfig{{
			AuthorityID: "aws-kms-lab", Region: "us-east-1", Address: stand.URL(),
			AccessKeyIDFile: accessFile, SecretAccessKeyFile: secretFile, AllowInsecureLoopback: true,
		}},
		ManagedKeyAuthorities: []eereconcile.ManagedKeyAuthorityConfig{{AuthorityID: "managed-keys-aws", Provider: "aws-kms"}},
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
		if len(byPair) == 1 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("no witness within 2 minutes (have %v)", byPair)
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
	expected := map[string]struct{ class, holder string }{
		stable("drift-disabled"):    {witness.ClassAttributeConflict, ""},
		stable("only-in-kms"):       {witness.ClassPresence, "aws-kms-lab"},
		stable("only-in-inventory"): {witness.ClassPresence, "managed-keys-aws"},
	}
	recorded, ok := byPair["aws-kms-lab|managed-keys-aws"]
	if !ok {
		t.Fatalf("no witness for the KMS pair (have %v)", byPair)
	}
	entries := recorded.Evidence.Body.Entries
	if len(entries) != len(expected) {
		t.Fatalf("witness entries = %+v; want exactly the disabled drift, the KMS-only and the inventory-only key", entries)
	}
	for _, entry := range entries {
		w, ok := expected[entry.RecordKey.StableID]
		if !ok || entry.Class != w.class || (w.holder != "" && entry.PresentAuthority != w.holder) {
			t.Fatalf("entry %+v; want one of %+v", entry, expected)
		}
	}
	if stand.Mutations() != 0 || stand.Refused() != 0 {
		t.Fatalf("the observation changed the account (%d) or signed badly (%d)", stand.Mutations(), stand.Refused())
	}
}
