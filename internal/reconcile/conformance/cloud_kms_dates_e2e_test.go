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

// A168-L3 Done-when (rounds): with key_dates_since set on both sides, a round
// between an AWS KMS account and the managed-key inventory compares each
// covered key's creation and deletion dates — KMS's own against the provider
// dates trstctl's lifecycle results recorded. Keys whose dates agree raise
// nothing; a deletion rescheduled at the provider and a covered key whose
// record has no provider date are witnessed as attribute conflicts; a key KMS
// created before key_dates_since is compared without dates, so it agrees.
func TestE2E_CloudKMSKeyDatesAreComparedSinceTheConfiguredMomentA168L3(t *testing.T) {
	const (
		accessKey = "AKIAA168L3E2E"
		secretKey = "a168l3-e2e-secret" // #nosec G101 -- fabricated fixture credential (CWE-798)
	)
	since := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	at := func(second int) time.Time { return time.Date(2026, 11, 13, 8, 0, second, 0, time.UTC) }
	h := newE2EHarness(t)
	tagged := map[string]string{"trstctl-managed-key-operation": "op"}
	stand := awskmstest.New("us-east-1", accessKey, secretKey, 100)
	t.Cleanup(stand.Close)
	stand.Put(
		awskmstest.Key{ID: "dated-agree", Spec: "ECC_NIST_P256", State: "Enabled", Tags: tagged, Created: at(1)},
		awskmstest.Key{ID: "dated-deleting", Spec: "ECC_NIST_P256", State: "PendingDeletion", Tags: tagged, Created: at(2), Deletes: at(2).Add(30 * 24 * time.Hour)},
		awskmstest.Key{ID: "rescheduled", Spec: "ECC_NIST_P256", State: "PendingDeletion", Tags: tagged, Created: at(3), Deletes: at(3).Add(7 * 24 * time.Hour)},
		awskmstest.Key{ID: "older", Spec: "ECC_NIST_P256", State: "Enabled", Tags: tagged, Created: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)},
		awskmstest.Key{ID: "unrecorded", Spec: "ECC_NIST_P256", State: "Enabled", Tags: tagged, Created: at(5)},
	)
	if _, err := h.store.SystemPool().Exec(h.ctx, `INSERT INTO tenants (tenant_id, name) VALUES ($1, 'a168l3 tenant') ON CONFLICT DO NOTHING`, h.tenant); err != nil {
		t.Fatalf("register tenant: %v", err)
	}
	now := time.Now().UTC()
	for _, row := range []struct {
		keyID, state      string
		created, deletion *time.Time
	}{
		{"dated-agree", "active", ptr(at(1)), nil},
		{"dated-deleting", "deletion_pending", ptr(at(2)), ptr(at(2).Add(30 * 24 * time.Hour))},
		{"rescheduled", "deletion_pending", ptr(at(3)), ptr(at(3).Add(30 * 24 * time.Hour))},
		{"older", "active", nil, nil},
		{"unrecorded", "active", nil, nil},
	} {
		if _, err := h.store.SystemPool().Exec(h.ctx, `INSERT INTO managed_keys
			(tenant_id, provider, key_id, algorithm, version, state, public_der, created_at, updated_at, provider_created_at, provider_deletion_at)
			VALUES ($1, 'aws', $2, 'ECDSA-P256', 1, $3, '\x30'::bytea, $4, $4, $5, $6)`,
			h.tenant, row.keyID, row.state, now, row.created, row.deletion); err != nil {
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
		Schedules:     []rounds.Config{{TenantID: h.tenant, Cadence: 2 * time.Second, Liveness: time.Hour, Planes: []rounds.PlaneConfig{plane("aws-kms-dates"), plane("managed-keys-dates")}}},
		RoundInterval: 200 * time.Millisecond,
		CloudKMSSources: []eereconcile.AWSKMSSourceConfig{{
			AuthorityID: "aws-kms-dates", Region: "us-east-1", Address: stand.URL(),
			AccessKeyIDFile: accessFile, SecretAccessKeyFile: secretFile, AllowInsecureLoopback: true, KeyDatesSince: since,
		}},
		ManagedKeyAuthorities: []eereconcile.ManagedKeyAuthorityConfig{{AuthorityID: "managed-keys-dates", Provider: "aws-kms", KeyDatesSince: since}},
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
			t.Fatalf("no witness within 2 minutes: the dates were not compared (have %v)", byPair)
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
	expected := map[string]bool{stable("rescheduled"): true, stable("unrecorded"): true}
	recorded, ok := byPair["aws-kms-dates|managed-keys-dates"]
	if !ok {
		t.Fatalf("no witness for the KMS pair (have %v)", byPair)
	}
	entries := recorded.Evidence.Body.Entries
	if len(entries) != len(expected) {
		t.Fatalf("witness entries = %+v; want exactly the rescheduled deletion and the unrecorded creation date", entries)
	}
	for _, entry := range entries {
		if !expected[entry.RecordKey.StableID] || entry.Class != witness.ClassAttributeConflict {
			t.Fatalf("entry %+v; want an attribute conflict on rescheduled or unrecorded", entry)
		}
	}
	if stand.Mutations() != 0 || stand.Refused() != 0 {
		t.Fatalf("the observation changed the account (%d) or signed badly (%d)", stand.Mutations(), stand.Refused())
	}
}

func ptr(t time.Time) *time.Time { return &t }
