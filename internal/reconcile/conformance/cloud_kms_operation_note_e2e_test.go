// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package conformance

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/managedkeystate"
	"trstctl.com/trstctl/internal/orchestrator"
	eereconcile "trstctl.com/trstctl/internal/reconcile"
	"trstctl.com/trstctl/internal/reconcile/awskmstest"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/rounds"
	"trstctl.com/trstctl/internal/reconcile/witness"
)

// A168-L4 Done-when (rounds): a key trstctl's own generate operation created
// at AWS KMS, whose completion trstctl never recorded, is witnessed as held
// only by the account — and the witness entry names that operation, its
// action and its state, and where to read it. A key only the account holds
// that no unfinished trstctl operation stamped carries no note.
func TestE2E_CloudKMSWitnessNamesTheUnfinishedOperationA168L4(t *testing.T) {
	const (
		accessKey = "AKIAA168L4E2E"
		secretKey = "a168l4-e2e-secret" // #nosec G101 -- fabricated fixture credential (CWE-798)
		operation = "managedkey:a168l4-queued-generate"
	)
	h := newE2EHarness(t)
	stamp := managedkeystate.OperationStamp("generate", operation, "", "ECDSA-P256")
	stand := awskmstest.New("us-east-1", accessKey, secretKey, 100)
	t.Cleanup(stand.Close)
	stand.Put(
		awskmstest.Key{ID: "agree", Spec: "ECC_NIST_P256", State: "Enabled", Tags: map[string]string{"trstctl-managed-key-operation": strings.Repeat("a", 64)}},
		awskmstest.Key{ID: "unrecorded", Spec: "ECC_NIST_P256", State: "Enabled", Tags: map[string]string{"trstctl-managed-key-operation": stamp}},
		awskmstest.Key{ID: "unexplained", Spec: "ECC_NIST_P256", State: "Enabled", Tags: map[string]string{"trstctl-managed-key-operation": "op"}},
	)
	if _, err := h.store.SystemPool().Exec(h.ctx, `INSERT INTO tenants (tenant_id, name) VALUES ($1, 'a168l4 tenant') ON CONFLICT DO NOTHING`, h.tenant); err != nil {
		t.Fatalf("register tenant: %v", err)
	}
	now := time.Now().UTC()
	if _, err := h.store.SystemPool().Exec(h.ctx, `INSERT INTO managed_keys
		(tenant_id, provider, key_id, algorithm, version, state, public_der, created_at, updated_at)
		VALUES ($1, 'aws', 'agree', 'ECDSA-P256', 1, 'active', '\x30'::bytea, $2, $2)`, h.tenant, now); err != nil {
		t.Fatalf("seed managed key: %v", err)
	}
	if _, err := h.store.SystemPool().Exec(h.ctx, `INSERT INTO managed_key_operations
		(tenant_id, operation_id, provider, action, key_id, algorithm, status, outbox_id, created_at, updated_at)
		VALUES ($1, $2, 'aws-kms', 'generate', '', 'ECDSA-P256', 'queued', 0, $3, $3)`, h.tenant, operation, now); err != nil {
		t.Fatalf("seed the unfinished operation: %v", err)
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
		Schedules:     []rounds.Config{{TenantID: h.tenant, Cadence: 2 * time.Second, Liveness: time.Hour, Planes: []rounds.PlaneConfig{plane("aws-kms-notes"), plane("managed-keys-notes")}}},
		RoundInterval: 200 * time.Millisecond,
		CloudKMSSources: []eereconcile.AWSKMSSourceConfig{{
			AuthorityID: "aws-kms-notes", Region: "us-east-1", Address: stand.URL(),
			AccessKeyIDFile: accessFile, SecretAccessKeyFile: secretFile, AllowInsecureLoopback: true,
		}},
		ManagedKeyAuthorities: []eereconcile.ManagedKeyAuthorityConfig{{AuthorityID: "managed-keys-notes", Provider: "aws-kms"}},
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
	recorded, ok := byPair["aws-kms-notes|managed-keys-notes"]
	if !ok {
		t.Fatalf("no witness for the KMS pair (have %v)", byPair)
	}
	entries := map[string]witness.Entry{}
	for _, entry := range recorded.Evidence.Body.Entries {
		entries[entry.RecordKey.StableID] = entry
	}
	unrecorded, unexplained := entries[stable("unrecorded")], entries[stable("unexplained")]
	if len(entries) != 2 || unrecorded.Class != witness.ClassPresence || unexplained.Class != witness.ClassPresence {
		t.Fatalf("witness entries = %+v; want the two keys only the account holds", recorded.Evidence.Body.Entries)
	}
	if !strings.Contains(unrecorded.Note, operation+" (generate, queued)") || !strings.Contains(unrecorded.Note, "/api/v1/managed-keys/operations/"+operation) {
		t.Fatalf("the unrecorded key's note = %q; want the queued generate operation named", unrecorded.Note)
	}
	if unexplained.Note != "" {
		t.Fatalf("a key no unfinished operation stamped was explained: %q", unexplained.Note)
	}
	if stand.Mutations() != 0 || stand.Refused() != 0 {
		t.Fatalf("the observation changed the account (%d) or signed badly (%d)", stand.Mutations(), stand.Refused())
	}
}
