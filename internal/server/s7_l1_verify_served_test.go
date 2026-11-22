// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

// TestS7L1VerifyServedFullRestoreRefusesAForgedPostgresStateArtifact (R1 verify
// VC3, S7-L1). End to end through the operator entry points: RunFullBackup (in
// the fixture) writes the keyed postgres-state artifact; someone who can write
// the backup directory adds one api_tokens row, recomputes the unkeyed SHA-256
// trailer and the unauthenticated manifest's sha256/bytes; RunFullRestore on a
// target holding the SAME deployment KEK (as restoreEventLog requires) must
// refuse it even when no optional pinned manifest key is configured.
func TestS7L1VerifyServedFullRestoreRefusesAForgedPostgresStateArtifact(t *testing.T) {
	info := eventProtectionPostgresBackupFixture(t, time.Hour, false)
	cfg := info.Config
	pgPath := filepath.Join(info.Directory, "postgres-state.jsonl")
	genuine, err := os.ReadFile(pgPath) // #nosec G304 -- test reads its own fixture path
	if err != nil {
		t.Fatal(err)
	}
	const attackerToken = "test-token"
	attackerHash := crypto.SHA256Hex([]byte(attackerToken))
	forged := s7VerifyForge(t, genuine, func(table string, row map[string]any) map[string]any {
		if table != "api_tokens" {
			return nil
		}
		extra := map[string]any{}
		for k, v := range row {
			extra[k] = v
		}
		extra["id"] = "a7770000-0000-4000-8000-0000000000f9"
		extra["tenant_id"] = info.Neighbor
		extra["token_hash"] = attackerHash
		extra["subject"] = "restored-admin"
		extra["subject_ref"] = ""
		extra["scopes"] = []string{"access:write", "keys:write", "secrets:read", "secrets:write", "identities:write"}
		return extra
	})

	// Controls on the target's own key: the target holds the same KEK, so the
	// key the restore could derive verifies the genuine artifact and refuses the
	// forgery.
	probe := protectedSQLRestoreTarget(t, cfg)
	key, err := backupIntegrityKey(probe)
	if err != nil || len(key) == 0 {
		t.Fatalf("control: target integrity key: len=%d err=%v", len(key), err)
	}
	defer secret.Wipe(key)
	if _, err := backup.VerifyPostgresStateWithKey(bytes.NewReader(genuine), key, backup.PostgresStateIdentity{}); err != nil {
		t.Fatalf("control: the genuine artifact does not verify under the target's own integrity key: %v", err)
	}
	if _, err := backup.VerifyPostgresStateWithKey(bytes.NewReader(forged), key, backup.PostgresStateIdentity{}); err == nil {
		t.Fatal("control: the forgery verified under the target's own integrity key")
	}

	if err := os.WriteFile(pgPath, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(info.Directory, backup.FullManifestName)
	manifest, err := backup.ReadFullManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	sum, n, err := backup.HashFile(pgPath)
	if err != nil {
		t.Fatal(err)
	}
	patched := false
	for i := range manifest.Artifacts {
		if manifest.Artifacts[i].Name == "postgres-state" {
			manifest.Artifacts[i].SHA256, manifest.Artifacts[i].Bytes = sum, n
			if manifest.Artifacts[i].PlaintextSHA256 != "" {
				manifest.Artifacts[i].PlaintextSHA256, manifest.Artifacts[i].PlaintextBytes = sum, n
			}
			patched = true
		}
	}
	if !patched {
		t.Fatal("manifest has no postgres-state artifact")
	}
	if err := backup.WriteFullManifest(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}

	// Control: with the optional pinned manifest key the forgery is refused.
	pinned := protectedSQLRestoreTarget(t, cfg)
	if len(pinned.Backup.TrustedManifestKeyFiles) == 0 {
		t.Fatal("control: fixture has no pinned manifest key")
	}
	if _, err := RunFullRestore(t.Context(), pinned, info.Directory); err == nil {
		t.Fatal("control: a pinned-manifest target restored the forgery")
	} else {
		t.Logf("control (pinned manifest key): RunFullRestore refused: %v", err)
	}

	// The default configuration: no pinned manifest key (the documented default).
	target := protectedSQLRestoreTarget(t, cfg)
	target.Backup.TrustedManifestKeyFiles = nil
	_, restoreErr := RunFullRestore(t.Context(), target, info.Directory)
	if restoreErr == nil || !strings.Contains(restoreErr.Error(), "HMAC") {
		t.Fatalf("forged PostgreSQL artifact restore error = %v; want HMAC refusal", restoreErr)
	}
	restored, err := store.Open(t.Context(), target.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restored.Close)
	if rec, err := restored.LookupAPITokenByHash(t.Context(), attackerHash); err == nil {
		t.Fatalf("S7-L1: RunFullRestore (err=%v) imported a forged api_tokens row; the attacker token authenticates: tenant=%s (neighbor=%v) subject=%s scopes=%v",
			restoreErr, rec.TenantID, rec.TenantID == info.Neighbor, rec.Subject, rec.Scopes)
	}
	t.Logf("restore err=%v", restoreErr)
}

func s7VerifyForge(t *testing.T, artifact []byte, add func(string, map[string]any) map[string]any) []byte {
	t.Helper()
	lines := bytes.Split(bytes.TrimRight(artifact, "\n"), []byte("\n"))
	if len(lines) < 2 {
		t.Fatalf("artifact has %d lines", len(lines))
	}
	var body bytes.Buffer
	body.Write(lines[0])
	body.WriteByte('\n')
	added := map[string]int{}
	for _, line := range lines[1 : len(lines)-1] {
		body.Write(line)
		body.WriteByte('\n')
		var rec struct {
			Table string         `json:"table"`
			Row   map[string]any `json:"row"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("decode artifact row: %v", err)
		}
		if added[rec.Table] > 0 {
			continue
		}
		extra := add(rec.Table, rec.Row)
		if extra == nil {
			continue
		}
		encoded, err := json.Marshal(struct {
			Table string         `json:"table"`
			Row   map[string]any `json:"row"`
		}{rec.Table, extra})
		if err != nil {
			t.Fatal(err)
		}
		body.Write(encoded)
		body.WriteByte('\n')
		added[rec.Table]++
	}
	if len(added) == 0 {
		t.Fatal("the forgery added no row")
	}
	var trailer map[string]any
	if err := json.Unmarshal(lines[len(lines)-1], &trailer); err != nil {
		t.Fatalf("decode trailer: %v", err)
	}
	if trailer["hmac_sha256"] == nil || trailer["hmac_sha256"] == "" {
		t.Fatal("the genuine artifact carries no HMAC to bypass")
	}
	tables, _ := trailer["tables"].(map[string]any)
	total := 0
	for table, n := range added {
		count, _ := tables[table].(float64)
		tables[table] = int(count) + n
		total += n
	}
	records, _ := trailer["records"].(float64)
	trailer["records"] = int(records) + total
	trailer["sha256"] = crypto.SHA256Hex(body.Bytes())
	encoded, err := json.Marshal(trailer)
	if err != nil {
		t.Fatal(err)
	}
	body.Write(encoded)
	body.WriteByte('\n')
	return body.Bytes()
}
