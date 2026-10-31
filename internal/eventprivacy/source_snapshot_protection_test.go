// SPDX-License-Identifier: BUSL-1.1
package eventprivacy_test

import (
	"bytes"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/store"
)

func snapshotSourceBinding(tenant string, cut uint64) eventprotect.Context {
	return eventprotect.Context{Scope: eventprotect.ScopeSnapshot, Type: "read_model_snapshot", TenantID: tenant,
		ID: "9c9ad802-f619-4aba-a84e-9044825dd337:" + strconv.FormatUint(cut, 10) + ":1:" + strings.Repeat("a", 64), SchemaVersion: store.SnapshotFormatVersion, Time: time.Now().UTC()}
}

func TestSnapshotSourceProtectionUsesExactCutAndOriginalCurrentCustody(t *testing.T) {
	reader, log, custody, directory, ref, authorizer := currentCustodyFixture(t)
	cut, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	provider := eventprivacy.SourceSnapshotProtection{Policy: reader.Policy, Custody: custody}
	binding := snapshotSourceBinding(ref.TenantID, cut)
	raw := []byte("original private snapshot chunk")
	unknown := snapshotSourceBinding("fe04b949-2c14-4c68-9f14-91a365cb44e6", cut)
	if _, protected, err := provider.ProtectSnapshotChunk(t.Context(), unknown, raw); err == nil || protected {
		t.Error("an unregistered cut was treated as a never-enabled tenant")
	}
	if erased, err := provider.RestorePlainSnapshot(t.Context(), unknown, raw); err == nil || erased {
		t.Error("an unregistered cut admitted plaintext snapshot data")
	}
	envelope, protected, err := provider.ProtectSnapshotChunk(t.Context(), binding, raw)
	if err != nil || !protected || envelope.KeyID != ref.ID {
		t.Fatalf("snapshot did not use exact source creation: %v", err)
	}
	opened, erased, err := provider.OpenSnapshotChunk(t.Context(), binding, envelope)
	if err != nil || erased || !bytes.Equal(opened, raw) {
		t.Fatalf("active snapshot chunk changed: %v", err)
	}
	if erased, err := provider.RestorePlainSnapshot(t.Context(), binding, raw); err == nil || erased {
		t.Fatal("plaintext bypassed opted-in snapshot protection")
	}
	foreign := binding
	foreign.Scope = eventprotect.ScopePostgresRow
	if _, _, err := provider.OpenSnapshotChunk(t.Context(), foreign, envelope); err == nil {
		t.Fatal("SQL purpose accepted snapshot ciphertext")
	}
	path := directory + "/" + ref.TenantID + "/" + ref.ID + ".key"
	held := path + ".held-by-snapshot-test"
	if err := os.Rename(path, held); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := os.Stat(held); err == nil {
			_ = os.Rename(held, path)
		}
	})
	if _, erased, err := provider.OpenSnapshotChunk(t.Context(), binding, envelope); !errors.Is(err, eventprotect.ErrKey) || erased {
		t.Fatal("lost material became erased or readable")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("snapshot access regenerated missing material")
	}
	if err := os.Rename(held, path); err != nil {
		t.Fatal(err)
	}
	appendSource(t, log, "snapshot-source-offboard", "tenant.offboarded", time.Now().UTC(), struct {
		RowsDeleted int `json:"rows_deleted"`
	}{0})
	life, err := reader.Policy.LatestLifetime(t.Context(), ref.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	authorizer.want, err = eventprivacy.NewDestructionRequest(life)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := custody.Destroy(t.Context(), authorizer.want); err != nil {
		t.Fatal(err)
	}
	if opened, erased, err := provider.OpenSnapshotChunk(t.Context(), binding, envelope); err != nil || !erased || len(opened) != 0 {
		t.Fatalf("old snapshot lost current signed absence: %v", err)
	}
	if _, protected, err := provider.ProtectSnapshotChunk(t.Context(), binding, raw); err == nil || protected {
		t.Fatal("removed snapshot key became a writable fallback")
	}
	wrong, err := jose.GenerateRSASigningKey("snapshot-wrong-trust")
	if err != nil {
		t.Fatal(err)
	}
	provider.Policy.Trust = wrong.JWKS()
	if _, erased, err := provider.OpenSnapshotChunk(t.Context(), binding, envelope); err == nil || erased {
		t.Fatal("wrong independent trust admitted snapshot erasure")
	}
}
