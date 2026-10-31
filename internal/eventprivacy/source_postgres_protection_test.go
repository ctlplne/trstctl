// Real source/current-file-custody contract; fixture locks/authority, no PG or isolated process proof.
// SPDX-License-Identifier: BUSL-1.1
package eventprivacy_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
)

func postgresArtifactBinding(tenant string, cut uint64) eventprotect.Context {
	return eventprotect.Context{Scope: eventprotect.ScopePostgresRow, ID: "9c9ad802-f619-4aba-a84e-9044825dd337:" + strconv.FormatUint(cut, 10) + ":1:" + strings.Repeat("a", 64), Type: "api_tokens", TenantID: tenant, SchemaVersion: 2, Time: time.Now().UTC()}
}
func TestPostgresSourceProtectionUsesOriginalCutAndCurrentCustody(t *testing.T) {
	reader, log, custody, _, ref, authorizer := currentCustodyFixture(t)
	cut, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	provider := eventprivacy.SourcePostgresProtection{Policy: reader.Policy, Custody: custody, Cut: cut}
	binding := postgresArtifactBinding(ref.TenantID, cut)
	row, err := json.Marshal(map[string]string{"tenant_id": ref.TenantID, "subject": "source-sql@example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	envelope, protected, err := provider.ProtectPostgresRow(t.Context(), binding, row)
	if err != nil || !protected || envelope.KeyID != ref.ID {
		t.Fatalf("source key not selected: protected=%v err=%v", protected, err)
	}
	opened, erased, err := provider.OpenPostgresRow(t.Context(), binding, envelope)
	if err != nil || erased || !bytes.Equal(opened, row) {
		t.Fatalf("active source row failed: %v", err)
	}
	if _, _, err := provider.RestorePlainPostgresRow(t.Context(), 2, cut, ref.TenantID, row); err == nil {
		t.Fatal("v2 plaintext bypassed active tenant protection")
	}
	if got, erased, err := provider.RestorePlainPostgresRow(t.Context(), 1, cut, ref.TenantID, row); err != nil || erased || !bytes.Equal(got, row) {
		t.Fatal("legacy v1 representation changed without current erasure")
	}
	appendSource(t, log, "postgres-source-offboard", "tenant.offboarded", time.Now().UTC(), struct {
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
	receipt, err := custody.Destroy(t.Context(), authorizer.want)
	if err != nil || receipt == "" {
		t.Fatalf("real fixture key removal failed: %v", err)
	}
	opened, erased, err = provider.OpenPostgresRow(t.Context(), binding, envelope)
	if err != nil || !erased || len(opened) != 0 {
		t.Fatalf("older-cut row did not honor current signed absence: erased=%v err=%v", erased, err)
	}
	if got, erased, err := provider.RestorePlainPostgresRow(t.Context(), 1, cut, ref.TenantID, row); err != nil || !erased || len(got) != 0 {
		t.Fatal("legacy SQL resurrection was not suppressed")
	}
	earliest := provider
	earliest.Cut = 1
	if got, erased, err := earliest.RestorePlainPostgresRow(t.Context(), 1, 1, ref.TenantID, row); err != nil || !erased || len(got) != 0 {
		t.Fatalf("pre-activation SQL floor missing: %v", err)
	}
	wrong, err := jose.GenerateRSASigningKey("wrong-postgres-receipt-trust")
	if err != nil {
		t.Fatal(err)
	}
	altered := provider
	altered.Policy.Trust = wrong.JWKS()
	if _, erased, err := altered.OpenPostgresRow(t.Context(), binding, envelope); err == nil || erased {
		t.Fatal("receipt granted erasure under wrong independent trust")
	}
	if _, _, err := provider.ProtectPostgresRow(t.Context(), binding, row); err == nil {
		t.Fatal("removed key fell back to a new plaintext row")
	}
}
func TestPostgresSourceProtectionRefusesLostMaterialAndForeignBinding(t *testing.T) {
	reader, log, custody, directory, ref, _ := currentCustodyFixture(t)
	cut, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	provider := eventprivacy.SourcePostgresProtection{Policy: reader.Policy, Custody: custody, Cut: cut}
	binding := postgresArtifactBinding(ref.TenantID, cut)
	row := json.RawMessage(`{"subject":"missing-custody@example.invalid"}`)
	envelope, protected, err := provider.ProtectPostgresRow(t.Context(), binding, row)
	if err != nil || !protected {
		t.Fatal(err)
	}
	foreign := binding
	foreign.Scope = eventprotect.ScopeEvent
	if _, _, err := provider.OpenPostgresRow(t.Context(), foreign, envelope); err == nil {
		t.Fatal("source-event purpose accepted SQL ciphertext")
	}
	changed := provider
	changed.Cut++
	if _, _, err := changed.OpenPostgresRow(t.Context(), binding, envelope); err == nil {
		t.Fatal("another cut accepted SQL ciphertext")
	}
	path := directory + "/" + ref.TenantID + "/" + ref.ID + ".key"
	held := path + ".held-by-postgres-test"
	if err := os.Rename(path, held); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := os.Stat(held); err == nil {
			_ = os.Rename(held, path)
		}
	})
	if _, erased, err := provider.OpenPostgresRow(t.Context(), binding, envelope); !errors.Is(err, eventprotect.ErrKey) || erased {
		t.Fatal("missing material became readable or erased")
	}
	if _, protected, err := provider.ProtectPostgresRow(t.Context(), binding, row); !errors.Is(err, eventprotect.ErrKey) || protected {
		t.Fatal("missing material became a writable fallback")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("artifact access regenerated missing material")
	}
}
