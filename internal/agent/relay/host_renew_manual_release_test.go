// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
)

// DOC-O2: a renewal whose certificate was signed and whose successor was then
// rolled back, before the agent freed such a slot itself, keeps its target's
// pending record; every later renewal for the target is refused as another
// job's, and the control plane's "ended through" release leaves a signed
// record alone. The runbook (docs/runbooks/stuck-host-renewal.md) removes the
// one record named by SHA-256 of tenant, connector and target, joined by NUL
// bytes, plus ".renew", in the host rollback directory; this proves that name
// is the record's and that removing it frees the slot.
func TestTheRunbooksManualReleaseFreesASignedPendingHostKeyDOCO2(t *testing.T) {
	root := t.TempDir()
	const (
		tenant    = "11111111-1111-1111-1111-111111111111"
		connector = "nginx"
		target    = "3f2a8d1c-5b7e-4c9a-8e21-6d4b0a9f7c13"
	)
	store, err := relay.NewHostRollbackStore(root, tenant)
	if err != nil {
		t.Fatal(err)
	}
	oldBinding, newBinding := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := store.RecordHostRenewKey(connector, target, 5, oldBinding, []byte("CSR"), []byte("OLD-KEY")); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordHostRenewCertificate(connector, target, 5, oldBinding, []byte("CERT"), []byte("CHAIN"), "sha256:old"); err != nil {
		t.Fatal(err)
	}
	// Another target's record, which the runbook's removal must not touch.
	if err := store.RecordHostRenewKey(connector, "another-target", 7, oldBinding, []byte("CSR"), []byte("OTHER-KEY")); err != nil {
		t.Fatal(err)
	}

	if _, err := store.LoadHostRenewPending(connector, target, 9, newBinding); err == nil {
		t.Fatal("a later renewal adopted the rolled-back job's signed record")
	}
	if released, err := store.ReleaseEndedHostRenewPending(connector, target, 8, 9); err != nil || released {
		t.Fatalf("the ended-through release = (%v, %v), want a signed record left alone", released, err)
	}

	name := crypto.SHA256Hex([]byte(tenant + "\x00" + connector + "\x00" + target))
	// The runbook's example uses these three values; its printf recipe
	// (printf '%s\0%s\0%s' ... | sha256sum) prints this name for them.
	if name != "e752fc2a40315aae0443dc4fc2e554ebda8546d9d8c3b8452879fd4bc2b8e701" {
		t.Fatalf("the record name for the runbook's example is %s, not what its recipe prints", name)
	}
	record := filepath.Join(root, name+".renew")
	if _, err := os.Stat(record); err != nil {
		t.Fatalf("the runbook's record name does not name the stuck record: %v", err)
	}
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	if pending, err := store.LoadHostRenewPending(connector, target, 9, newBinding); err != nil || pending != nil {
		t.Fatalf("after the runbook's removal the slot = (%v, %v), want free", pending != nil, err)
	}
	if err := store.RecordHostRenewKey(connector, target, 9, newBinding, []byte("CSR"), []byte("NEW-KEY")); err != nil {
		t.Fatalf("the next renewal could not take the freed slot: %v", err)
	}
	if _, err := store.LoadHostRenewPending(connector, "another-target", 7, oldBinding); err != nil {
		t.Fatalf("another target's record was disturbed: %v", err)
	}
}
