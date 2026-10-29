// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"errors"
	"os"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestFileAuthorityRefusesReplacementMaterialBeforeUse(t *testing.T) {
	authority, _, ref := keyAuthorityFixture(t)
	if err := authority.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	fresh, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(fresh)
	file, err := authority.root.OpenFile(keyName(ref), os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	written, writeErr := file.Write(fresh)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || written != len(fresh) {
		t.Fatalf("replace fixture key: %v %v", writeErr, closeErr)
	}
	called := false
	if err := authority.WithKey(t.Context(), ref, func(seal.KeyWrapper) error { called = true; return nil }); !errors.Is(err, ErrKey) || called {
		t.Fatalf("a different32-byte key inherited an active custody identity: %v", err)
	}
	if err := authority.Provision(t.Context(), ref); !errors.Is(err, ErrKey) {
		t.Fatalf("provisioning certified replacement material: %v", err)
	}
}

func TestFileAuthorityRefusesChangedIdentityProbe(t *testing.T) {
	authority, _, ref := keyAuthorityFixture(t)
	if err := authority.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	record, found, err := authority.readRecord(ref)
	if err != nil || !found || len(record.Probe) == 0 {
		t.Fatalf("active custody lacks a probe: %v", err)
	}
	record.Probe[0] ^= 0xff
	if err := authority.writeRecord(record); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := authority.WithKey(t.Context(), ref, func(seal.KeyWrapper) error { called = true; return nil }); !errors.Is(err, ErrKey) || called {
		t.Fatalf("changed custody probe reached key use: %v", err)
	}
}

func TestFileAuthorityVerifiesSourceBoundCreationEvidence(t *testing.T) {
	authority, _, ref := keyAuthorityFixture(t)
	if err := authority.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	evidence, err := authority.CreationEvidence(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Ref != ref || evidence.CreatedAt.IsZero() || len(evidence.Probe) == 0 || len(evidence.Digest()) != 64 {
		t.Fatal("creation evidence is incomplete")
	}
	if err := authority.WithVerifiedKey(t.Context(), evidence, func(seal.KeyWrapper) error { return nil }); err != nil {
		t.Fatal(err)
	}
	evidence.Probe[0] ^= 0xff
	called := false
	if err := authority.WithVerifiedKey(t.Context(), evidence, func(seal.KeyWrapper) error { called = true; return nil }); !errors.Is(err, ErrKey) || called {
		t.Fatalf("local key ignored the immutable activation's creation evidence: %v", err)
	}
}
