// SPDX-License-Identifier: MPL-2.0

package tenantseal_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/tenantseal"
)

type fixedCipherAccess struct {
	tenant string
	cipher tenantseal.Cipher
	err    error
	calls  int
}

func (a *fixedCipherAccess) WithTenant(
	_ context.Context,
	tenantID string,
	fn func(tenantseal.Cipher) error,
) error {
	a.calls++
	if a.err != nil {
		return a.err
	}
	if tenantID != a.tenant {
		return errors.New("wrong tenant")
	}
	return fn(a.cipher)
}

type localResultCipher struct{ key *seal.LocalKEK }

func (c localResultCipher) Seal(plaintext, aad []byte) ([]byte, error) {
	return seal.Seal(c.key, plaintext, aad)
}

func (c localResultCipher) Open(container, aad []byte) ([]byte, error) {
	return seal.Open(c.key, container, aad)
}

func TestResultProtectorBindsTenantKeyAndRequestBinding(t *testing.T) {
	t.Parallel()
	keyMaterial := bytes.Repeat([]byte{0x91}, 32)
	key, err := seal.NewLocalKEK(keyMaterial)
	if err != nil {
		t.Fatalf("NewLocalKEK: %v", err)
	}
	defer key.Destroy()
	access := &fixedCipherAccess{
		tenant: testTenantA,
		cipher: localResultCipher{key: key},
	}
	protector, err := tenantseal.NewResultProtector(access)
	if err != nil {
		t.Fatalf("NewResultProtector: %v", err)
	}
	var _ orchestrator.ResultProtector = protector

	plaintext := []byte("private-key-canary")
	codec, protected, err := protector.Protect(
		context.Background(), testTenantA, "issue-key", "request-binding", plaintext,
	)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	if codec != orchestrator.ResultCodecSealedRowV1 {
		t.Fatalf("codec = %q, want %q", codec, orchestrator.ResultCodecSealedRowV1)
	}
	if bytes.Contains(protected, plaintext) {
		t.Fatal("protected result retains plaintext canary")
	}
	opened, err := protector.Open(
		context.Background(), testTenantA, "issue-key", "request-binding", codec, protected,
	)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened = %q, want %q", opened, plaintext)
	}

	for _, swapped := range []struct {
		name              string
		tenant, key, bind string
	}{
		{name: "tenant", tenant: testTenantB, key: "issue-key", bind: "request-binding"},
		{name: "key", tenant: testTenantA, key: "other-key", bind: "request-binding"},
		{name: "binding", tenant: testTenantA, key: "issue-key", bind: "other-binding"},
	} {
		t.Run(swapped.name, func(t *testing.T) {
			if _, err := protector.Open(
				context.Background(), swapped.tenant, swapped.key, swapped.bind, codec, protected,
			); err == nil {
				t.Fatal("Open accepted a result copied to different authenticated row context")
			}
		})
	}
}

func TestResultProtectorRejectsLegacyCodecsAfterReadiness(t *testing.T) {
	t.Parallel()
	access := &fixedCipherAccess{tenant: testTenantA, cipher: localResultCipher{}}
	protector, err := tenantseal.NewResultProtector(access)
	if err != nil {
		t.Fatalf("NewResultProtector: %v", err)
	}

	for _, codec := range []string{
		orchestrator.ResultCodecRawV0,
		orchestrator.ResultCodecSealedDynamicLeaseV1,
	} {
		if _, err := protector.Open(
			context.Background(), testTenantA, "legacy-key", "", codec, []byte("legacy"),
		); err == nil {
			t.Fatalf("Open accepted retired codec %q", codec)
		}
	}
	if access.calls != 0 {
		t.Fatalf("retired codec reached tenant crypto access %d times, want 0", access.calls)
	}
}

func TestResultProtectorRejectsUnknownCodecAndMissingIdentity(t *testing.T) {
	t.Parallel()
	access := &fixedCipherAccess{tenant: testTenantA, cipher: localResultCipher{}}
	protector, err := tenantseal.NewResultProtector(access)
	if err != nil {
		t.Fatalf("NewResultProtector: %v", err)
	}
	if _, err := protector.Open(
		context.Background(), testTenantA, "key", "", "unknown", []byte("value"),
	); err == nil {
		t.Fatal("Open accepted unknown codec")
	}
	if _, _, err := protector.Protect(context.Background(), "", "key", "", nil); err == nil {
		t.Fatal("Protect accepted empty tenant")
	}
	if _, err := tenantseal.NewResultProtector(nil); err == nil {
		t.Fatal("NewResultProtector accepted nil access")
	}
}
