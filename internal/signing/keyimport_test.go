// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"bytes"
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// operatorKey is an operator's existing CA private key as PKCS#8, with its
// PKIX public key: what the CA certificate being imported carries.
func operatorKey(t *testing.T) (pkcs8, spki []byte) {
	t.Helper()
	pkcs8, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := crypto.LockedKeyFromPKCS8(pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Destroy()
	return pkcs8, append([]byte(nil), locked.Public().DER...)
}

func prepareImport(t *testing.T, s *signing.Server, operation string) []byte {
	t.Helper()
	resp, err := s.PrepareKeyImport(context.Background(), &signerpb.PrepareKeyImportRequest{OperationId: operation})
	if err != nil {
		t.Fatalf("PrepareKeyImport: %v", err)
	}
	if resp.GetSuite() != crypto.KeyImportSuite || len(resp.GetPublicKey()) == 0 {
		t.Fatalf("import offer = %+v", resp)
	}
	return resp.GetPublicKey()
}

func sealOperatorKey(t *testing.T, public []byte, tenant, operation string, pkcs8, spki []byte) []byte {
	t.Helper()
	sealed, err := crypto.SealKeyImport(public, crypto.KeyImportInfo(tenant, operation, spki), pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func importRequest(operation, tenant string, sealed, spki []byte, handle string) *signerpb.ImportWrappedKeyRequest {
	return &signerpb.ImportWrappedKeyRequest{
		OperationId: operation, TenantId: tenant, SealedKey: sealed, ExpectedPublicKey: spki,
		RequestedId: handle, AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN},
	}
}

// A128: an operator's CA private key, sealed to the signer's one-time import
// key on the operator's machine, opens only inside the signer under the exact
// binding, must match the expected public key, and is then held under the
// requested handle with its constraints. A repeated import returns the same
// key; the import key is used up by the import.
func TestImportWrappedKeyKeepsTheOperatorsKeyUnderItsHandle(t *testing.T) {
	ctx := context.Background()
	s := signing.NewServer()
	public := prepareImport(t, s, "ceremony-1")
	if again := prepareImport(t, s, "ceremony-1"); !bytes.Equal(again, public) {
		t.Fatal("a repeated prepare for the same operation offered a different import key")
	}
	pkcs8, spki := operatorKey(t)
	defer secret.Wipe(pkcs8)
	sealed := sealOperatorKey(t, public, "tenant-a", "ceremony-1", pkcs8, spki)

	_, otherSPKI := operatorKey(t)
	for name, req := range map[string]*signerpb.ImportWrappedKeyRequest{
		"a different expected key": importRequest("ceremony-1", "tenant-a", sealed, otherSPKI, "imported-ca"),
		"another tenant's binding": importRequest("ceremony-1", "tenant-b", sealed, spki, "imported-ca"),
		"a damaged sealed key":     importRequest("ceremony-1", "tenant-a", sealed[:len(sealed)-1], spki, "imported-ca"),
	} {
		if _, err := s.ImportWrappedKey(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%s: import = %v, want InvalidArgument", name, err)
		}
	}
	if _, err := s.ImportWrappedKey(ctx, importRequest("no-such-operation", "tenant-a", sealed, spki, "imported-ca")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("import without a prepared key = %v, want FailedPrecondition", err)
	}

	resp, err := s.ImportWrappedKey(ctx, importRequest("ceremony-1", "tenant-a", sealed, spki, "imported-ca"))
	if err != nil {
		t.Fatalf("ImportWrappedKey: %v", err)
	}
	if resp.GetHandle().GetId() != "imported-ca" || !bytes.Equal(resp.GetPublicKey(), spki) {
		t.Fatalf("import result = %+v", resp)
	}
	if _, err := s.Sign(ctx, &signerpb.SignRequest{
		Handle: resp.GetHandle(), Digest: make([]byte, 32), Hash: signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN,
	}); err != nil {
		t.Fatalf("the imported key does not sign for its purpose: %v", err)
	}
	if _, err := s.Sign(ctx, &signerpb.SignRequest{
		Handle: resp.GetHandle(), Digest: make([]byte, 32), Hash: signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_LEAF_TLS,
	}); err == nil {
		t.Fatal("the imported key signed outside its constrained purpose")
	}
	again, err := s.ImportWrappedKey(ctx, importRequest("ceremony-1", "tenant-a", sealed, spki, "imported-ca"))
	if err != nil || !bytes.Equal(again.GetPublicKey(), spki) {
		t.Fatalf("a repeated import = %+v, %v; want the same key", again, err)
	}
	secondPKCS8, secondSPKI := operatorKey(t)
	secondSealed := sealOperatorKey(t, public, "tenant-a", "ceremony-1", secondPKCS8, secondSPKI)
	if _, err := s.ImportWrappedKey(ctx, importRequest("ceremony-1", "tenant-a", secondSealed, secondSPKI, "imported-ca-2")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a second key under a used import key = %v, want FailedPrecondition", err)
	}
}

// The import key is shared keystore state: a signer process other than the
// one that prepared it can complete the import, the imported key survives a
// restart, and the used import key is gone from the keystore.
func TestKeyImportWorksAcrossSignersSharingTheKeystore(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK(t)
	ctx := context.Background()
	a, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek))
	if err != nil {
		t.Fatal(err)
	}
	b, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek))
	if err != nil {
		t.Fatal(err)
	}
	public := prepareImport(t, a, "ceremony-shared")
	pkcs8, spki := operatorKey(t)
	sealed := sealOperatorKey(t, public, "tenant-a", "ceremony-shared", pkcs8, spki)
	if _, err := b.ImportWrappedKey(ctx, importRequest("ceremony-shared", "tenant-a", sealed, spki, "imported-shared")); err != nil {
		t.Fatalf("import on the second signer: %v", err)
	}
	c, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek))
	if err != nil {
		t.Fatalf("restart over an imported key: %v", err)
	}
	got, err := c.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: "imported-shared"}})
	if err != nil || !bytes.Equal(got.GetPublicKey(), spki) {
		t.Fatalf("restarted signer holds %+v, %v; want the imported key", got, err)
	}
	if fresh := prepareImport(t, c, "ceremony-shared"); bytes.Equal(fresh, public) {
		t.Fatal("the used import key is still in the keystore")
	}
}

// A dual-control import needs a signer that can enforce it.
func TestImportWrappedKeyRefusesDualControlWithoutAnAuthorizer(t *testing.T) {
	s := signing.NewServer()
	public := prepareImport(t, s, "ceremony-dual")
	pkcs8, spki := operatorKey(t)
	req := importRequest("ceremony-dual", "tenant-a", sealOperatorKey(t, public, "tenant-a", "ceremony-dual", pkcs8, spki), spki, "imported-dual")
	req.RequireAuthorization = true
	if _, err := s.ImportWrappedKey(context.Background(), req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("dual-control import without an authorizer = %v, want FailedPrecondition", err)
	}
}
