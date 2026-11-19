// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

const (
	importTenant    = "11111111-1111-4111-8111-111111111111"
	importOperation = "00000000-0000-4000-8000-000000082103"
	importSecond    = "00000000-0000-4000-8000-000000082104"
)

// CR-821: a legacy caller must be stopped before it receives an unsigned offer.
func TestSignerRefusesLegacyImportPreparation(t *testing.T) {
	signer := signing.NewServer()
	t.Cleanup(signer.Shutdown)
	response, err := signer.PrepareKeyImport(t.Context(), &signerpb.PrepareKeyImportRequest{
		OperationId: importOperation,
	})
	if response != nil || status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("legacy prepare must require the authenticated import protocol, returned offer=%t status=%s", response != nil, status.Code(err))
	}
	imported, err := signer.ImportWrappedKey(t.Context(), &signerpb.ImportWrappedKeyRequest{})
	if imported != nil || status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("legacy import returned result=%t status=%s, want FailedPrecondition", imported != nil, status.Code(err))
	}
}

// operatorKey is an operator's existing CA private key as PKCS#8, with its
// PKIX public key: what the CA certificate being imported carries.
func operatorKey(t *testing.T) (pkcs8, spki []byte) {
	t.Helper()
	pkcs8, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { secret.Wipe(pkcs8) })
	locked, err := crypto.LockedKeyFromPKCS8(pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Destroy()
	return pkcs8, append([]byte(nil), locked.Public().DER...)
}

func newImportSigner(t *testing.T, store *signing.KeyStore, authorizer *crypto.SignAuthorizer) *signing.Server {
	t.Helper()
	signer, err := signing.NewPersistentServer(store, signing.WithAuthorizer(authorizer))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Shutdown)
	return signer
}

func prepareImport(t *testing.T, s *signing.Server, policy *signerpb.KeyImportPolicyV2) *signerpb.PrepareKeyImportV2Response {
	t.Helper()
	resp, err := s.PrepareKeyImportV2(t.Context(), &signerpb.PrepareKeyImportV2Request{Version: crypto.KeyImportOfferVersion, Policy: policy})
	if err != nil {
		t.Fatalf("PrepareKeyImportV2: %v", err)
	}
	if resp.GetSuite() != crypto.AuthenticatedKeyImportSuite || len(resp.GetPublicKey()) == 0 || !proto.Equal(policy, resp.GetPolicy()) {
		t.Fatal("the import offer did not preserve the request policy")
	}
	return resp
}

func sealOperatorKey(t *testing.T, offer *signerpb.PrepareKeyImportV2Response, pin string, pkcs8 []byte) []byte {
	t.Helper()
	policy := offer.GetPolicy()
	signed := crypto.AuthenticatedKeyImportOffer{
		KeyImportPolicy: crypto.CAKeyImportPolicy(policy.GetTenantId(), policy.GetOperationId(), policy.GetExpectedPublicKey()),
		Version:         offer.GetVersion(), Suite: offer.GetSuite(), PublicKey: offer.GetPublicKey(),
		IssuedAt: offer.GetIssuedAtUnix(), ExpiresAt: offer.GetExpiresAtUnix(),
		SignerPublicKey: offer.GetSignerPublicKey(), Signature: offer.GetSignature(),
	}
	info, err := signed.Verify(pin, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := crypto.SealKeyImport(signed.PublicKey, info, pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func importRequest(operation, tenant string, sealed, spki []byte) *signerpb.ImportWrappedKeyV2Request {
	return &signerpb.ImportWrappedKeyV2Request{
		Version: crypto.KeyImportOfferVersion, SealedKey: sealed,
		Policy: &signerpb.KeyImportPolicyV2{
			OperationId: operation, TenantId: tenant, ExpectedPublicKey: spki,
			RequestedId:          crypto.CAHierarchySignerHandle(operation),
			AllowedPurposes:      []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN},
			RequireAuthorization: true,
		},
	}
}

// A128: an operator's CA private key, sealed to the signer's one-time import
// key on the operator's machine, opens only inside the signer under the exact
// binding, must match the expected public key, and is then held under the
// requested handle with its constraints. A repeated import returns the same
// key; the import key is used up by the import.
func TestImportWrappedKeyKeepsTheOperatorsKeyUnderItsHandle(t *testing.T) {
	ctx := context.Background()
	store := signing.NewKeyStore(t.TempDir(), testKEK(t))
	pin, err := store.InitializeKeyImportIdentity()
	if err != nil {
		t.Fatal(err)
	}
	authz := dualControlAuthorizer(t)
	s := newImportSigner(t, store, authz)
	pkcs8, spki := operatorKey(t)
	policy := importRequest(importOperation, importTenant, nil, spki).GetPolicy()
	offer := prepareImport(t, s, policy)
	if again := prepareImport(t, s, policy); !proto.Equal(again, offer) {
		t.Fatal("a repeated prepare for the same operation returned a different signed offer")
	}
	sealed := sealOperatorKey(t, offer, pin, pkcs8)
	request := importRequest(importOperation, importTenant, sealed, spki)

	_, otherSPKI := operatorKey(t)
	for name, change := range map[string]func(*signerpb.ImportWrappedKeyV2Request){
		"expected key": func(r *signerpb.ImportWrappedKeyV2Request) { r.Policy.ExpectedPublicKey = otherSPKI },
		"tenant": func(r *signerpb.ImportWrappedKeyV2Request) {
			r.Policy.TenantId = "22222222-2222-4222-8222-222222222222"
		},
		"damaged key": func(r *signerpb.ImportWrappedKeyV2Request) { r.SealedKey = r.SealedKey[:len(r.SealedKey)-1] },
		"handle":      func(r *signerpb.ImportWrappedKeyV2Request) { r.Policy.RequestedId += "-other" },
		"purpose": func(r *signerpb.ImportWrappedKeyV2Request) {
			r.Policy.AllowedPurposes[0] = signerpb.KeyPurpose_KEY_PURPOSE_LEAF_TLS
		},
		"hash": func(r *signerpb.ImportWrappedKeyV2Request) {
			r.Policy.AllowedHashes = []signerpb.Hash{signerpb.Hash_HASH_SHA256}
		},
		"authorization": func(r *signerpb.ImportWrappedKeyV2Request) { r.Policy.RequireAuthorization = false },
	} {
		t.Run(name, func(t *testing.T) {
			req := proto.Clone(request).(*signerpb.ImportWrappedKeyV2Request)
			change(req)
			if _, err := s.ImportWrappedKeyV2(ctx, req); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("changed import = %v, want InvalidArgument", err)
			}
		})
	}
	if _, err := s.ImportWrappedKeyV2(ctx, importRequest(importSecond, importTenant, sealed, spki)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("import without a prepared key = %v, want FailedPrecondition", err)
	}

	resp, err := s.ImportWrappedKeyV2(ctx, request)
	if err != nil {
		t.Fatalf("ImportWrappedKey: %v", err)
	}
	if resp.GetHandle().GetId() != policy.RequestedId || !bytes.Equal(resp.GetPublicKey(), spki) {
		t.Fatalf("import result = %+v", resp)
	}
	assertImportedKeyConstraints(t, s, authz, resp.GetHandle())
	again, err := s.ImportWrappedKeyV2(ctx, request)
	if err != nil || !proto.Equal(again, resp) {
		t.Fatalf("a repeated import = %+v, %v; want the same key", again, err)
	}
	secondPKCS8, _ := operatorKey(t)
	secondSealed := sealOperatorKey(t, offer, pin, secondPKCS8)
	if _, err := s.ImportWrappedKeyV2(ctx, importRequest(importSecond, importTenant, secondSealed, otherSPKI)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a second key under a used import key = %v, want FailedPrecondition", err)
	}
	resealed := sealOperatorKey(t, offer, pin, pkcs8)
	if _, err := s.ImportWrappedKeyV2(ctx, importRequest(importOperation, importTenant, resealed, spki)); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("different ciphertext for the same public key = %v, want AlreadyExists", status.Code(err))
	}
}

func assertImportedKeyConstraints(t *testing.T, s *signing.Server, authz *crypto.SignAuthorizer, handle *signerpb.KeyHandle) {
	t.Helper()
	digest := crypto.SHA256Sum([]byte("test CA signing purpose"))
	req := &signerpb.SignRequest{Handle: handle, Digest: digest, Hash: signerpb.Hash_HASH_SHA256, Purpose: signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN}
	if _, err := s.Sign(t.Context(), req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unattested sign status = %v, want PermissionDenied", status.Code(err))
	}
	token, err := authz.Authorize(crypto.SignIntent{
		KeyHandle: handle.GetId(), Purpose: int32(req.Purpose), Hash: crypto.SHA256, Padding: crypto.RSAPKCS1v15, Digest: digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(token)
	req.AuthorizationToken = token
	if _, err := s.Sign(t.Context(), req); err != nil {
		t.Fatalf("the imported key cannot sign for its approved purpose: %v", err)
	}
	req.Purpose = signerpb.KeyPurpose_KEY_PURPOSE_LEAF_TLS
	if _, err := s.Sign(t.Context(), req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("sign outside the approved purpose = %v, want FailedPrecondition", status.Code(err))
	}
}

// The import key is shared keystore state: a signer process other than the
// one that prepared it can complete the import, the imported key survives a
// restart, and the used import key is gone from the keystore.
func TestKeyImportWorksAcrossSignersSharingTheKeystore(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK(t)
	ctx := context.Background()
	store := signing.NewKeyStore(dir, kek)
	pin, err := store.InitializeKeyImportIdentity()
	if err != nil {
		t.Fatal(err)
	}
	authz := dualControlAuthorizer(t)
	a := newImportSigner(t, store, authz)
	b := newImportSigner(t, signing.NewKeyStore(dir, kek), authz)
	pkcs8, spki := operatorKey(t)
	policy := importRequest(importOperation, importTenant, nil, spki).GetPolicy()
	offer := prepareImport(t, a, policy)
	sealed := sealOperatorKey(t, offer, pin, pkcs8)
	request := importRequest(importOperation, importTenant, sealed, spki)
	before, err := b.ImportWrappedKeyV2(ctx, request)
	if err != nil {
		t.Fatalf("import on the second signer: %v", err)
	}
	c := newImportSigner(t, signing.NewKeyStore(dir, kek), authz)
	got, err := c.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: before.GetHandle()})
	if err != nil || !bytes.Equal(got.GetPublicKey(), spki) || !got.GetRequiresAuthorization() {
		t.Fatal("restarted signer did not restore the imported key and constraints", err)
	}
	assertImportedKeyConstraints(t, c, authz, before.GetHandle())
	if result, err := c.ImportWrappedKeyV2(ctx, request); err != nil || !proto.Equal(result, before) {
		t.Fatal("the import receipt did not survive restart", err)
	}
	if _, err := c.PrepareKeyImportV2(ctx, &signerpb.PrepareKeyImportV2Request{Version: crypto.KeyImportOfferVersion, Policy: policy}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("a repeat prepare after import = %v, want AlreadyExists", status.Code(err))
	}
	for _, suffix := range []string{".import-v2", ".import-v2.stage"} {
		if _, err := os.Stat(filepath.Join(dir, policy.RequestedId+suffix)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("the used import preparation was not retired", err)
		}
	}
}

// A dual-control import needs a signer that can enforce it.
func TestImportWrappedKeyRefusesDualControlWithoutAnAuthorizer(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK(t)
	store := signing.NewKeyStore(dir, kek)
	pin, err := store.InitializeKeyImportIdentity()
	if err != nil {
		t.Fatal(err)
	}
	good := newImportSigner(t, store, dualControlAuthorizer(t))
	s := newImportSigner(t, signing.NewKeyStore(dir, kek), nil)
	pkcs8, spki := operatorKey(t)
	req := importRequest(importOperation, importTenant, nil, spki)
	if _, err := s.PrepareKeyImportV2(t.Context(), &signerpb.PrepareKeyImportV2Request{Version: crypto.KeyImportOfferVersion, Policy: req.GetPolicy()}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("dual-control preparation without an authorizer = %v, want FailedPrecondition", err)
	}
	offer := prepareImport(t, good, req.GetPolicy())
	req.SealedKey = sealOperatorKey(t, offer, pin, pkcs8)
	if _, err := s.ImportWrappedKeyV2(t.Context(), req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("dual-control import without an authorizer = %v, want FailedPrecondition", err)
	}
}
