// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

type importRecoveryFixture struct {
	store      *KeyStore
	signer     *Server
	authorizer *crypto.SignAuthorizer
	policy     crypto.KeyImportPolicy
	pin        string
	pkcs8      []byte
	now        time.Time
}

const recoveryImportCeremony = "00000000-0000-4000-8000-000000082113"

func newImportRecoveryFixture(t *testing.T) *importRecoveryFixture {
	t.Helper()
	return newImportRecoveryFixtureAt(t, t.TempDir())
}

func newImportRecoveryFixtureAt(t *testing.T, dir string) *importRecoveryFixture {
	t.Helper()
	wrapper, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x53}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrapper.Destroy)
	store := NewKeyStore(dir, wrapper)
	pin, err := store.InitializeKeyImportIdentity()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := crypto.NewSignAuthorizer(bytes.Repeat([]byte{0x35}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(auth.Destroy)
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	pkcs8, err := privateKeyBytesForSealing(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { secret.Wipe(pkcs8) })
	fixture := &importRecoveryFixture{store: store, authorizer: auth, pin: pin, pkcs8: pkcs8, now: time.Now()}
	fixture.signer = fixture.open(t, store)
	fixture.policy = crypto.CAKeyImportPolicy(
		"11111111-1111-4111-8111-111111111111", recoveryImportCeremony, key.Public().DER,
	)
	return fixture
}

func (f *importRecoveryFixture) open(t *testing.T, store *KeyStore) *Server {
	t.Helper()
	server, err := NewPersistentServer(store, WithAuthorizer(f.authorizer))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Shutdown)
	server.keyImportClock = func() time.Time { return f.now }
	return server
}

func (f *importRecoveryFixture) prepare(t *testing.T) (*signerpb.PrepareKeyImportV2Response, *signerpb.ImportWrappedKeyV2Request) {
	t.Helper()
	policy := keyImportPolicyProto(f.policy)
	response, err := f.signer.PrepareKeyImportV2(t.Context(), &signerpb.PrepareKeyImportV2Request{Version: crypto.KeyImportOfferVersion, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	offer := crypto.AuthenticatedKeyImportOffer{
		KeyImportPolicy: f.policy, Version: response.GetVersion(), Suite: response.GetSuite(),
		PublicKey: response.GetPublicKey(), IssuedAt: response.GetIssuedAtUnix(), ExpiresAt: response.GetExpiresAtUnix(),
		SignerPublicKey: response.GetSignerPublicKey(), Signature: response.GetSignature(),
	}
	info, err := offer.Verify(f.pin, f.now)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := crypto.SealKeyImport(offer.PublicKey, info, f.pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	return response, &signerpb.ImportWrappedKeyV2Request{Version: crypto.KeyImportOfferVersion, Policy: policy, SealedKey: ciphertext}
}

func assertImportName(t *testing.T, store *KeyStore, name string, want bool) {
	t.Helper()
	exists, err := store.hierarchyEntryExists(name)
	if err != nil || exists != want {
		t.Fatalf("entry %s exists = %t, want %t: %v", name, exists, want, err)
	}
}

func TestImportFileSyncFailureDoesNotPublishAKey(t *testing.T) {
	f := newImportRecoveryFixture(t)
	_, request := f.prepare(t)
	name := f.policy.Handle + keyFileExt
	f.store.beforeHierarchyFileSync = func(candidate string) error {
		if candidate == name+custodyStageExt {
			return errors.New("fixture file sync failure")
		}
		return nil
	}
	if response, err := f.signer.ImportWrappedKeyV2(t.Context(), request); response != nil || status.Code(err) != codes.Internal {
		t.Fatalf("import acknowledged before file sync: %v", err)
	}
	assertImportName(t, f.store, name, false)
	assertImportName(t, f.store, name+custodyStageExt, true)
	assertImportName(t, f.store, keyImportPreparationName(f.policy.Handle), true)
	f.store.beforeHierarchyFileSync = nil
	if response, err := f.signer.ImportWrappedKeyV2(t.Context(), request); err != nil || !bytes.Equal(response.GetPublicKey(), f.policy.ExpectedPublicKey) {
		t.Fatal("retry did not finish file publication", err)
	}
	assertImportName(t, f.store, name+custodyStageExt, false)
}

func TestDestructionFencesAStagedImportBeforeAnyKeyIsPublished(t *testing.T) {
	f := newImportRecoveryFixture(t)
	_, request := f.prepare(t)
	handle := &signerpb.KeyHandle{Id: f.policy.Handle}
	f.store.beforeHierarchyFileSync = func(stage string) error {
		if stage == handle.Id+keyFileExt+custodyStageExt {
			return errors.New("fixture file sync failure")
		}
		return nil
	}
	if _, err := f.signer.ImportWrappedKeyV2(t.Context(), request); status.Code(err) != codes.Internal {
		t.Fatalf("expected an interrupted import, got %v", err)
	}
	f.store.beforeHierarchyFileSync = nil
	if _, err := f.signer.DestroyKey(t.Context(), &signerpb.DestroyKeyRequest{Handle: handle}); err != nil {
		t.Fatal(err)
	}
	assertImportName(t, f.store, handle.Id+destroyedKeyFileExt, true)
	assertImportName(t, f.store, handle.Id+keyFileExt+custodyStageExt, false)
	preparation := keyImportPreparationName(handle.Id)
	assertImportName(t, f.store, preparation, false)
	assertImportName(t, f.store, preparation+custodyStageExt, false)
	if response, err := f.signer.ImportWrappedKeyV2(t.Context(), request); response != nil || status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("import continued after acknowledged destruction: %v", err)
	}
}

type custodyReadTrap struct {
	seal.KeyWrapper
	opens int
}

func (c *custodyReadTrap) UnwrapDEK([]byte) ([]byte, error) {
	c.opens++
	return nil, errors.New("fixture refuses access to sealed private material")
}

func TestFirstRevocationFencesAnInterruptedImportWithoutUnsealingIt(t *testing.T) {
	f := newImportRecoveryFixture(t)
	_, request := f.prepare(t)
	handle := &signerpb.KeyHandle{Id: f.policy.Handle}
	f.store.beforeHierarchySync = func() error { return errors.New("fixture directory sync failure") }
	if _, err := f.signer.ImportWrappedKeyV2(t.Context(), request); status.Code(err) != codes.Internal {
		t.Fatalf("expected interrupted directory publication, got %v", err)
	}
	f.store.beforeHierarchySync = nil
	assertImportName(t, f.store, handle.Id+keyFileExt, true)
	trap := &custodyReadTrap{KeyWrapper: f.store.wrapper}
	f.store.wrapper = trap
	revoke := &signerpb.RevokeKeyRequest{Handle: handle, OperationId: "first", Reason: "key_compromise"}
	response, err := f.signer.RevokeKey(t.Context(), revoke)
	if err != nil || trap.opens != 0 || !bytes.Equal(response.GetPublicKey(), f.policy.ExpectedPublicKey) {
		t.Fatalf("revocation failed to fence and read public state without opening a private key: calls=%d, err=%v", trap.opens, err)
	}
	assertImportName(t, f.store, handle.Id+revokedKeyFileExt, true)
	assertImportName(t, f.store, keyImportPreparationName(handle.Id), false)
	assertImportName(t, f.store, handle.Id+keyFileExt, true)
	if _, err := f.signer.ImportWrappedKeyV2(t.Context(), request); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("exact receipt crossed a durable revocation fence: %v", err)
	}
}

func TestAnUnavailableImportPublicHeaderDoesNotBlockRevocation(t *testing.T) {
	f := newImportRecoveryFixture(t)
	_, req := f.prepare(t)
	handle := &signerpb.KeyHandle{Id: f.policy.Handle}
	root, err := os.OpenRoot(f.store.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	// A truncated authoritative file must still allow terminal fencing.
	if err := root.WriteFile(handle.Id+keyFileExt, []byte("incomplete test envelope"), 0o600); err != nil {
		t.Fatal(err)
	}
	trap := &custodyReadTrap{KeyWrapper: f.store.wrapper}
	f.store.wrapper = trap
	revoke := &signerpb.RevokeKeyRequest{Handle: handle, OperationId: "first", Reason: "key_compromise"}
	result, err := f.signer.RevokeKey(t.Context(), revoke)
	if err != nil || result.GetOperationId() != "first" || len(result.GetPublicKey()) != 0 || trap.opens != 0 {
		t.Fatalf("failed to fence unreadable key, private opens=%d: %v", trap.opens, err)
	}
	if retry, err := f.signer.RevokeKey(t.Context(), revoke); err != nil || !proto.Equal(retry, result) || trap.opens != 0 {
		t.Fatalf("could not recover first revoke without a private read: %v", err)
	}
	if _, err := f.signer.ImportWrappedKeyV2(t.Context(), req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("import crossed a fence with unavailable public evidence: %v", err)
	}
	assertImportName(t, f.store, keyImportPreparationName(handle.Id), false)
}

func TestLegacyHierarchyKeyEnvelopesKeepTheirOriginalSealingLabel(t *testing.T) {
	f := newImportRecoveryFixture(t)
	for _, tc := range []struct {
		name   string
		header []byte
		dual   bool
	}{
		{"bare", nil, false},
		{"v1", append(bytes.Clone(metaMagic), 1, 1, byte(PurposeCASign), 0), false},
		{"v2", append(bytes.Clone(metaMagic), 2, 1, byte(PurposeCASign), 0, flagRequireAuth), true},
		{"v3", append(bytes.Clone(metaMagic), 3, 1, byte(PurposeCASign), 0, flagRequireAuth, byte(signerpb.Algorithm_ALGORITHM_ECDSA_P256)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plaintext := append(bytes.Clone(tc.header), f.pkcs8...)
			defer secret.Wipe(plaintext)
			file, err := seal.Seal(f.store.wrapper, plaintext, []byte(f.policy.Handle))
			if err != nil {
				t.Fatal(err)
			}
			key, err := f.store.decodeHeldKey(f.policy.Handle, file)
			if err != nil {
				t.Fatal(err)
			}
			defer key.signer.Destroy()
			if !bytes.Equal(key.signer.Public().DER, f.policy.ExpectedPublicKey) ||
				key.constraints.requireAuth != tc.dual || key.constraints.importReceipt != [32]byte{} {
				t.Fatal("legacy key or constraints changed during open")
			}
		})
	}
}

func TestImportDirectorySyncGatesFirstUseOnEveryReplica(t *testing.T) {
	f := newImportRecoveryFixture(t)
	offer, request := f.prepare(t)
	followerStore := NewKeyStore(f.store.dir, f.store.wrapper)
	follower := f.open(t, followerStore)
	handle := &signerpb.KeyHandle{Id: f.policy.Handle}
	name := handle.Id + keyFileExt
	preparation := keyImportPreparationName(handle.Id)
	syncFailure := func() error { return errors.New("fixture directory sync failure") }
	f.store.beforeHierarchySync = syncFailure
	if response, err := f.signer.ImportWrappedKeyV2(t.Context(), request); response != nil || status.Code(err) != codes.Internal {
		t.Fatalf("import acknowledged before directory sync: %v", err)
	}
	assertImportName(t, f.store, name, true)
	assertImportName(t, f.store, preparation, true)
	followerStore.beforeHierarchySync = syncFailure
	if response, err := follower.GetPublicKey(t.Context(), &signerpb.GetPublicKeyRequest{Handle: handle}); response != nil || status.Code(err) != codes.Internal {
		t.Fatalf("cold lookup admitted a key before confirming durability: %v", err)
	}
	coldStore := NewKeyStore(f.store.dir, f.store.wrapper)
	coldStore.beforeHierarchySync = syncFailure
	if cold, err := NewPersistentServer(coldStore, WithAuthorizer(f.authorizer)); cold != nil || err == nil {
		t.Fatal("startup admitted a key before confirming durability")
	}
	f.now = time.Unix(offer.GetExpiresAtUnix(), 0)
	changed := proto.Clone(request).(*signerpb.ImportWrappedKeyV2Request)
	changed.SealedKey[len(changed.SealedKey)-1] ^= 1
	if _, err := follower.ImportWrappedKeyV2(t.Context(), changed); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("different ciphertext reached recovery: %v", err)
	}
	assertImportName(t, f.store, preparation, true)
	followerStore.beforeHierarchySync = nil
	resp, err := follower.ImportWrappedKeyV2(t.Context(), request)
	if err != nil || !bytes.Equal(resp.GetPublicKey(), f.policy.ExpectedPublicKey) {
		t.Fatal("an exact retry after offer expiry did not recover the published key", err)
	}
	assertImportName(t, f.store, preparation, false)
	pub, err := follower.GetPublicKey(t.Context(), &signerpb.GetPublicKeyRequest{Handle: handle})
	if err != nil || !pub.GetRequiresAuthorization() || !bytes.Equal(pub.GetPublicKey(), resp.GetPublicKey()) {
		t.Fatal("the durable published key was not admitted with its original constraints", err)
	}
}

func TestExpiredPreparationRequiresANewCeremony(t *testing.T) {
	f := newImportRecoveryFixture(t)
	offer, request := f.prepare(t)
	f.now = time.Unix(offer.GetExpiresAtUnix(), 0)
	if result, err := f.signer.ImportWrappedKeyV2(t.Context(), request); result != nil || status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expired preparation permitted a new import: %v", err)
	}
	if result, err := f.signer.PrepareKeyImportV2(t.Context(), &signerpb.PrepareKeyImportV2Request{Version: crypto.KeyImportOfferVersion, Policy: request.GetPolicy()}); result != nil || status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expired preparation issued another offer: %v", err)
	}
	assertImportName(t, f.store, f.policy.Handle+keyFileExt, false)
}

func TestPreparationRecoversTheSameSignedOfferAfterDirectoryFailure(t *testing.T) {
	f := newImportRecoveryFixture(t)
	name := keyImportPreparationName(f.policy.Handle)
	f.store.beforeHierarchySync = func() error {
		if exists, err := f.store.hierarchyEntryExists(name); err != nil {
			return err
		} else if exists {
			return errors.New("fixture preparation directory sync failure")
		}
		return nil
	}
	req := &signerpb.PrepareKeyImportV2Request{Version: crypto.KeyImportOfferVersion, Policy: keyImportPolicyProto(f.policy)}
	if offer, err := f.signer.PrepareKeyImportV2(t.Context(), req); offer != nil || status.Code(err) != codes.Internal {
		t.Fatalf("prepare reported success before directory sync: %v", err)
	}
	before, err := f.store.loadKeyImportPreparation(f.policy.Handle)
	if err != nil || before.recipient == nil {
		t.Fatal("could not observe the published preparation", err)
	}
	defer before.recipient.Destroy()
	f.store.beforeHierarchySync = nil
	next, err := f.signer.PrepareKeyImportV2(t.Context(), req)
	if err != nil || !proto.Equal(next, prepareKeyImportProto(before.offer)) {
		t.Fatal("exact prepare retry did not recover the original signature", err)
	}
}

func TestImportRecoveryRefusesAnExistingKeyWithoutItsReceipt(t *testing.T) {
	f := newImportRecoveryFixture(t)
	_, req := f.prepare(t)
	key, err := crypto.LockedKeyFromPKCS8(f.pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	if err := f.store.Save(f.policy.Handle, key, keyConstraints{
		purposes: map[signerpb.KeyPurpose]bool{signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN: true}, requireAuth: true,
	}); err != nil {
		t.Fatal(err)
	}
	if response, err := f.signer.ImportWrappedKeyV2(t.Context(), req); response != nil || status.Code(err) != codes.AlreadyExists {
		t.Fatalf("storage reported a different command as a completed import: %v", err)
	}
	assertImportName(t, f.store, keyImportPreparationName(f.policy.Handle), true)
}

func TestRewrapPreservesCAImportIdentityPreparationAndReceipt(t *testing.T) {
	f := newImportRecoveryFixture(t)
	_, firstReq := f.prepare(t)
	firstResult, err := f.signer.ImportWrappedKeyV2(t.Context(), firstReq)
	if err != nil {
		t.Fatal(err)
	}
	f.policy = crypto.CAKeyImportPolicy(f.policy.TenantID, "00000000-0000-4000-8000-000000082119", f.policy.ExpectedPublicKey)
	pendingOffer, pendingReq := f.prepare(t)
	f.signer.Shutdown()

	nextWrapper, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x65}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nextWrapper.Destroy)
	state, err := RewrapKeyStore(f.store.dir, f.store.wrapper, nextWrapper, f.now)
	if err != nil || state.Rewrapped < 3 || state.Keys != 1 {
		t.Fatal("rewrap did not validate installed key, offer identity and preparation", err)
	}
	newStore := NewKeyStore(f.store.dir, nextWrapper)
	if pin, err := newStore.KeyImportIdentityFingerprint(); err != nil || pin != f.pin {
		t.Fatal("rewrap changed the independently trusted fingerprint", err)
	}
	signer := f.open(t, newStore)
	if again, err := signer.ImportWrappedKeyV2(t.Context(), firstReq); err != nil || !proto.Equal(again, firstResult) {
		t.Fatal("rewrap did not preserve the installed key's exact receipt", err)
	}
	prepare := &signerpb.PrepareKeyImportV2Request{Version: pendingReq.GetVersion(), Policy: pendingReq.GetPolicy()}
	if offer, err := signer.PrepareKeyImportV2(t.Context(), prepare); err != nil || !proto.Equal(offer, pendingOffer) {
		t.Fatal("rewrap did not preserve the signed preparation", err)
	}
	if result, err := signer.ImportWrappedKeyV2(t.Context(), pendingReq); err != nil || !bytes.Equal(result.GetPublicKey(), f.policy.ExpectedPublicKey) {
		t.Fatal("rewrap did not preserve the one-time recipient", err)
	}
}

func TestRewrapRejectsMalformedFinalCAImportState(t *testing.T) {
	for _, state := range []string{"identity", "preparation"} {
		t.Run(state, func(t *testing.T) {
			f := newImportRecoveryFixture(t)
			_, _ = f.prepare(t)
			name, aad := keyImportIdentityName, keyImportIdentityAAD
			malformed := []byte("invalid identity fixture")
			if state == "preparation" {
				name, aad = keyImportPreparationName(f.policy.Handle), keyImportPreparationAAD(f.policy.Handle)
				plain, err := f.store.readCustodyFile(name, aad)
				if err != nil {
					t.Fatal(err)
				}
				plain[0] ^= 1
				malformed = plain
			}
			defer secret.Wipe(malformed)
			ciphertext, err := seal.Seal(f.store.wrapper, malformed, []byte(aad))
			if err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(f.store.dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			if err := root.WriteFile(name, ciphertext, 0o600); err != nil {
				t.Fatal(err)
			}
			f.signer.Shutdown()
			destination, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x64}, 32))
			if err != nil {
				t.Fatal(err)
			}
			defer destination.Destroy()
			if report, err := RewrapKeyStore(f.store.dir, f.store.wrapper, destination, f.now); err == nil || report.Backup != "" {
				t.Fatalf("rewrap swapped a store with malformed %s state: %v", state, err)
			}
			inPlace, err := os.OpenRoot(f.store.dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = inPlace.Close() }()
			if after, err := inPlace.ReadFile(name); err != nil || !bytes.Equal(after, ciphertext) {
				t.Fatal("rewrap changed the live store after validation refused it", err)
			}
		})
	}
}

func TestRewrapPreservesUnreadableImportStageForExactCleanup(t *testing.T) {
	f := newImportRecoveryFixture(t)
	offer, request := f.prepare(t)
	name := keyImportPreparationName(f.policy.Handle)
	root, err := os.OpenRoot(f.store.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	stage, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	dek, _, err := seal.ContainerWrappedDEK(stage)
	if err != nil {
		t.Fatal(err)
	}
	offset := bytes.Index(stage, dek)
	if offset < 0 {
		t.Fatal("the stage does not contain its wrapped DEK")
	}
	stage[offset] ^= 1
	if err := root.WriteFile(name+custodyStageExt, stage, 0o600); err != nil {
		t.Fatal(err)
	}
	f.signer.Shutdown()
	wrapper, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer wrapper.Destroy()
	if _, err := RewrapKeyStore(f.store.dir, f.store.wrapper, wrapper, f.now); err != nil {
		t.Fatal("an unreadable, non-authoritative stage prevented rewrap", err)
	}
	rootAfter, err := os.OpenRoot(f.store.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rootAfter.Close() }()
	if got, err := rootAfter.ReadFile(name + custodyStageExt); err != nil || !bytes.Equal(got, stage) {
		t.Fatal("rewrap did not preserve the interrupted stage for exact cleanup", err)
	}
	store := NewKeyStore(f.store.dir, wrapper)
	signer := f.open(t, store)
	got, err := signer.PrepareKeyImportV2(t.Context(), &signerpb.PrepareKeyImportV2Request{Version: request.GetVersion(), Policy: request.GetPolicy()})
	if err != nil || !proto.Equal(got, offer) {
		t.Fatal("exact preparation retry did not recover the signed offer after rewrap", err)
	}
	assertImportName(t, store, name+custodyStageExt, false)
}

type unavailableImportDestination struct {
	seal.KeyWrapper
}

func (unavailableImportDestination) WrapDEK([]byte) ([]byte, error) {
	return nil, errors.New("fixture destination wrapper unavailable")
}

func TestRewrapValidImportStageRequiresVerifiedDestination(t *testing.T) {
	f := newImportRecoveryFixture(t)
	// Isolate one legitimately sealed stage from other authoritative files.
	dir := t.TempDir()
	name := f.policy.Handle + keyFileExt + custodyStageExt
	stage, err := seal.Seal(f.store.wrapper, []byte("stage fixture"), []byte(f.policy.Handle))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), stage, 0o600); err != nil {
		t.Fatal(err)
	}
	destination := unavailableImportDestination{KeyWrapper: f.store.wrapper}
	if report, err := RewrapKeyStore(dir, f.store.wrapper, destination, f.now); err == nil || report.Backup != "" {
		t.Fatal("rewrap must fail when the destination cannot wrap a readable stage", err)
	}
}

func TestRewrapRefusesDirectoriesAtAuthoritativeImportNames(t *testing.T) {
	f := newImportRecoveryFixture(t)
	for _, name := range []string{keyImportIdentityName, keyImportPreparationName(f.policy.Handle), f.policy.Handle + keyFileExt} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
				t.Fatal(err)
			}
			if report, err := RewrapKeyStore(dir, f.store.wrapper, f.store.wrapper, f.now); err == nil || report.Backup != "" {
				t.Fatal("rewrap must refuse a directory at an authoritative import name", err)
			}
		})
	}
}

func TestImportedKeyAdmissionAuthenticatesPublicMetadata(t *testing.T) {
	f := newImportRecoveryFixture(t)
	_, request := f.prepare(t)
	handle := f.policy.Handle
	if _, err := f.signer.ImportWrappedKeyV2(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(f.store.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	stored, err := root.ReadFile(handle + keyFileExt)
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Destroy()
	otherPublic := other.Public().DER
	index := bytes.Index(stored, f.policy.ExpectedPublicKey)
	if index < 0 || len(otherPublic) != len(f.policy.ExpectedPublicKey) {
		t.Fatal("v4 authenticated public metadata is absent")
	}
	changed := bytes.Clone(stored)
	copy(changed[index:], otherPublic)
	plain, public, err := f.store.openHeldKey(handle, stored)
	if err != nil || !bytes.Equal(public, f.policy.ExpectedPublicKey) {
		t.Fatal("load the installed v4 envelope", err)
	}
	defer secret.Wipe(plain)
	otherDomain := append(installedImportDomain(handle), otherPublic...)
	inconsistent, err := seal.SealDomain(f.store.wrapper, plain, otherDomain, otherDomain)
	if err != nil {
		t.Fatal(err)
	}
	domainless, err := seal.Seal(f.store.wrapper, plain, []byte(handle))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, stem string
		ciphertext []byte
	}{
		{"different handle", crypto.CAHierarchySignerHandle("00000000-0000-4000-8000-000000082120"), stored},
		{"header changed", handle, changed},
		{"header truncated", handle, stored[:index+1]},
		{"header disagrees with the private key", handle, inconsistent},
		{"v4 receipt without the public envelope", handle, domainless},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if key, err := f.store.decodeHeldKey(tc.stem, tc.ciphertext); key != nil || err == nil {
				t.Fatal("inconsistent custody data admitted a key")
			}
		})
	}
}

func TestHierarchyPublicationGuardOrdersDestructionAcrossReplicas(t *testing.T) {
	f := newImportRecoveryFixture(t)
	_, request := f.prepare(t)
	replica := f.open(t, NewKeyStore(f.store.dir, f.store.wrapper))
	handle := &signerpb.KeyHandle{Id: f.policy.Handle}
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() { close(release) }()
	f.store.beforeHierarchySync = func() error {
		if exists, err := f.store.hierarchyEntryExists(handle.Id + keyFileExt); err != nil {
			return err
		} else if exists {
			close(entered)
			<-release
			return errors.New("fixture interrupted publisher")
		}
		return nil
	}
	result := make(chan error, 1)
	go func() {
		_, err := f.signer.ImportWrappedKeyV2(t.Context(), request)
		result <- err
	}()
	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("publisher exited before reaching the guarded boundary: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("publisher did not reach the guarded boundary")
	}
	if _, err := replica.DestroyKey(t.Context(), &signerpb.DestroyKeyRequest{Handle: handle}); status.Code(err) != codes.Unavailable {
		t.Fatalf("destruction did not defer to the active publisher: %v", err)
	}
	if _, err := replica.GenerateKey(t.Context(), &signerpb.GenerateKeyRequest{RequestedId: handle.Id, Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256}); status.Code(err) != codes.Unavailable {
		t.Fatalf("generic generation did not defer to the active publisher: %v", err)
	}
	if _, err := replica.RevokeKey(t.Context(), &signerpb.RevokeKeyRequest{Handle: handle, OperationId: "revoke", Reason: "key_compromise"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("revocation did not defer to the active publisher: %v", err)
	}
	release <- struct{}{}
	if err := <-result; status.Code(err) != codes.Internal {
		t.Fatalf("interrupted publisher returned %v", err)
	}
	if _, err := replica.DestroyKey(t.Context(), &signerpb.DestroyKeyRequest{Handle: handle}); err != nil {
		t.Fatal(err)
	}
	assertImportName(t, f.store, handle.Id+keyFileExt, false)
	assertImportName(t, f.store, keyImportPreparationName(handle.Id), false)
	if _, err := f.signer.ImportWrappedKeyV2(t.Context(), request); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("publisher resumed after guarded destruction: %v", err)
	}
}

func TestTerminalHierarchyMarkersCompleteInterruptedCleanup(t *testing.T) {
	t.Run("revocation retry preserves the first result after the key is gone", func(t *testing.T) {
		f := newImportRecoveryFixture(t)
		_, request := f.prepare(t)
		handle := &signerpb.KeyHandle{Id: f.policy.Handle}
		preparation := keyImportPreparationName(handle.Id)
		stage := preparation + custodyStageExt
		if err := os.Link(filepath.Join(f.store.dir, preparation), filepath.Join(f.store.dir, stage)); err != nil {
			t.Fatal(err)
		}
		f.store.beforeHierarchyUnlink = func(name string) error {
			if name == stage {
				return errors.New("fixture cleanup failure")
			}
			return nil
		}
		if result, err := f.signer.ImportWrappedKeyV2(t.Context(), request); result != nil || status.Code(err) != codes.Internal {
			t.Fatalf("import acknowledged before retiring its staged preparation: %v", err)
		}
		revoke := &signerpb.RevokeKeyRequest{Handle: handle, OperationId: "first", Reason: "key_compromise"}
		if result, err := f.signer.RevokeKey(t.Context(), revoke); result != nil || status.Code(err) != codes.Internal {
			t.Fatalf("revocation acknowledged before retiring the staged preparation: %v", err)
		}
		mark, found, err := f.store.Revocation(handle.Id)
		if err != nil || !found || mark.OperationID != "first" {
			t.Fatal("the revocation fence must persist before cleanup", err)
		}
		if result, err := f.signer.ImportWrappedKeyV2(t.Context(), request); result != nil || status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("exact import replay passed a revocation fence: %v", err)
		}
		if err := os.Remove(filepath.Join(f.store.dir, handle.Id+keyFileExt)); err != nil {
			t.Fatal(err)
		}
		f.store.beforeHierarchyUnlink = nil
		revoke.OperationId, revoke.Reason = "second", "cessation_of_operation"
		result, err := f.signer.RevokeKey(t.Context(), revoke)
		if err != nil || result.GetOperationId() != mark.OperationID || result.GetReason() != mark.Reason ||
			result.GetRevokedAtUnix() != mark.RevokedAt || !bytes.Equal(result.GetPublicKey(), f.policy.ExpectedPublicKey) {
			t.Fatal("revocation retry lost the first result", err)
		}
		assertImportName(t, f.store, stage, false)
	})
	t.Run("destruction repairs a torn marker and retires both names without a key", func(t *testing.T) {
		f := newImportRecoveryFixture(t)
		_, request := f.prepare(t)
		handle := &signerpb.KeyHandle{Id: f.policy.Handle}
		preparation := keyImportPreparationName(handle.Id)
		if err := os.Link(filepath.Join(f.store.dir, preparation), filepath.Join(f.store.dir, preparation+custodyStageExt)); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(f.store.dir, handle.Id+destroyedKeyFileExt)
		if err := os.WriteFile(marker, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := f.signer.DestroyKey(t.Context(), &signerpb.DestroyKeyRequest{Handle: handle}); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(f.store.dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		body, err := root.ReadFile(handle.Id + destroyedKeyFileExt)
		if err != nil || string(body) != destructionMarker {
			t.Fatal("destruction did not repair the durable terminal marker", err)
		}
		assertImportName(t, f.store, preparation, false)
		assertImportName(t, f.store, preparation+custodyStageExt, false)
		if result, err := f.signer.ImportWrappedKeyV2(t.Context(), request); result != nil || status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("import passed a destroyed handle fence: %v", err)
		}
	})
}
