// SPDX-License-Identifier: MPL-2.0

package signing_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

type journalProvider struct {
	mu       sync.Mutex
	keys     map[string]*crypto.LockedSigner
	next     int
	generate int
	revoke   int
	zeroize  int
	sign     int
}

type journalSigner struct{ key *crypto.LockedSigner }

type echoingJournalProvider struct {
	delegate      *journalProvider
	marker        string
	failLifecycle bool
	failSign      bool
}

// operationAwareJournalProvider is a faithful remote receiver: operationID is
// the durable find-or-create identity. failAfterEffect simulates the signer
// losing the provider response after the receiver committed its side effect.
type operationAwareJournalProvider struct {
	delegate        *journalProvider
	mu              sync.Mutex
	generated       map[string]crypto.KeyRef
	destructiveDone map[string]struct{}
	failAfterEffect bool
}

func newOperationAwareJournalProvider() *operationAwareJournalProvider {
	return &operationAwareJournalProvider{
		delegate:        newJournalProvider(),
		generated:       make(map[string]crypto.KeyRef),
		destructiveDone: make(map[string]struct{}),
	}
}

func (p *operationAwareJournalProvider) signer(ref crypto.KeyRef) (crypto.Signer, error) {
	p.delegate.mu.Lock()
	defer p.delegate.mu.Unlock()
	key := p.delegate.keys[ref.ID]
	if key == nil {
		return nil, fmt.Errorf("operation receiver key is absent")
	}
	return journalSigner{key: key}, nil
}

func (p *operationAwareJournalProvider) GenerateManagedKey(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	return p.delegate.GenerateManagedKey(ctx, alg)
}

func (p *operationAwareJournalProvider) RotateKey(ctx context.Context, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	return p.delegate.RotateKey(ctx, ref)
}

func (p *operationAwareJournalProvider) RevokeKey(ctx context.Context, ref crypto.KeyRef) error {
	return p.delegate.RevokeKey(ctx, ref)
}

func (p *operationAwareJournalProvider) ZeroizeKey(ctx context.Context, ref crypto.KeyRef) error {
	return p.delegate.ZeroizeKey(ctx, ref)
}

func (p *operationAwareJournalProvider) GenerateManagedKeyForOperation(ctx context.Context, operationID string, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ref, ok := p.generated[operationID]; ok {
		signer, err := p.signer(ref)
		return signer, ref, err
	}
	signer, ref, err := p.delegate.GenerateManagedKey(ctx, alg)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	p.generated[operationID] = ref
	if p.failAfterEffect {
		p.failAfterEffect = false
		return nil, crypto.KeyRef{}, errors.New("response lost after provider committed key")
	}
	return signer, ref, nil
}

func (p *operationAwareJournalProvider) RotateKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	return p.GenerateManagedKeyForOperation(ctx, operationID, ref.Algorithm)
}

func (p *operationAwareJournalProvider) RevokeKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.destructiveDone[operationID]; ok {
		return nil
	}
	if err := p.delegate.RevokeKey(ctx, ref); err != nil {
		return err
	}
	p.destructiveDone[operationID] = struct{}{}
	if p.failAfterEffect {
		p.failAfterEffect = false
		return errors.New("response lost after provider revoked key")
	}
	return nil
}

func (p *operationAwareJournalProvider) ZeroizeKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.destructiveDone[operationID]; ok {
		return nil
	}
	if err := p.delegate.ZeroizeKey(ctx, ref); err != nil {
		return err
	}
	p.destructiveDone[operationID] = struct{}{}
	if p.failAfterEffect {
		p.failAfterEffect = false
		return errors.New("response lost after provider zeroized key")
	}
	return nil
}

func (p *echoingJournalProvider) GenerateManagedKey(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	if p.failLifecycle {
		return nil, crypto.KeyRef{}, fmt.Errorf("upstream echoed authorization=%s", p.marker)
	}
	return p.delegate.GenerateManagedKey(ctx, alg)
}

func (p *echoingJournalProvider) RotateKey(ctx context.Context, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if p.failLifecycle {
		return nil, crypto.KeyRef{}, fmt.Errorf("upstream echoed authorization=%s", p.marker)
	}
	return p.delegate.RotateKey(ctx, ref)
}

func (p *echoingJournalProvider) RevokeKey(ctx context.Context, ref crypto.KeyRef) error {
	return p.delegate.RevokeKey(ctx, ref)
}

func (p *echoingJournalProvider) ZeroizeKey(ctx context.Context, ref crypto.KeyRef) error {
	return p.delegate.ZeroizeKey(ctx, ref)
}

func (p *echoingJournalProvider) SignManagedDigest(ctx context.Context, ref crypto.KeyRef, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	if p.failSign {
		return nil, fmt.Errorf("upstream echoed bearer=%s", p.marker)
	}
	return p.delegate.SignManagedDigest(ctx, ref, digest, opts)
}

func (s journalSigner) Public() crypto.PublicKey    { return s.key.Public() }
func (s journalSigner) Algorithm() crypto.Algorithm { return s.key.Algorithm() }
func (s journalSigner) Sign(message []byte, opts crypto.SignOptions) ([]byte, error) {
	hash := opts.Hash
	if hash == "" {
		hash = crypto.SHA256
	}
	digest, err := crypto.Digest(hash, message)
	if err != nil {
		return nil, err
	}
	return s.key.SignDigest(digest, opts)
}

func newJournalProvider() *journalProvider {
	return &journalProvider{keys: make(map[string]*crypto.LockedSigner)}
}

func (p *journalProvider) GenerateManagedKey(_ context.Context, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	p.next++
	p.generate++
	id := fmt.Sprintf("provider-key-%d", p.next)
	p.keys[id] = key
	return journalSigner{key: key}, crypto.KeyRef{ID: id, Algorithm: alg}, nil
}

func (p *journalProvider) RotateKey(ctx context.Context, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	return p.GenerateManagedKey(ctx, ref.Algorithm)
}

func (p *journalProvider) RevokeKey(_ context.Context, ref crypto.KeyRef) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.keys[ref.ID] == nil {
		return fmt.Errorf("unknown key")
	}
	p.revoke++
	return nil
}

func (p *journalProvider) ZeroizeKey(_ context.Context, ref crypto.KeyRef) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := p.keys[ref.ID]
	if key == nil {
		return fmt.Errorf("unknown key")
	}
	key.Destroy()
	delete(p.keys, ref.ID)
	p.zeroize++
	return nil
}

func (p *journalProvider) SignManagedDigest(_ context.Context, ref crypto.KeyRef, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := p.keys[ref.ID]
	if key == nil {
		return nil, fmt.Errorf("unknown key")
	}
	p.sign++
	return key.SignDigest(digest, opts)
}

func (p *journalProvider) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, key := range p.keys {
		key.Destroy()
		delete(p.keys, id)
	}
}

func TestManagedKeyDigestSignBindsTenantProviderRefAndState(t *testing.T) {
	provider := newJournalProvider()
	t.Cleanup(provider.cleanup)
	authorizer := managedKeyTestAuthorizer(t)
	server := signing.NewServer(
		signing.WithAuthorizer(authorizer),
		signing.WithManagedKeyProviders(t.TempDir(), map[string]crypto.RemoteKeyLifecycle{"aws-kms": provider}),
	)
	created, err := server.ManageKey(context.Background(), &signerpb.ManageKeyRequest{
		TenantId: "tenant-a", Provider: "aws-kms", OperationId: "create-signing-key",
		Action:    signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_GENERATE,
		Algorithm: signerpb.Algorithm_ALGORITHM_RSA_2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := crypto.Digest(crypto.SHA256, []byte("managed key digest signing boundary"))
	if err != nil {
		t.Fatal(err)
	}
	request := managedKeyAuthorizedSignRequest(t, authorizer, created.GetKeyId(), digest, 1, time.Now().Add(time.Minute), signing.PurposeCASign)
	signed, err := server.SignManagedKey(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.VerifyDigest(crypto.PublicKey{Algorithm: crypto.RSA2048, DER: created.GetPublicKey()}, digest, signed.GetSignature(), crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatalf("managed provider signature: %v", err)
	}
	crossTenant := managedKeyAuthorizedSignRequest(t, authorizer, created.GetKeyId(), digest, 2, time.Now().Add(time.Minute), signing.PurposeCASign)
	crossTenant.TenantId = "tenant-b"
	if _, err := server.SignManagedKey(context.Background(), crossTenant); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-tenant sign status = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := server.ManageKey(context.Background(), &signerpb.ManageKeyRequest{
		TenantId: "tenant-a", Provider: "aws-kms", OperationId: "revoke-signing-key",
		Action: signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_REVOKE, KeyId: created.GetKeyId(),
		Algorithm: signerpb.Algorithm_ALGORITHM_RSA_2048,
	}); err != nil {
		t.Fatal(err)
	}
	revokedRequest := managedKeyAuthorizedSignRequest(t, authorizer, created.GetKeyId(), digest, 3, time.Now().Add(time.Minute), signing.PurposeCASign)
	if _, err := server.SignManagedKey(context.Background(), revokedRequest); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("revoked sign status = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestManagedKeyDigestSignRequiresExpiringReplaySafeBoundAuthorization(t *testing.T) {
	provider := newJournalProvider()
	t.Cleanup(provider.cleanup)
	authorizer := managedKeyTestAuthorizer(t)
	dir := t.TempDir()
	newServer := func(withAuthorizer bool) *signing.Server {
		options := []signing.ServerOption{signing.WithManagedKeyProviders(dir, map[string]crypto.RemoteKeyLifecycle{"aws-kms": provider})}
		if withAuthorizer {
			options = append(options, signing.WithAuthorizer(authorizer))
		}
		return signing.NewServer(options...)
	}
	server := newServer(true)
	created, err := server.ManageKey(context.Background(), &signerpb.ManageKeyRequest{
		TenantId: "tenant-a", Provider: "aws-kms", OperationId: "create-authorized-key",
		Action:    signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_GENERATE,
		Algorithm: signerpb.Algorithm_ALGORITHM_RSA_2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := crypto.Digest(crypto.SHA256, []byte("authorized managed-key signing tuple"))
	if err != nil {
		t.Fatal(err)
	}

	missing := managedKeySignRequest(created.GetKeyId(), digest, 10, time.Now().Add(time.Minute), signing.PurposeCASign)
	if _, err := server.SignManagedKey(context.Background(), missing); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("missing token status = %v, want PermissionDenied", status.Code(err))
	}
	forged := managedKeySignRequest(created.GetKeyId(), digest, 11, time.Now().Add(time.Minute), signing.PurposeCASign)
	forged.AuthorizationToken = bytes.Repeat([]byte{0xA7}, 32)
	if _, err := server.SignManagedKey(context.Background(), forged); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("forged token status = %v, want PermissionDenied", status.Code(err))
	}
	expired := managedKeyAuthorizedSignRequest(t, authorizer, created.GetKeyId(), digest, 12, time.Now().Add(-time.Second), signing.PurposeCASign)
	if _, err := server.SignManagedKey(context.Background(), expired); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expired token status = %v, want PermissionDenied", status.Code(err))
	}

	alteredDigest := managedKeyAuthorizedSignRequest(t, authorizer, created.GetKeyId(), digest, 13, time.Now().Add(time.Minute), signing.PurposeCASign)
	alteredDigest.Digest = bytes.Clone(alteredDigest.Digest)
	alteredDigest.Digest[0] ^= 0x80
	if _, err := server.SignManagedKey(context.Background(), alteredDigest); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("altered digest status = %v, want PermissionDenied", status.Code(err))
	}
	alteredRef := managedKeyAuthorizedSignRequest(t, authorizer, created.GetKeyId(), digest, 14, time.Now().Add(time.Minute), signing.PurposeCASign)
	alteredRef.KeyId += "-substituted"
	if _, err := server.SignManagedKey(context.Background(), alteredRef); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("altered ref status = %v, want PermissionDenied", status.Code(err))
	}
	alteredPurpose := managedKeyAuthorizedSignRequest(t, authorizer, created.GetKeyId(), digest, 15, time.Now().Add(time.Minute), signing.PurposeCASign)
	alteredPurpose.Purpose = signing.PurposeCodeSign
	if _, err := server.SignManagedKey(context.Background(), alteredPurpose); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("altered purpose status = %v, want PermissionDenied", status.Code(err))
	}

	replay := managedKeyAuthorizedSignRequest(t, authorizer, created.GetKeyId(), digest, 16, time.Now().Add(time.Minute), signing.PurposeCASign)
	if _, err := server.SignManagedKey(context.Background(), replay); err != nil {
		t.Fatalf("authorized sign: %v", err)
	}
	managedKeyAuthorizeRequest(t, authorizer, replay)
	if _, err := server.SignManagedKey(context.Background(), replay); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("same-process replay status = %v, want PermissionDenied", status.Code(err))
	}
	managedKeyAuthorizeRequest(t, authorizer, replay)
	if _, err := newServer(true).SignManagedKey(context.Background(), replay); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("restart replay status = %v, want PermissionDenied", status.Code(err))
	}
	if provider.sign != 1 {
		t.Fatalf("adversarial requests reached provider %d times, want exactly one authorized sign", provider.sign)
	}

	withoutAuthorizer := managedKeySignRequest(created.GetKeyId(), digest, 17, time.Now().Add(time.Minute), signing.PurposeCASign)
	if _, err := newServer(false).SignManagedKey(context.Background(), withoutAuthorizer); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("signer without authorizer status = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestManagedKeyProviderFailureTextNeverEscapesStatusOrJournal(t *testing.T) {
	const marker = "dod-provider-secret-echo-7d119a"
	provider := &echoingJournalProvider{delegate: newJournalProvider(), marker: marker, failLifecycle: true}
	t.Cleanup(provider.delegate.cleanup)
	dir := t.TempDir()
	server := signing.NewServer(signing.WithManagedKeyProviders(dir, map[string]crypto.RemoteKeyLifecycle{"aws-kms": provider}))
	request := &signerpb.ManageKeyRequest{
		TenantId: "tenant-a", Provider: "aws-kms", OperationId: "echoing-provider-operation",
		Action: signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_GENERATE, Algorithm: signerpb.Algorithm_ALGORITHM_RSA_2048,
	}
	_, err := server.ManageKey(context.Background(), request)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("provider failure status = %v, want Unavailable", status.Code(err))
	}
	assertManagedKeyMarkerAbsent(t, marker, []byte(err.Error()))
	journal := readManagedKeyJournalBytes(t, dir)
	assertManagedKeyMarkerAbsent(t, marker, journal)
	if !bytes.Contains(journal, []byte(`"failure":"provider_action_failed"`)) {
		t.Fatalf("journal did not retain the closed provider failure code: %s", journal)
	}

	_, err = server.ManageKey(context.Background(), request)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("failed-operation replay status = %v, want FailedPrecondition", status.Code(err))
	}
	assertManagedKeyMarkerAbsent(t, marker, []byte(err.Error()))

	signProvider := &echoingJournalProvider{delegate: newJournalProvider(), marker: marker}
	t.Cleanup(signProvider.delegate.cleanup)
	signDir := t.TempDir()
	authorizer := managedKeyTestAuthorizer(t)
	signServer := signing.NewServer(
		signing.WithAuthorizer(authorizer),
		signing.WithManagedKeyProviders(signDir, map[string]crypto.RemoteKeyLifecycle{"aws-kms": signProvider}),
	)
	created, err := signServer.ManageKey(context.Background(), &signerpb.ManageKeyRequest{
		TenantId: "tenant-a", Provider: "aws-kms", OperationId: "create-before-echoing-sign",
		Action: signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_GENERATE, Algorithm: signerpb.Algorithm_ALGORITHM_RSA_2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	signProvider.failSign = true
	digest, err := crypto.Digest(crypto.SHA256, []byte("provider error echo must stay closed"))
	if err != nil {
		t.Fatal(err)
	}
	signRequest := managedKeyAuthorizedSignRequest(t, authorizer, created.GetKeyId(), digest, 41, time.Now().Add(time.Minute), signing.PurposeCASign)
	_, err = signServer.SignManagedKey(context.Background(), signRequest)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("provider sign failure status = %v, want Unavailable", status.Code(err))
	}
	assertManagedKeyMarkerAbsent(t, marker, []byte(err.Error()), readManagedKeyJournalBytes(t, signDir))
}

func readManagedKeyJournalBytes(t *testing.T, root string) []byte {
	t.Helper()
	var all bytes.Buffer
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, _ = all.Write(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return all.Bytes()
}

func assertManagedKeyMarkerAbsent(t *testing.T, marker string, values ...[]byte) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(string(value), marker) {
			t.Fatalf("provider-controlled secret marker escaped signer boundary: %q", marker)
		}
	}
}

func managedKeyTestAuthorizer(t *testing.T) *crypto.SignAuthorizer {
	t.Helper()
	raw := bytes.Repeat([]byte{0x6D}, 32)
	authorizer, err := crypto.NewSignAuthorizer(raw)
	secret.Wipe(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authorizer.Destroy)
	return authorizer
}

func managedKeySignRequest(keyID string, digest []byte, nonceByte byte, expires time.Time, purpose signing.KeyPurpose) *signerpb.SignManagedKeyRequest {
	return &signerpb.SignManagedKeyRequest{
		TenantId: "tenant-a", Provider: "aws-kms", KeyId: keyID,
		Algorithm: signerpb.Algorithm_ALGORITHM_RSA_2048, Digest: bytes.Clone(digest),
		Hash: signerpb.Hash_HASH_SHA256, RsaPadding: signerpb.RSAPadding_RSA_PADDING_PKCS1V15,
		Purpose: purpose, AuthorizationExpiresUnix: expires.Unix(),
		AuthorizationNonce: bytes.Repeat([]byte{nonceByte}, 32),
	}
}

func managedKeyAuthorizedSignRequest(t *testing.T, authorizer *crypto.SignAuthorizer, keyID string, digest []byte, nonceByte byte, expires time.Time, purpose signing.KeyPurpose) *signerpb.SignManagedKeyRequest {
	t.Helper()
	request := managedKeySignRequest(keyID, digest, nonceByte, expires, purpose)
	managedKeyAuthorizeRequest(t, authorizer, request)
	return request
}

func managedKeyAuthorizeRequest(t *testing.T, authorizer *crypto.SignAuthorizer, request *signerpb.SignManagedKeyRequest) {
	t.Helper()
	intent, err := signing.ManagedKeySignAuthorizationIntent(
		request.GetTenantId(), request.GetProvider(), request.GetKeyId(), crypto.RSA2048,
		request.GetPurpose(), request.GetAuthorizationExpiresUnix(), request.GetAuthorizationNonce(),
		request.GetDigest(), crypto.SignOptions{Hash: crypto.SHA256, RSAPadding: crypto.RSAPKCS1v15},
	)
	if err != nil {
		t.Fatal(err)
	}
	token, err := authorizer.Authorize(intent)
	if err != nil {
		t.Fatal(err)
	}
	request.AuthorizationToken = token
}

func TestManagedKeyJournalReplaysAcrossSignerRestartAndBindsTenant(t *testing.T) {
	provider := newJournalProvider()
	t.Cleanup(provider.cleanup)
	dir := t.TempDir()
	newServer := func() *signing.Server {
		return signing.NewServer(signing.WithManagedKeyProviders(dir, map[string]crypto.RemoteKeyLifecycle{
			"aws-kms": provider,
		}))
	}

	first := newServer()
	req := &signerpb.ManageKeyRequest{
		TenantId: "tenant-a", Provider: "aws-kms", OperationId: "outbox-op-1",
		Action:    signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_GENERATE,
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
	}
	created, err := first.ManageKey(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if created.GetKeyId() == "" || created.GetState() != "active" || created.GetReplayed() {
		t.Fatalf("first result = %+v", created)
	}

	// A fresh Server simulates a signer process restart. The completed operation
	// and provider-ref ownership are reloaded from signer-owned storage.
	second := newServer()
	replayed, err := second.ManageKey(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.GetReplayed() || replayed.GetKeyId() != created.GetKeyId() || provider.generate != 1 {
		t.Fatalf("restart replay = %+v provider_generates=%d", replayed, provider.generate)
	}

	_, err = second.ManageKey(context.Background(), &signerpb.ManageKeyRequest{
		TenantId: "tenant-b", Provider: "aws-kms", OperationId: "outbox-op-tenant-b",
		Action: signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_REVOKE,
		KeyId:  created.GetKeyId(), Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("cross-tenant provider ref status = %v, want Unavailable fail-closed", status.Code(err))
	}
	if provider.revoke != 0 {
		t.Fatalf("cross-tenant command reached provider %d times", provider.revoke)
	}
}

func TestManagedKeyExecutingJournalReconcilesCommittedProviderEffectAfterSignerRestart(t *testing.T) {
	provider := newOperationAwareJournalProvider()
	provider.failAfterEffect = true
	t.Cleanup(provider.delegate.cleanup)
	dir := t.TempDir()
	newServer := func() *signing.Server {
		return signing.NewServer(signing.WithManagedKeyProviders(dir, map[string]crypto.RemoteKeyLifecycle{
			"aws-kms": provider,
		}))
	}
	request := &signerpb.ManageKeyRequest{
		TenantId: "tenant-a", Provider: "aws-kms", OperationId: "provider-committed-before-signer-journal",
		Action: signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_GENERATE, Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
	}

	if _, err := newServer().ManageKey(context.Background(), request); status.Code(err) != codes.Unavailable {
		t.Fatalf("lost provider response status=%v, want retryable Unavailable", status.Code(err))
	}
	if provider.delegate.generate != 1 {
		t.Fatalf("provider effects after lost response=%d, want exactly one committed key", provider.delegate.generate)
	}

	// A new Server has no process-local operation state. It reloads the executing
	// intent, asks the receiver for the same operation ID, and completes the
	// journal with the original key rather than returning Aborted or creating two.
	reconciled, err := newServer().ManageKey(context.Background(), request)
	if err != nil {
		t.Fatalf("restart reconciliation: %v", err)
	}
	if !reconciled.GetReplayed() || reconciled.GetKeyId() == "" || provider.delegate.generate != 1 {
		t.Fatalf("restart result=%+v provider effects=%d, want replayed original key and one effect", reconciled, provider.delegate.generate)
	}
	completed, err := newServer().ManageKey(context.Background(), request)
	if err != nil || !completed.GetReplayed() || completed.GetKeyId() != reconciled.GetKeyId() || provider.delegate.generate != 1 {
		t.Fatalf("completed restart replay=%+v err=%v provider effects=%d", completed, err, provider.delegate.generate)
	}

	provider.failAfterEffect = true
	revoke := &signerpb.ManageKeyRequest{
		TenantId: "tenant-a", Provider: "aws-kms", OperationId: "provider-revoked-before-signer-journal",
		Action: signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_REVOKE, KeyId: reconciled.GetKeyId(),
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
	}
	if _, err := newServer().ManageKey(context.Background(), revoke); status.Code(err) != codes.Unavailable {
		t.Fatalf("lost revoke response status=%v, want retryable Unavailable", status.Code(err))
	}
	revoked, err := newServer().ManageKey(context.Background(), revoke)
	if err != nil || !revoked.GetReplayed() || revoked.GetState() != "revoked" || provider.delegate.revoke != 1 {
		t.Fatalf("reconciled revoke=%+v err=%v provider effects=%d", revoked, err, provider.delegate.revoke)
	}

	provider.failAfterEffect = true
	zeroize := &signerpb.ManageKeyRequest{
		TenantId: "tenant-a", Provider: "aws-kms", OperationId: "provider-zeroized-before-signer-journal",
		Action: signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_ZEROIZE, KeyId: reconciled.GetKeyId(),
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
	}
	if _, err := newServer().ManageKey(context.Background(), zeroize); status.Code(err) != codes.Unavailable {
		t.Fatalf("lost zeroize response status=%v, want retryable Unavailable", status.Code(err))
	}
	zeroized, err := newServer().ManageKey(context.Background(), zeroize)
	if err != nil || !zeroized.GetReplayed() || zeroized.GetState() != "zeroized" || provider.delegate.zeroize != 1 {
		t.Fatalf("reconciled zeroize=%+v err=%v provider effects=%d", zeroized, err, provider.delegate.zeroize)
	}
}
