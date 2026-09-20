// SPDX-License-Identifier: BUSL-1.1

package signing

// This file is the AN-4 transport endpoint for cloud KMS and hardware-backed
// managed-key lifecycle operations. Provider implementations are injected by
// cmd/trstctl-signer; the control plane only sends durable, tenant-scoped public
// commands over gRPC. The signer has no SQL/NATS/HTTP-server dependency.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

const (
	managedKeyJournalVersion        = 1
	managedKeySignMaxAuthorization  = 2 * time.Minute
	managedKeyFailureProviderAction = "provider_action_failed"
	managedKeyFailureProviderSign   = "provider_sign_failed"
	managedKeyFailureProviderEmpty  = "provider_empty_signature"
	managedKeyFailureJournal        = "provider_failure_journal_unavailable"
)

var errManagedKeySignAuthorizationReplay = errors.New("managed-key sign authorization nonce was already consumed")

var managedKeyCustodyProbe = []byte("trstctl managed-key custody proof v1")

// WithManagedKeyProviders installs signer-local provider lifecycles and their
// durable operation journal. journalDir must be on signer-owned storage in
// production (normally signer.key_store_dir). A completed operation survives a
// process restart and is returned on outbox redelivery without touching the
// provider a second time.
func WithManagedKeyProviders(journalDir string, providers map[string]crypto.RemoteKeyLifecycle) ServerOption {
	return func(s *Server) {
		if len(providers) == 0 {
			return
		}
		cloned := make(map[string]crypto.RemoteKeyLifecycle, len(providers))
		for name, provider := range providers {
			name = normalizeManagedKeyProvider(name)
			if name != "" && provider != nil {
				cloned[name] = provider
			}
		}
		s.managedKeys = newManagedKeyRuntime(journalDir, cloned)
	}
}

type managedKeyRuntime struct {
	mu         sync.Mutex
	root       string
	providers  map[string]crypto.RemoteKeyLifecycle
	owners     map[string]managedKeyOwner
	volatile   map[string]managedKeyOperation
	usedNonces map[string]int64
	loadErr    error
}

type managedKeyOwner struct {
	TenantID  string           `json:"tenant_id"`
	Provider  string           `json:"provider"`
	KeyID     string           `json:"key_id"`
	Algorithm crypto.Algorithm `json:"algorithm"`
	PublicDER []byte           `json:"public_der,omitempty"`
	State     string           `json:"state"`
}

type managedKeyOperation struct {
	Version int                      `json:"version"`
	Request managedKeyJournalRequest `json:"request"`
	Status  string                   `json:"status"`
	Result  managedKeyJournalResult  `json:"result,omitempty"`
	Failure string                   `json:"failure,omitempty"`
}

type managedKeyJournalRequest struct {
	TenantID    string           `json:"tenant_id"`
	Provider    string           `json:"provider"`
	OperationID string           `json:"operation_id"`
	Action      int32            `json:"action"`
	KeyID       string           `json:"key_id,omitempty"`
	Algorithm   crypto.Algorithm `json:"algorithm"`
}

type managedKeyJournalResult struct {
	Provider  string           `json:"provider"`
	KeyID     string           `json:"key_id"`
	Algorithm crypto.Algorithm `json:"algorithm"`
	PublicDER []byte           `json:"public_der,omitempty"`
	State     string           `json:"state"`
}

func newManagedKeyRuntime(root string, providers map[string]crypto.RemoteKeyLifecycle) *managedKeyRuntime {
	r := &managedKeyRuntime{
		root: strings.TrimSpace(root), providers: providers,
		owners: make(map[string]managedKeyOwner), volatile: make(map[string]managedKeyOperation),
		usedNonces: make(map[string]int64),
	}
	if err := r.loadOwners(); err != nil {
		r.loadErr = fmt.Errorf("load managed-key ownership: %w", err)
	}
	if err := r.loadSignNonces(); err != nil {
		r.loadErr = errors.Join(r.loadErr, fmt.Errorf("load managed-key authorization nonces: %w", err))
	}
	return r
}

func normalizeManagedKeyProvider(in string) string {
	switch strings.ToLower(strings.TrimSpace(in)) {
	case "aws", "aws-kms":
		return "aws-kms"
	case "azure", "azure-kv", "azure-key-vault", "azure-managed-hsm":
		return "azure-key-vault"
	case "gcp", "gcp-kms":
		return "gcp-kms"
	case "pkcs11", "pkcs#11":
		return "pkcs11"
	case "tpm", "tpm2":
		return "tpm2"
	case "yubihsm", "yubihsm2":
		return "yubihsm2"
	default:
		return strings.ToLower(strings.TrimSpace(in))
	}
}

// ManageKey is the only signer RPC that drives a remote KMS/HSM lifecycle.
func (s *Server) ManageKey(ctx context.Context, req *signerpb.ManageKeyRequest) (*signerpb.ManageKeyResponse, error) {
	if s.managedKeys == nil {
		return nil, status.Error(codes.FailedPrecondition, "no managed-key provider is configured in the signer")
	}
	result, replayed, err := s.managedKeys.execute(ctx, req)
	if err != nil {
		return nil, err
	}
	return &signerpb.ManageKeyResponse{
		Provider: result.Provider, KeyId: result.KeyID,
		Algorithm: algorithmToProto(result.Algorithm), PublicKey: bytes.Clone(result.PublicDER),
		State: result.State, Replayed: replayed,
	}, nil
}

// SignManagedKey performs an existing provider-key digest signature only after
// signer-local tenant/provider/ref ownership validation. Provider credentials
// and the private operation stay in this separate process.
func (s *Server) SignManagedKey(ctx context.Context, req *signerpb.SignManagedKeyRequest) (*signerpb.SignManagedKeyResponse, error) {
	if s.managedKeys == nil {
		return nil, status.Error(codes.FailedPrecondition, "no managed-key provider is configured in the signer")
	}
	signature, err := s.managedKeys.signDigest(ctx, req, s.authorizer)
	if err != nil {
		return nil, err
	}
	return &signerpb.SignManagedKeyResponse{Signature: signature}, nil
}

func (r *managedKeyRuntime) signDigest(ctx context.Context, req *signerpb.SignManagedKeyRequest, authorizer *crypto.SignAuthorizer) ([]byte, error) {
	if req == nil || req.GetTenantId() == "" || req.GetProvider() == "" || req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "managed-key tenant, provider, and key id are required")
	}
	if authorizer == nil {
		return nil, status.Error(codes.FailedPrecondition, "managed-key signing has no independent content authorizer configured")
	}
	defer secret.Wipe(req.AuthorizationToken)
	alg, err := algorithmFromProto(req.GetAlgorithm())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	hash, digestLength, err := hashFromProto(req.GetHash())
	if err != nil || len(req.GetDigest()) != digestLength {
		return nil, status.Errorf(codes.InvalidArgument, "managed-key digest length %d does not match the declared hash", len(req.GetDigest()))
	}
	if !validManagedKeySignPurpose(req.GetPurpose()) {
		return nil, status.Error(codes.PermissionDenied, "managed-key sign purpose is missing or unsupported")
	}
	now := time.Now()
	if req.GetAuthorizationExpiresUnix() <= now.Unix() || req.GetAuthorizationExpiresUnix() > now.Add(managedKeySignMaxAuthorization).Unix() {
		return nil, status.Error(codes.PermissionDenied, "managed-key sign authorization is expired or exceeds the maximum lifetime")
	}
	if len(req.GetAuthorizationNonce()) < 16 || len(req.GetAuthorizationNonce()) > 64 || len(req.GetAuthorizationToken()) == 0 {
		return nil, status.Error(codes.PermissionDenied, "managed-key sign authorization nonce and token are required")
	}
	providerName := normalizeManagedKeyProvider(req.GetProvider())
	opts := crypto.SignOptions{Hash: hash, RSAPadding: paddingFromProto(req.GetRsaPadding())}
	intent, err := ManagedKeySignAuthorizationIntent(
		req.GetTenantId(), providerName, req.GetKeyId(), alg, req.GetPurpose(),
		req.GetAuthorizationExpiresUnix(), req.GetAuthorizationNonce(), req.GetDigest(), opts,
	)
	if err != nil || !authorizer.Verify(intent, req.GetAuthorizationToken()) {
		return nil, status.Error(codes.PermissionDenied, "managed-key sign authorization is invalid for this request")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loadErr != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "managed-key signer journal is unavailable: %v", r.loadErr)
	}
	provider := r.providers[providerName]
	if provider == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "managed-key provider %q is not configured in the signer", providerName)
	}
	owner, ok := r.owners[managedKeyOwnerKey(providerName, req.GetKeyId())]
	if !ok || owner.TenantID != req.GetTenantId() || owner.Algorithm != alg {
		return nil, status.Error(codes.PermissionDenied, "managed-key ref is not owned by this tenant/provider/algorithm")
	}
	if owner.State != "active" {
		return nil, status.Errorf(codes.FailedPrecondition, "managed-key state %q cannot sign", owner.State)
	}
	digestSigner, ok := provider.(crypto.RemoteKeyDigestSigner)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "managed-key provider does not implement digest signing")
	}
	if err := r.consumeSignNonce(req.GetAuthorizationNonce(), req.GetAuthorizationExpiresUnix(), now); err != nil {
		if errors.Is(err, errManagedKeySignAuthorizationReplay) {
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "persist managed-key sign authorization consumption: %v", err)
	}
	signature, err := digestSigner.SignManagedDigest(ctx, crypto.KeyRef{ID: owner.KeyID, Algorithm: owner.Algorithm}, bytes.Clone(req.GetDigest()), crypto.SignOptions{
		Hash: opts.Hash, RSAPadding: opts.RSAPadding,
	})
	if err != nil {
		return nil, managedKeyClosedFailure(codes.Unavailable, managedKeyFailureProviderSign)
	}
	if len(signature) == 0 {
		return nil, managedKeyClosedFailure(codes.Internal, managedKeyFailureProviderEmpty)
	}
	return signature, nil
}

func (r *managedKeyRuntime) execute(ctx context.Context, req *signerpb.ManageKeyRequest) (managedKeyJournalResult, bool, error) {
	jr, err := validateManagedKeyRequest(req)
	if err != nil {
		return managedKeyJournalResult{}, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loadErr != nil {
		return managedKeyJournalResult{}, false, status.Errorf(codes.FailedPrecondition, "managed-key signer journal is unavailable: %v", r.loadErr)
	}

	provider := r.providers[jr.Provider]
	if provider == nil {
		return managedKeyJournalResult{}, false, status.Errorf(codes.FailedPrecondition, "managed-key provider %q is not configured in the signer", jr.Provider)
	}
	if prior, ok, err := r.loadOperation(jr.OperationID); err != nil {
		return managedKeyJournalResult{}, false, status.Errorf(codes.Internal, "load managed-key operation: %v", err)
	} else if ok {
		if prior.Request != jr {
			return managedKeyJournalResult{}, false, status.Error(codes.AlreadyExists, "managed-key operation id was already used for a different command")
		}
		switch prior.Status {
		case "completed":
			return prior.Result, true, nil
		case "failed":
			return managedKeyJournalResult{}, true, managedKeyClosedFailure(codes.FailedPrecondition, closedManagedKeyFailureCode(prior.Failure))
		case "executing":
			if _, ok := provider.(crypto.OperationAwareRemoteKeyLifecycle); !ok {
				return managedKeyJournalResult{}, true, status.Error(codes.Aborted, "managed-key operation has an indeterminate provider outcome; configured provider cannot reconcile the durable operation id")
			}
			result, execErr := r.apply(ctx, provider, jr)
			if execErr != nil {
				// Keep the intent executing. Provider text is untrusted and never
				// persisted; an identical retry asks the operation-aware provider to
				// find/reconcile the same effect again.
				return managedKeyJournalResult{}, true, managedKeyClosedFailure(codes.Unavailable, managedKeyFailureProviderAction)
			}
			if err := r.completeOperation(&prior, result); err != nil {
				return managedKeyJournalResult{}, true, status.Errorf(codes.Internal, "persist reconciled managed-key result: %v", err)
			}
			return result, true, nil
		default:
			return managedKeyJournalResult{}, true, status.Error(codes.Aborted, "managed-key operation has an indeterminate provider outcome; reconciliation is required before a new operation id is used")
		}
	}

	op := managedKeyOperation{Version: managedKeyJournalVersion, Request: jr, Status: "executing"}
	if err := r.saveOperation(op); err != nil {
		return managedKeyJournalResult{}, false, status.Errorf(codes.Internal, "persist managed-key intent: %v", err)
	}
	result, execErr := r.apply(ctx, provider, jr)
	if execErr != nil {
		if _, ok := provider.(crypto.OperationAwareRemoteKeyLifecycle); ok {
			// The provider owns a deterministic operation identity, so an error may
			// be reconciled safely. Leave the already-durable intent in executing
			// state instead of converting an ambiguous response into a terminal fact.
			return managedKeyJournalResult{}, false, managedKeyClosedFailure(codes.Unavailable, managedKeyFailureProviderAction)
		}
		op.Status = "failed"
		// Provider errors are attacker-controlled network/device text and may echo
		// submitted credentials. Persist only this closed code; never the provider
		// string, even in a bounded/sanitized form (AN-8).
		op.Failure = managedKeyFailureProviderAction
		if saveErr := r.saveOperation(op); saveErr != nil {
			return managedKeyJournalResult{}, false, managedKeyClosedFailure(codes.Internal, managedKeyFailureJournal)
		}
		// Never automatically repeat an externally ambiguous failure. An operator
		// reconciles provider state and submits a new intent if it is safe.
		return managedKeyJournalResult{}, false, managedKeyClosedFailure(codes.Unavailable, managedKeyFailureProviderAction)
	}
	if err := r.completeOperation(&op, result); err != nil {
		return managedKeyJournalResult{}, false, status.Errorf(codes.Internal, "persist managed-key result: %v", err)
	}
	return result, false, nil
}

func (r *managedKeyRuntime) completeOperation(op *managedKeyOperation, result managedKeyJournalResult) error {
	if op == nil {
		return errors.New("managed-key operation is required")
	}
	if err := r.recordOwner(op.Request, result); err != nil {
		return fmt.Errorf("persist managed-key ownership: %w", err)
	}
	op.Status = "completed"
	op.Result = result
	return r.saveOperation(*op)
}

func validManagedKeySignPurpose(p signerpb.KeyPurpose) bool {
	switch p {
	case signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN,
		signerpb.KeyPurpose_KEY_PURPOSE_LEAF_TLS,
		signerpb.KeyPurpose_KEY_PURPOSE_SSH_CERT,
		signerpb.KeyPurpose_KEY_PURPOSE_CODE_SIGN,
		signerpb.KeyPurpose_KEY_PURPOSE_GENERIC,
		signerpb.KeyPurpose_KEY_PURPOSE_ACME_ACCOUNT:
		return true
	default:
		return false
	}
}

func validateManagedKeyRequest(req *signerpb.ManageKeyRequest) (managedKeyJournalRequest, error) {
	if req == nil {
		return managedKeyJournalRequest{}, status.Error(codes.InvalidArgument, "managed-key request is required")
	}
	provider := normalizeManagedKeyProvider(req.GetProvider())
	if req.GetTenantId() == "" || len(req.GetTenantId()) > 256 {
		return managedKeyJournalRequest{}, status.Error(codes.InvalidArgument, "managed-key tenant id is required and must be at most 256 bytes")
	}
	if provider == "" || len(provider) > 64 {
		return managedKeyJournalRequest{}, status.Error(codes.InvalidArgument, "managed-key provider is required")
	}
	if req.GetOperationId() == "" || len(req.GetOperationId()) > 256 {
		return managedKeyJournalRequest{}, status.Error(codes.InvalidArgument, "managed-key operation id is required and must be at most 256 bytes")
	}
	alg, err := algorithmFromProto(req.GetAlgorithm())
	if err != nil {
		return managedKeyJournalRequest{}, status.Error(codes.InvalidArgument, err.Error())
	}
	switch req.GetAction() {
	case signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_GENERATE:
		if req.GetKeyId() != "" {
			return managedKeyJournalRequest{}, status.Error(codes.InvalidArgument, "generate must not carry a key id")
		}
	case signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_ROTATE,
		signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_REVOKE,
		signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_ZEROIZE:
		if req.GetKeyId() == "" || len(req.GetKeyId()) > 2048 {
			return managedKeyJournalRequest{}, status.Error(codes.InvalidArgument, "managed-key action requires a bounded key id")
		}
	default:
		return managedKeyJournalRequest{}, status.Error(codes.InvalidArgument, "managed-key action is required")
	}
	return managedKeyJournalRequest{
		TenantID: req.GetTenantId(), Provider: provider, OperationID: req.GetOperationId(),
		Action: int32(req.GetAction()), KeyID: req.GetKeyId(), Algorithm: alg,
	}, nil
}

func (r *managedKeyRuntime) apply(ctx context.Context, provider crypto.RemoteKeyLifecycle, req managedKeyJournalRequest) (managedKeyJournalResult, error) {
	ref := crypto.KeyRef{ID: req.KeyID, Algorithm: req.Algorithm}
	operationProvider, operationAware := provider.(crypto.OperationAwareRemoteKeyLifecycle)
	if req.Action != int32(signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_GENERATE) {
		owner, ok := r.owners[managedKeyOwnerKey(req.Provider, req.KeyID)]
		if !ok || owner.TenantID != req.TenantID {
			return managedKeyJournalResult{}, fmt.Errorf("key ref is not owned by this tenant/provider")
		}
		if owner.Algorithm != req.Algorithm {
			return managedKeyJournalResult{}, fmt.Errorf("key ref algorithm differs from the durable ownership record")
		}
	}
	switch signerpb.ManagedKeyAction(req.Action) {
	case signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_GENERATE:
		var signer crypto.Signer
		var next crypto.KeyRef
		var err error
		if operationAware {
			signer, next, err = operationProvider.GenerateManagedKeyForOperation(ctx, req.OperationID, req.Algorithm)
		} else {
			signer, next, err = provider.GenerateManagedKey(ctx, req.Algorithm)
		}
		if err != nil {
			return managedKeyJournalResult{}, err
		}
		if err := proveManagedKeyCustody(signer); err != nil {
			cleanupErr := provider.ZeroizeKey(ctx, next)
			return managedKeyJournalResult{}, managedKeyCustodyFailure(err, cleanupErr)
		}
		return managedKeyResult(req.Provider, next, signer.Public(), "active"), nil
	case signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_ROTATE:
		var signer crypto.Signer
		var next crypto.KeyRef
		var err error
		if operationAware {
			signer, next, err = operationProvider.RotateKeyForOperation(ctx, req.OperationID, ref)
		} else {
			signer, next, err = provider.RotateKey(ctx, ref)
		}
		if err != nil {
			return managedKeyJournalResult{}, err
		}
		if err := proveManagedKeyCustody(signer); err != nil {
			cleanupErr := provider.ZeroizeKey(ctx, next)
			return managedKeyJournalResult{}, managedKeyCustodyFailure(err, cleanupErr)
		}
		return managedKeyResult(req.Provider, next, signer.Public(), "active"), nil
	case signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_REVOKE:
		var err error
		if operationAware {
			err = operationProvider.RevokeKeyForOperation(ctx, req.OperationID, ref)
		} else {
			err = provider.RevokeKey(ctx, ref)
		}
		if err != nil {
			return managedKeyJournalResult{}, err
		}
		owner := r.owners[managedKeyOwnerKey(req.Provider, req.KeyID)]
		return managedKeyJournalResult{Provider: req.Provider, KeyID: req.KeyID, Algorithm: req.Algorithm, PublicDER: bytes.Clone(owner.PublicDER), State: "revoked"}, nil
	case signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_ZEROIZE:
		var err error
		if operationAware {
			err = operationProvider.ZeroizeKeyForOperation(ctx, req.OperationID, ref)
		} else {
			err = provider.ZeroizeKey(ctx, ref)
		}
		if err != nil {
			return managedKeyJournalResult{}, err
		}
		owner := r.owners[managedKeyOwnerKey(req.Provider, req.KeyID)]
		return managedKeyJournalResult{Provider: req.Provider, KeyID: req.KeyID, Algorithm: req.Algorithm, PublicDER: bytes.Clone(owner.PublicDER), State: "zeroized"}, nil
	default:
		return managedKeyJournalResult{}, fmt.Errorf("unsupported action")
	}
}

// proveManagedKeyCustody performs a real private-key operation before a newly
// created provider handle can become active. This runs inside the isolated
// signer process. It catches a read-only/misconfigured HSM slot and proves the
// returned public key matches the provider-held private key without exporting
// private material.
func proveManagedKeyCustody(signer crypto.Signer) error {
	if signer == nil || len(signer.Public().DER) == 0 {
		return errors.New("managed-key provider returned no usable signer/public key")
	}
	opts := crypto.SignOptions{Hash: crypto.SHA256}
	signature, err := signer.Sign(managedKeyCustodyProbe, opts)
	if err != nil {
		return fmt.Errorf("managed-key custody self-test sign: %w", err)
	}
	if err := crypto.Verify(signer.Public(), managedKeyCustodyProbe, signature, opts); err != nil {
		return fmt.Errorf("managed-key custody self-test verify: %w", err)
	}
	return nil
}

func managedKeyCustodyFailure(proofErr, cleanupErr error) error {
	if cleanupErr != nil {
		return fmt.Errorf("%v; failed to destroy unusable provider key: %w", proofErr, cleanupErr)
	}
	return proofErr
}

func managedKeyResult(provider string, ref crypto.KeyRef, pub crypto.PublicKey, state string) managedKeyJournalResult {
	return managedKeyJournalResult{Provider: provider, KeyID: ref.ID, Algorithm: ref.Algorithm, PublicDER: bytes.Clone(pub.DER), State: state}
}

func managedKeyOwnerKey(provider, keyID string) string { return provider + "\x00" + keyID }

func (r *managedKeyRuntime) recordOwner(req managedKeyJournalRequest, result managedKeyJournalResult) error {
	if signerpb.ManagedKeyAction(req.Action) == signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_ROTATE {
		prior := r.owners[managedKeyOwnerKey(req.Provider, req.KeyID)]
		prior.State = "superseded"
		r.owners[managedKeyOwnerKey(req.Provider, req.KeyID)] = prior
	}
	r.owners[managedKeyOwnerKey(result.Provider, result.KeyID)] = managedKeyOwner{
		TenantID: req.TenantID, Provider: result.Provider, KeyID: result.KeyID,
		Algorithm: result.Algorithm, PublicDER: bytes.Clone(result.PublicDER), State: result.State,
	}
	return r.saveOwners()
}

func (r *managedKeyRuntime) operationPath(operationID string) (string, error) {
	digest, err := crypto.Digest(crypto.SHA256, []byte(operationID))
	if err != nil {
		return "", err
	}
	return filepath.Join(r.root, "managed-key-operations", hex.EncodeToString(digest)+".json"), nil
}

func (r *managedKeyRuntime) loadOperation(operationID string) (managedKeyOperation, bool, error) {
	if r.root == "" {
		op, ok := r.volatile[operationID]
		return op, ok, nil
	}
	path, err := r.operationPath(operationID)
	if err != nil {
		return managedKeyOperation{}, false, err
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- the signer's own keystore/journal directory from its config (CWE-22)
	if errors.Is(err, os.ErrNotExist) {
		return managedKeyOperation{}, false, nil
	}
	if err != nil {
		return managedKeyOperation{}, false, err
	}
	var op managedKeyOperation
	if err := json.Unmarshal(raw, &op); err != nil {
		return managedKeyOperation{}, false, err
	}
	return op, true, nil
}

func (r *managedKeyRuntime) saveOperation(op managedKeyOperation) error {
	if r.root == "" {
		r.volatile[op.Request.OperationID] = op
		return nil
	}
	path, err := r.operationPath(op.Request.OperationID)
	if err != nil {
		return err
	}
	return atomicJSONFile(path, op)
}

func (r *managedKeyRuntime) ownersPath() string {
	return filepath.Join(r.root, "managed-key-operations", "ownership.json")
}

func (r *managedKeyRuntime) loadOwners() error {
	if r.root == "" {
		return nil
	}
	raw, err := os.ReadFile(r.ownersPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var owners []managedKeyOwner
	if err := json.Unmarshal(raw, &owners); err != nil {
		return err
	}
	for _, owner := range owners {
		r.owners[managedKeyOwnerKey(owner.Provider, owner.KeyID)] = owner
	}
	return nil
}

func (r *managedKeyRuntime) saveOwners() error {
	if r.root == "" {
		return nil
	}
	owners := make([]managedKeyOwner, 0, len(r.owners))
	for _, owner := range r.owners {
		owner.PublicDER = bytes.Clone(owner.PublicDER)
		owners = append(owners, owner)
	}
	return atomicJSONFile(r.ownersPath(), owners)
}

func (r *managedKeyRuntime) signNoncesPath() string {
	return filepath.Join(r.root, "managed-key-operations", "sign-authorization-nonces.json")
}

func (r *managedKeyRuntime) loadSignNonces() error {
	if r.root == "" {
		return nil
	}
	raw, err := os.ReadFile(r.signNoncesPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var nonces map[string]int64
	if err := json.Unmarshal(raw, &nonces); err != nil {
		return err
	}
	for nonceDigest, expiresUnix := range nonces {
		if len(nonceDigest) != 64 || expiresUnix <= 0 {
			return fmt.Errorf("invalid managed-key sign nonce journal entry")
		}
		r.usedNonces[nonceDigest] = expiresUnix
	}
	return nil
}

func (r *managedKeyRuntime) consumeSignNonce(nonce []byte, expiresUnix int64, now time.Time) error {
	nonceDigest := crypto.SHA256Hex(nonce)
	for priorDigest, priorExpiry := range r.usedNonces {
		if priorExpiry < now.Unix() {
			delete(r.usedNonces, priorDigest)
		}
	}
	if _, exists := r.usedNonces[nonceDigest]; exists {
		return errManagedKeySignAuthorizationReplay
	}
	r.usedNonces[nonceDigest] = expiresUnix
	if r.root == "" {
		return nil
	}
	// Persist before the private provider call. A signer crash or ambiguous
	// provider failure therefore cannot make the same authorization usable again.
	return atomicJSONFile(r.signNoncesPath(), r.usedNonces)
}

func atomicJSONFile(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".managed-key-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	d, err := os.Open(dir) // #nosec G304 -- the signer's own keystore/journal directory from its config (CWE-22)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}

func closedManagedKeyFailureCode(in string) string {
	switch in {
	case managedKeyFailureProviderAction,
		managedKeyFailureProviderSign,
		managedKeyFailureProviderEmpty,
		managedKeyFailureJournal:
		return in
	default:
		// Old/corrupt journals may contain arbitrary text. Treat it as the only
		// replayable semantic fact we know: the provider action failed.
		return managedKeyFailureProviderAction
	}
}

func managedKeyClosedFailure(code codes.Code, failureCode string) error {
	return status.Error(code, "managed-key failure: "+closedManagedKeyFailureCode(failureCode))
}

func (r *managedKeyRuntime) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, provider := range r.providers {
		if destroyer, ok := provider.(interface{ Destroy() }); ok {
			destroyer.Destroy()
		}
		if closer, ok := provider.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
	r.providers = nil
}
