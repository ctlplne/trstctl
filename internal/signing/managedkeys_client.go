// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

const managedKeySignAuthorizationTTL = 30 * time.Second

// ManagedKeyAction names the public lifecycle command sent to the isolated
// signer. It contains no credential or private-key material.
type ManagedKeyAction string

const (
	ManagedKeyGenerate ManagedKeyAction = "generate"
	ManagedKeyRotate   ManagedKeyAction = "rotate"
	ManagedKeyRevoke   ManagedKeyAction = "revoke"
	ManagedKeyZeroize  ManagedKeyAction = "zeroize"
)

// ManagedKeyCommand is the durable outbox command contract used by the control
// plane. OperationID must be stable across retries.
type ManagedKeyCommand struct {
	TenantID    string
	Provider    string
	OperationID string
	Action      ManagedKeyAction
	KeyID       string
	Algorithm   crypto.Algorithm
}

// ManagedKeySigner is a crypto.DigestSigner whose private operation is routed
// to a tenant-bound provider ref inside the isolated signer.
type ManagedKeySigner struct {
	client     *Client
	tenantID   string
	provider   string
	keyID      string
	algorithm  crypto.Algorithm
	public     crypto.PublicKey
	purpose    KeyPurpose
	authorizer SignTokenProvider
}

var _ crypto.DigestSigner = (*ManagedKeySigner)(nil)

// SignerForManagedKey binds public provider metadata to the isolated signer
// transport. publicDER normally comes from the configured CA certificate or a
// prior managed-key lifecycle result; no provider credential is accepted here.
func (c *Client) SignerForManagedKey(tenantID, provider, keyID string, algorithm crypto.Algorithm, publicDER []byte, purpose KeyPurpose, authorizer SignTokenProvider) (*ManagedKeySigner, error) {
	if c == nil || tenantID == "" || provider == "" || keyID == "" || algorithm == "" || len(publicDER) == 0 || purpose == PurposeUnspecified || authorizer == nil {
		return nil, fmt.Errorf("signing: complete managed-key tenant/provider/ref/algorithm/public/purpose/authorizer metadata is required")
	}
	return &ManagedKeySigner{
		client: c, tenantID: tenantID, provider: provider, keyID: keyID,
		algorithm: algorithm, public: crypto.PublicKey{Algorithm: algorithm, DER: bytes.Clone(publicDER)},
		purpose: purpose, authorizer: authorizer,
	}, nil
}

func (s *ManagedKeySigner) Public() crypto.PublicKey { return s.public }

func (s *ManagedKeySigner) Algorithm() crypto.Algorithm { return s.algorithm }

func (s *ManagedKeySigner) SignDigest(digest []byte, opts crypto.SignOptions) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	nonce, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("signing: managed-key authorization nonce: %w", err)
	}
	expiresUnix := time.Now().Add(managedKeySignAuthorizationTTL).Unix()
	intent, err := ManagedKeySignAuthorizationIntent(s.tenantID, s.provider, s.keyID, s.algorithm, s.purpose, expiresUnix, nonce, digest, opts)
	if err != nil {
		return nil, err
	}
	token, err := s.authorizer.Authorize(intent)
	if err != nil {
		return nil, fmt.Errorf("signing: authorize managed-key private operation: %w", err)
	}
	defer secret.Wipe(token)
	request := &signerpb.SignManagedKeyRequest{
		TenantId: s.tenantID, Provider: s.provider, KeyId: s.keyID,
		Algorithm: algorithmToProto(s.algorithm), Digest: bytes.Clone(digest),
		Hash: hashToProto(opts.Hash), RsaPadding: paddingToProto(opts.RSAPadding),
		Purpose: s.purpose, AuthorizationExpiresUnix: expiresUnix,
		AuthorizationNonce: bytes.Clone(nonce), AuthorizationToken: bytes.Clone(token),
	}
	// gRPC marshals but does not wipe the caller-owned protobuf. Destroy the
	// request clone as soon as the call returns; wiping only token above would
	// leave this second authorization capability live in the control-plane heap.
	defer secret.Wipe(request.AuthorizationToken)
	response, err := s.client.svc.SignManagedKey(ctx, request)
	if err != nil {
		return nil, err
	}
	if len(response.GetSignature()) == 0 {
		return nil, fmt.Errorf("signing: isolated managed-key signer returned an empty signature")
	}
	return bytes.Clone(response.GetSignature()), nil
}

// ManagedKeySignAuthorizationIntent is the single canonical authorization tuple
// used by both the independent token authority and the isolated signer. The
// opaque SignIntent key handle carries base64url-encoded public metadata so an
// external authority can inspect tenant/provider/ref/purpose/expiry/nonce policy;
// the HMAC additionally binds the exact digest, hash, and padding.
func ManagedKeySignAuthorizationIntent(tenantID, provider, keyID string, algorithm crypto.Algorithm, purpose KeyPurpose, expiresUnix int64, nonce, digest []byte, opts crypto.SignOptions) (crypto.SignIntent, error) {
	provider = normalizeManagedKeyProvider(provider)
	if tenantID == "" || provider == "" || keyID == "" || algorithm == "" || purpose == PurposeUnspecified || expiresUnix <= 0 || len(nonce) < 16 || len(nonce) > 64 || len(digest) == 0 {
		return crypto.SignIntent{}, fmt.Errorf("signing: incomplete managed-key sign authorization tuple")
	}
	metadata, err := json.Marshal(struct {
		Version     int              `json:"version"`
		TenantID    string           `json:"tenant_id"`
		Provider    string           `json:"provider"`
		KeyID       string           `json:"key_id"`
		Algorithm   crypto.Algorithm `json:"algorithm"`
		Purpose     int32            `json:"purpose"`
		ExpiresUnix int64            `json:"expires_unix"`
		Nonce       []byte           `json:"nonce"`
	}{
		Version: 1, TenantID: tenantID, Provider: provider, KeyID: keyID,
		Algorithm: algorithm, Purpose: int32(purpose), ExpiresUnix: expiresUnix,
		Nonce: bytes.Clone(nonce),
	})
	if err != nil {
		return crypto.SignIntent{}, fmt.Errorf("signing: encode managed-key authorization tuple: %w", err)
	}
	return crypto.SignIntent{
		KeyHandle: "managed-key-sign-v1:" + base64.RawURLEncoding.EncodeToString(metadata),
		Purpose:   int32(purpose), Hash: opts.Hash, Padding: opts.RSAPadding,
		Digest: bytes.Clone(digest),
	}, nil
}

// ManagedKeyResult is public provider metadata returned by the signer.
type ManagedKeyResult struct {
	Provider  string
	KeyID     string
	Algorithm crypto.Algorithm
	PublicDER []byte
	State     string
	Replayed  bool
}

// ManageKey drives one provider lifecycle command over the authenticated
// signer transport. The provider action itself runs only in trstctl-signer.
func (c *Client) ManageKey(ctx context.Context, command ManagedKeyCommand) (ManagedKeyResult, error) {
	action, err := managedKeyActionToProto(command.Action)
	if err != nil {
		return ManagedKeyResult{}, err
	}
	resp, err := c.svc.ManageKey(ctx, &signerpb.ManageKeyRequest{
		TenantId: command.TenantID, Provider: command.Provider,
		OperationId: command.OperationID, Action: action, KeyId: command.KeyID,
		Algorithm: algorithmToProto(command.Algorithm),
	})
	if err != nil {
		return ManagedKeyResult{}, err
	}
	alg, err := algorithmFromProto(resp.GetAlgorithm())
	if err != nil {
		return ManagedKeyResult{}, err
	}
	return ManagedKeyResult{
		Provider: resp.GetProvider(), KeyID: resp.GetKeyId(), Algorithm: alg,
		PublicDER: bytes.Clone(resp.GetPublicKey()), State: resp.GetState(), Replayed: resp.GetReplayed(),
	}, nil
}

func managedKeyActionToProto(action ManagedKeyAction) (signerpb.ManagedKeyAction, error) {
	switch action {
	case ManagedKeyGenerate:
		return signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_GENERATE, nil
	case ManagedKeyRotate:
		return signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_ROTATE, nil
	case ManagedKeyRevoke:
		return signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_REVOKE, nil
	case ManagedKeyZeroize:
		return signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_ZEROIZE, nil
	default:
		return signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_UNSPECIFIED, fmt.Errorf("signing: unsupported managed-key action %q", action)
	}
}
