// SPDX-License-Identifier: MPL-2.0

package gcpkms

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto"
)

var _ crypto.RemoteKeyLifecycle = (*Backend)(nil)
var _ crypto.OperationAwareRemoteKeyLifecycle = (*Backend)(nil)
var _ crypto.RemoteKeyDigestSigner = (*Backend)(nil)

// GenerateManagedKey creates an asymmetric signing key version in Cloud KMS and
// returns the opaque cryptoKeyVersion resource name. The private key never leaves
// Cloud KMS.
func (b *Backend) GenerateManagedKey(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	signer, err := b.GenerateKeyContext(ctx, alg)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	ks, ok := signer.(*kmsSigner)
	if !ok {
		return nil, crypto.KeyRef{}, fmt.Errorf("gcp-kms: unexpected signer type %T", signer)
	}
	return signer, crypto.KeyRef{ID: ks.versionName, Algorithm: alg}, nil
}

// RotateKey mints a successor Cloud KMS signing key. The old version stays intact
// until the caller re-points issuance and explicitly revokes or zeroizes it.
func (b *Backend) RotateKey(ctx context.Context, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if ref.ID == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("gcp-kms: rotate requires a key ref")
	}
	return b.GenerateManagedKey(ctx, ref.Algorithm)
}

// GenerateManagedKeyForOperation derives a stable Cloud-KMS-safe cryptoKeyId and
// resolves that resource before creating it. Cloud KMS rejects duplicate ids, but
// the explicit GET is what lets a replay bind version 1 after a create response
// was lost without treating AlreadyExists as an opaque failure.
func (b *Backend) GenerateManagedKeyForOperation(ctx context.Context, operationID string, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	return b.managedKeyForOperation(ctx, "generate", operationID, "", alg)
}

// RotateKeyForOperation creates the successor under a separate deterministic
// cryptoKey resource; the predecessor remains untouched until its own retirement
// command runs.
func (b *Backend) RotateKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if ref.ID == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("gcp-kms: rotate requires a key ref")
	}
	return b.managedKeyForOperation(ctx, "rotate", operationID, ref.ID, ref.Algorithm)
}

func (b *Backend) managedKeyForOperation(ctx context.Context, kind, operationID, source string, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	if strings.TrimSpace(operationID) == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("gcp-kms: durable operation id is required")
	}
	gcpAlg, err := versionAlgorithm(alg)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	keyID := gcpOperationKeyID(kind, operationID, source, alg)
	cryptoKey := b.parent + "/cryptoKeys/" + keyID
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	foundName, found, err := b.findCryptoKey(ctx, cryptoKey)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	if found {
		return b.signerForManagedCryptoKey(ctx, foundName, alg)
	}
	create := map[string]any{
		"purpose":         "ASYMMETRIC_SIGN",
		"versionTemplate": map[string]string{"algorithm": gcpAlg},
	}
	var created struct {
		Name string `json:"name"`
	}
	path := b.parent + "/cryptoKeys?cryptoKeyId=" + keyID
	if err := b.call(ctx, http.MethodPost, path, create, &created); err != nil {
		// Do not retry the mutation inside this call. A process replay performs
		// GET on the deterministic resource and recovers an applied request.
		return nil, crypto.KeyRef{}, fmt.Errorf("gcp-kms: create operation-owned key: %w", err)
	}
	if created.Name != "" {
		cryptoKey = created.Name
	}
	return b.signerForManagedCryptoKey(ctx, cryptoKey, alg)
}

func gcpOperationKeyID(kind, operationID, source string, alg crypto.Algorithm) string {
	digest := crypto.SHA256Hex([]byte(kind + "\x00" + operationID + "\x00" + source + "\x00" + string(alg)))
	prefix := "trstctl-g-"
	if kind == "rotate" {
		prefix = "trstctl-r-"
	}
	// Cloud KMS limits cryptoKeyId to 63 characters. This keeps 192 digest bits
	// and uses only its accepted letters, digits, and hyphens.
	return prefix + digest[:48]
}

func (b *Backend) findCryptoKey(ctx context.Context, resourceName string) (string, bool, error) {
	var resource struct {
		Name string `json:"name"`
	}
	if err := b.call(ctx, http.MethodGet, resourceName, nil, &resource); err != nil {
		if isGCPStatus(err, http.StatusNotFound) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("gcp-kms: find operation-owned key: %w", err)
	}
	if resource.Name == "" {
		resource.Name = resourceName
	}
	return resource.Name, true, nil
}

func (b *Backend) signerForManagedCryptoKey(ctx context.Context, cryptoKey string, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	versionName := cryptoKey + "/cryptoKeyVersions/1"
	pub, err := b.publicKey(ctx, versionName, alg)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	signer := &kmsSigner{b: b, versionName: versionName, alg: alg, pub: pub}
	return signer, crypto.KeyRef{ID: versionName, Algorithm: alg}, nil
}

// RevokeKey disables the Cloud KMS key version so asymmetricSign fails closed at
// the provider.
func (b *Backend) RevokeKey(ctx context.Context, ref crypto.KeyRef) error {
	if ref.ID == "" {
		return fmt.Errorf("gcp-kms: revoke requires a key ref")
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	var out map[string]any
	if err := b.call(ctx, http.MethodPatch, ref.ID+"?updateMask=state", map[string]string{"state": "DISABLED"}, &out); err != nil {
		return fmt.Errorf("gcp-kms: disable (revoke) key version: %w", err)
	}
	return nil
}

// ZeroizeKey asks Cloud KMS to destroy the key version. Cloud KMS moves it into a
// destroy-scheduled state and then removes the material after its provider window.
func (b *Backend) ZeroizeKey(ctx context.Context, ref crypto.KeyRef) error {
	if ref.ID == "" {
		return fmt.Errorf("gcp-kms: zeroize requires a key ref")
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	var out map[string]any
	if err := b.call(ctx, http.MethodPost, ref.ID+":destroy", map[string]any{}, &out); err != nil {
		return fmt.Errorf("gcp-kms: destroy (zeroize) key version: %w", err)
	}
	return nil
}

// RevokeKeyForOperation reads the version state before and after the patch. A
// replay after a lost PATCH response sees DISABLED (or a stronger destruction
// state) and performs no second mutation.
func (b *Backend) RevokeKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) error {
	if strings.TrimSpace(operationID) == "" {
		return fmt.Errorf("gcp-kms: durable operation id is required")
	}
	if ref.ID == "" {
		return fmt.Errorf("gcp-kms: revoke requires a key ref")
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	state, exists, err := b.keyVersionState(ctx, ref.ID)
	if err != nil {
		return err
	}
	if !exists || gcpRevokedState(state) {
		return nil
	}
	var out map[string]any
	if err := b.call(ctx, http.MethodPatch, ref.ID+"?updateMask=state", map[string]string{"state": "DISABLED"}, &out); err != nil {
		return fmt.Errorf("gcp-kms: disable operation-owned key version: %w", err)
	}
	state, exists, err = b.keyVersionState(ctx, ref.ID)
	if err != nil {
		return err
	}
	if exists && !gcpRevokedState(state) {
		return fmt.Errorf("gcp-kms: key version %q state is %q after revoke, want DISABLED or destroyed", ref.ID, state)
	}
	return nil
}

// ZeroizeKeyForOperation confirms DESTROY_SCHEDULED/DESTROYED (or completed
// deletion) before returning. Response loss is safe because the replay reads the
// terminal version state before considering another :destroy call.
func (b *Backend) ZeroizeKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) error {
	if strings.TrimSpace(operationID) == "" {
		return fmt.Errorf("gcp-kms: durable operation id is required")
	}
	if ref.ID == "" {
		return fmt.Errorf("gcp-kms: zeroize requires a key ref")
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	state, exists, err := b.keyVersionState(ctx, ref.ID)
	if err != nil {
		return err
	}
	if !exists || gcpZeroizedState(state) {
		return nil
	}
	var out map[string]any
	if err := b.call(ctx, http.MethodPost, ref.ID+":destroy", map[string]any{}, &out); err != nil {
		return fmt.Errorf("gcp-kms: destroy operation-owned key version: %w", err)
	}
	state, exists, err = b.keyVersionState(ctx, ref.ID)
	if err != nil {
		return err
	}
	if exists && !gcpZeroizedState(state) {
		return fmt.Errorf("gcp-kms: key version %q state is %q after zeroize, want DESTROY_SCHEDULED or DESTROYED", ref.ID, state)
	}
	return nil
}

func (b *Backend) keyVersionState(ctx context.Context, versionName string) (state string, exists bool, err error) {
	var resource struct {
		State string `json:"state"`
	}
	if err := b.call(ctx, http.MethodGet, versionName, nil, &resource); err != nil {
		if isGCPStatus(err, http.StatusNotFound) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("gcp-kms: read key version state: %w", err)
	}
	if resource.State == "" {
		return "", true, fmt.Errorf("gcp-kms: key version %q returned no state", versionName)
	}
	return resource.State, true, nil
}

func gcpRevokedState(state string) bool {
	return state == "DISABLED" || gcpZeroizedState(state)
}

func gcpZeroizedState(state string) bool {
	return state == "DESTROY_SCHEDULED" || state == "DESTROYED"
}

func isGCPStatus(err error, status int) bool {
	var statusErr *cloudhttp.StatusError
	return errors.As(err, &statusErr) && statusErr.StatusCode == status
}

// SignManagedDigest signs an already-computed digest through asymmetricSign.
func (b *Backend) SignManagedDigest(ctx context.Context, ref crypto.KeyRef, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	if ref.ID == "" {
		return nil, fmt.Errorf("gcp-kms: sign requires a key ref")
	}
	field, err := digestField(hashOf(opts))
	if err != nil {
		return nil, err
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	var out struct {
		Signature string `json:"signature"`
	}
	in := map[string]any{"digest": map[string]string{field: base64.StdEncoding.EncodeToString(digest)}}
	if err := b.call(ctx, http.MethodPost, ref.ID+":asymmetricSign", in, &out); err != nil {
		return nil, fmt.Errorf("gcp-kms: sign managed digest: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(out.Signature)
	if err != nil || len(signature) == 0 {
		return nil, fmt.Errorf("gcp-kms: decode managed signature: %w", err)
	}
	return signature, nil
}
