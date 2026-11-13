// SPDX-License-Identifier: BUSL-1.1

package gcpkms

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/managedkeystate"
)

var _ crypto.RemoteKeyLifecycle = (*Backend)(nil)
var _ crypto.OperationAwareRemoteKeyLifecycle = (*Backend)(nil)
var _ crypto.RemoteKeyDigestSigner = (*Backend)(nil)
var _ crypto.RemoteKeyDater = (*Backend)(nil)

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
	return b.managedKeyForOperation(ctx, "generate", operationID, "", alg, "")
}

// tenantLabelKey records, in the same create request, the tenant a key
// belongs to, so tenants sharing one key ring tell their keys apart in a
// reconciliation round (A168-L1, as A168-L2 did for AWS).
const tenantLabelKey = "trstctl-tenant"

// ForKeyTenant returns the backend's operation lifecycle that labels every
// key it creates with tenantID. Revoke and zeroize act on an existing key and
// are the backend's own.
func (b *Backend) ForKeyTenant(tenantID string) crypto.OperationAwareRemoteKeyLifecycle {
	return tenantKeyLifecycle{b: b, tenant: strings.TrimSpace(tenantID)}
}

type tenantKeyLifecycle struct {
	b      *Backend
	tenant string
}

func (l tenantKeyLifecycle) GenerateManagedKeyForOperation(ctx context.Context, operationID string, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	return l.b.managedKeyForOperation(ctx, "generate", operationID, "", alg, l.tenant)
}

func (l tenantKeyLifecycle) RotateKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if ref.ID == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("gcp-kms: rotate requires a key ref")
	}
	return l.b.managedKeyForOperation(ctx, "rotate", operationID, ref.ID, ref.Algorithm, l.tenant)
}

func (l tenantKeyLifecycle) RevokeKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) error {
	return l.b.RevokeKeyForOperation(ctx, operationID, ref)
}

func (l tenantKeyLifecycle) ZeroizeKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) error {
	return l.b.ZeroizeKeyForOperation(ctx, operationID, ref)
}

// gcpLabelValue reports whether v satisfies Cloud KMS's label grammar
// (lowercase letters, digits, underscores and hyphens, at most 63); a tenant
// id outside it is not recorded rather than make the create fail.
func gcpLabelValue(v string) bool {
	if v == "" || len(v) > 63 {
		return false
	}
	for _, r := range v {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// RotateKeyForOperation creates the successor under a separate deterministic
// cryptoKey resource; the predecessor remains untouched until its own retirement
// command runs.
func (b *Backend) RotateKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if ref.ID == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("gcp-kms: rotate requires a key ref")
	}
	return b.managedKeyForOperation(ctx, "rotate", operationID, ref.ID, ref.Algorithm, "")
}

func (b *Backend) managedKeyForOperation(ctx context.Context, kind, operationID, source string, alg crypto.Algorithm, tenant string) (crypto.Signer, crypto.KeyRef, error) {
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
	if gcpLabelValue(tenant) {
		create["labels"] = map[string]string{tenantLabelKey: tenant}
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
	prefix := "trstctl-g-"
	if kind == "rotate" {
		prefix = "trstctl-r-"
	}
	// Cloud KMS limits cryptoKeyId to 63 characters. This keeps 192 digest bits
	// and uses only its accepted letters, digits, and hyphens.
	return prefix + managedkeystate.OperationFingerprint(kind, operationID, source, string(alg))
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

// KeyDates reads the key version's own creation time and, once destruction is
// scheduled, the time Cloud KMS will destroy its material (destroyTime; for a
// version already destroyed, destroyEventTime) (A168-L3).
func (b *Backend) KeyDates(ctx context.Context, ref crypto.KeyRef) (crypto.KeyDates, error) {
	if strings.TrimSpace(ref.ID) == "" {
		return crypto.KeyDates{}, fmt.Errorf("gcp-kms: key dates require a key ref")
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	var resource struct {
		CreateTime       string `json:"createTime"`
		DestroyTime      string `json:"destroyTime"`
		DestroyEventTime string `json:"destroyEventTime"`
	}
	if err := b.call(ctx, http.MethodGet, ref.ID, nil, &resource); err != nil {
		return crypto.KeyDates{}, fmt.Errorf("gcp-kms: read key version dates: %w", err)
	}
	var dates crypto.KeyDates
	var err error
	if dates.Created, err = gcpTime(resource.CreateTime); err != nil {
		return crypto.KeyDates{}, err
	}
	deletion := resource.DestroyTime
	if deletion == "" {
		deletion = resource.DestroyEventTime
	}
	if dates.DeletionScheduled, err = gcpTime(deletion); err != nil {
		return crypto.KeyDates{}, err
	}
	return dates, nil
}

// gcpTime parses a Cloud KMS timestamp (RFC 3339); empty is zero.
func gcpTime(value string) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("gcp-kms: key version returned a bad timestamp")
	}
	return t.UTC(), nil
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
