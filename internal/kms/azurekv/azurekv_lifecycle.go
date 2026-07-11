// SPDX-License-Identifier: MPL-2.0

package azurekv

import (
	"context"
	"encoding/json"
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

// GenerateManagedKey creates an Azure Key Vault / Managed HSM signing key and
// returns the opaque provider key id. The private key never leaves Azure; only the
// public SPKI travels back through the crypto boundary.
func (b *Backend) GenerateManagedKey(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	signer, err := b.GenerateKeyContext(ctx, alg)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	ks, ok := signer.(*kvSigner)
	if !ok {
		return nil, crypto.KeyRef{}, fmt.Errorf("azure-key-vault: unexpected signer type %T", signer)
	}
	return signer, crypto.KeyRef{ID: b.vaultURL + keyPath(ks.name, ks.version), Algorithm: alg}, nil
}

// RotateKey mints a successor Azure key. The caller re-points issuance before it
// retires the superseded key, matching the other remote-custody backends.
func (b *Backend) RotateKey(ctx context.Context, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if ref.ID == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("azure-key-vault: rotate requires a key ref")
	}
	return b.GenerateManagedKey(ctx, ref.Algorithm)
}

// GenerateManagedKeyForOperation derives an Azure-safe key name from the durable
// signer command. Azure's create endpoint creates another VERSION when the same
// name is posted twice, so the GET-before-create is what turns an ambiguous first
// response into one provider key/version rather than a duplicate version.
func (b *Backend) GenerateManagedKeyForOperation(ctx context.Context, operationID string, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	return b.managedKeyForOperation(ctx, "generate", operationID, "", alg)
}

// RotateKeyForOperation gives the successor its own deterministic name. The old
// ref participates in the digest, so this command cannot resolve a different
// lifecycle action that reused the same operation id.
func (b *Backend) RotateKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if ref.ID == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("azure-key-vault: rotate requires a key ref")
	}
	return b.managedKeyForOperation(ctx, "rotate", operationID, ref.ID, ref.Algorithm)
}

func (b *Backend) managedKeyForOperation(ctx context.Context, kind, operationID, source string, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	if strings.TrimSpace(operationID) == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("azure-key-vault: durable operation id is required")
	}
	if _, err := createBody(alg); err != nil {
		return nil, crypto.KeyRef{}, err
	}
	name := azureOperationKeyName(kind, operationID, source, alg)
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	signer, ref, found, err := b.findManagedKey(ctx, name, alg)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	if found {
		return signer, ref, nil
	}
	body, err := createBody(alg)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	var created keyResponse
	if err := b.call(ctx, http.MethodPost, fmt.Sprintf("/keys/%s/create", name), body, &created); err != nil {
		// Do not POST again here. If Azure applied the request and the response
		// was lost, the next invocation's GET resolves this exact name/version.
		return nil, crypto.KeyRef{}, fmt.Errorf("azure-key-vault: create operation-owned key: %w", err)
	}
	return b.signerFromManagedResource(ctx, name, alg, created)
}

func azureOperationKeyName(kind, operationID, source string, alg crypto.Algorithm) string {
	digest := crypto.SHA256Hex([]byte(kind + "\x00" + operationID + "\x00" + source + "\x00" + string(alg)))
	// The fixed alphabet is a subset of Azure Key Vault's [A-Za-z0-9-]
	// grammar, and 48 digest characters retain 192 bits while staying short.
	return "trstctl-" + kind + "-" + digest[:48]
}

func (b *Backend) findManagedKey(ctx context.Context, name string, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, bool, error) {
	var resource keyResponse
	if err := b.call(ctx, http.MethodGet, keyPath(name, ""), nil, &resource); err != nil {
		if isAzureStatus(err, http.StatusNotFound) {
			return nil, crypto.KeyRef{}, false, nil
		}
		return nil, crypto.KeyRef{}, false, fmt.Errorf("azure-key-vault: find operation-owned key: %w", err)
	}
	signer, ref, err := b.signerFromManagedResource(ctx, name, alg, resource)
	return signer, ref, true, err
}

func (b *Backend) signerFromManagedResource(ctx context.Context, fallbackName string, alg crypto.Algorithm, resource keyResponse) (crypto.Signer, crypto.KeyRef, error) {
	name, version := keyNameAndVersion(resource.Key.Kid, fallbackName)
	pub, err := b.publicKey(ctx, name, version, alg, resource)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	signer := &kvSigner{b: b, name: name, version: version, alg: alg, pub: pub}
	return signer, crypto.KeyRef{ID: b.vaultURL + keyPath(name, version), Algorithm: alg}, nil
}

// RevokeKey disables the Azure key version so the provider refuses future signing
// operations with it.
func (b *Backend) RevokeKey(ctx context.Context, ref crypto.KeyRef) error {
	name, version, err := parseRef(ref)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"attributes": map[string]bool{"enabled": false}})
	if err != nil {
		return err
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	var out map[string]any
	if err := b.call(ctx, http.MethodPatch, keyPath(name, version), body, &out); err != nil {
		return fmt.Errorf("azure-key-vault: disable (revoke) key: %w", err)
	}
	return nil
}

// ZeroizeKey deletes the Azure key so the provider schedules destruction of the
// remotely custodied material. The provider enforces its configured recovery/purge
// policy; after this call the active key can no longer sign.
func (b *Backend) ZeroizeKey(ctx context.Context, ref crypto.KeyRef) error {
	name, _, err := parseRef(ref)
	if err != nil {
		return err
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	var out map[string]any
	if err := b.call(ctx, http.MethodDelete, keyPath(name, ""), nil, &out); err != nil {
		return fmt.Errorf("azure-key-vault: delete (zeroize) key: %w", err)
	}
	return nil
}

// RevokeKeyForOperation reads the exact Azure key version before and after the
// patch. A replay after Azure disabled the key but lost the response observes
// enabled=false and does not issue a second patch.
func (b *Backend) RevokeKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) error {
	if strings.TrimSpace(operationID) == "" {
		return fmt.Errorf("azure-key-vault: durable operation id is required")
	}
	name, version, err := parseRef(ref)
	if err != nil {
		return err
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	exists, enabled, err := b.azureKeyState(ctx, name, version)
	if err != nil {
		return err
	}
	if !exists || !enabled {
		return nil
	}
	body, err := json.Marshal(map[string]any{"attributes": map[string]bool{"enabled": false}})
	if err != nil {
		return err
	}
	var out map[string]any
	if err := b.call(ctx, http.MethodPatch, keyPath(name, version), body, &out); err != nil {
		return fmt.Errorf("azure-key-vault: disable operation-owned key: %w", err)
	}
	exists, enabled, err = b.azureKeyState(ctx, name, version)
	if err != nil {
		return err
	}
	if exists && enabled {
		return fmt.Errorf("azure-key-vault: key %q remained enabled after revoke", ref.ID)
	}
	return nil
}

// ZeroizeKeyForOperation confirms that the active key name no longer exists.
// Azure soft-delete makes GET /keys/{name} return 404 immediately; that absence is
// the provider terminal state for signing even while Azure retains recovery data.
func (b *Backend) ZeroizeKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) error {
	if strings.TrimSpace(operationID) == "" {
		return fmt.Errorf("azure-key-vault: durable operation id is required")
	}
	name, _, err := parseRef(ref)
	if err != nil {
		return err
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	exists, _, err := b.azureKeyState(ctx, name, "")
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	var out map[string]any
	if err := b.call(ctx, http.MethodDelete, keyPath(name, ""), nil, &out); err != nil {
		return fmt.Errorf("azure-key-vault: delete operation-owned key: %w", err)
	}
	exists, _, err = b.azureKeyState(ctx, name, "")
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("azure-key-vault: key %q remained active after zeroize", ref.ID)
	}
	return nil
}

func (b *Backend) azureKeyState(ctx context.Context, name, version string) (exists, enabled bool, err error) {
	var resource struct {
		Attributes struct {
			Enabled *bool `json:"enabled"`
		} `json:"attributes"`
	}
	if err := b.call(ctx, http.MethodGet, keyPath(name, version), nil, &resource); err != nil {
		if isAzureStatus(err, http.StatusNotFound) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("azure-key-vault: read key state: %w", err)
	}
	if resource.Attributes.Enabled == nil {
		return true, false, fmt.Errorf("azure-key-vault: key %q returned no enabled state", keyPath(name, version))
	}
	return true, *resource.Attributes.Enabled, nil
}

func isAzureStatus(err error, status int) bool {
	var statusErr *cloudhttp.StatusError
	return errors.As(err, &statusErr) && statusErr.StatusCode == status
}

func parseRef(ref crypto.KeyRef) (name, version string, err error) {
	if ref.ID == "" {
		return "", "", fmt.Errorf("azure-key-vault: key ref is required")
	}
	name, version = keyNameAndVersion(ref.ID, "")
	if name == "" {
		return "", "", fmt.Errorf("azure-key-vault: key ref %q does not contain a key name", ref.ID)
	}
	return name, version, nil
}

// SignManagedDigest binds the provider ref to its real Azure key version and
// performs the digest signature inside the isolated signer process.
func (b *Backend) SignManagedDigest(ctx context.Context, ref crypto.KeyRef, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	name, version, err := parseRef(ref)
	if err != nil {
		return nil, err
	}
	signer, err := b.SignerForKey(ctx, name, version)
	if err != nil {
		return nil, err
	}
	if signer.Algorithm() != ref.Algorithm {
		return nil, fmt.Errorf("azure-key-vault: provider key algorithm %q differs from ownership record %q", signer.Algorithm(), ref.Algorithm)
	}
	return signer.SignDigest(digest, opts)
}
