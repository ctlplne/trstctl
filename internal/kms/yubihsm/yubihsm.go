// SPDX-License-Identifier: BUSL-1.1

// Package yubihsm is the YubiHSM 2 key-management backend (S9.7), built from the S9.1
// backend template behind the AN-3 crypto boundary. GenerateKey asks the device to create
// an asymmetric signing key and returns a crypto.Signer that signs via the device — the
// private key never leaves the YubiHSM. Digests route through internal/crypto (no crypto/*),
// so the backend stays inside the AN-3 boundary.
//
// Production opens Yubico's yubihsm_pkcs11 module through the shipped cgo HSM
// signer. The Connector seam keeps the backend independent of that vendor ABI;
// fast tests use a software double and the launched-binary DoD proof exercises the
// same PKCS#11 object/sign/destroy contract against a vendor-ABI emulator.
package yubihsm

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// Connector is the device-access seam. Production wraps the vendor PKCS#11 module;
// tests inject a software-backed double.
// Handles are opaque, connector-assigned identifiers (e.g. an object ID) for a key whose
// private material lives on the device. The seam carries no crypto/* types, keeping the
// binding swappable and the boundary intact (AN-3).
type Connector interface {
	// GenerateKey creates an asymmetric signing key on the device for alg and returns an
	// opaque handle plus the public key as DER (PKIX/SubjectPublicKeyInfo).
	GenerateKey(alg crypto.Algorithm) (handle string, publicDER []byte, err error)
	// SignDigest signs a pre-computed digest with the on-device key named by handle and
	// returns the raw signature.
	SignDigest(handle string, digest []byte, opts crypto.SignOptions) (sig []byte, err error)
	// Close releases the device session.
	Close() error
}

// LifecycleConnector is implemented by the vendor PKCS#11 binding so a served
// managed-key can be disabled and destroyed on the YubiHSM 2.
type LifecycleConnector interface {
	RevokeKey(handle string) error
	ZeroizeKey(handle string) error
}

// OperationLifecycleConnector binds find-or-create and terminal-state readback
// to the signer's durable operation ID. The production connector forwards this
// to deterministic PKCS#11 CKA_ID operations on the YubiHSM token.
type OperationLifecycleConnector interface {
	GenerateKeyForOperation(operationID string, alg crypto.Algorithm) (handle string, publicDER []byte, err error)
	RevokeKeyForOperation(operationID, handle string) error
	ZeroizeKeyForOperation(operationID, handle string) error
}

// Backend is a YubiHSM 2 crypto.Backend. It owns a Connector to a device session; key
// material never leaves the device.
type Backend struct {
	conn Connector
}

var (
	_ crypto.Backend                          = (*Backend)(nil)
	_ crypto.RemoteKeyLifecycle               = (*Backend)(nil)
	_ crypto.OperationAwareRemoteKeyLifecycle = (*Backend)(nil)
	_ crypto.RemoteKeyDigestSigner            = (*Backend)(nil)
)

// Option configures a Backend. It exists so future device options (auth key, domain,
// capability set) can be added without changing New's signature.
type Option func(*Backend)

// New returns a YubiHSM backend over conn.
func New(conn Connector, opts ...Option) *Backend {
	b := &Backend{conn: conn}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Name identifies the backend.
func (b *Backend) Name() string { return "yubihsm2" }

// GenerateKey creates an on-device asymmetric signing key and returns a Signer for it.
func (b *Backend) GenerateKey(alg crypto.Algorithm) (crypto.Signer, error) {
	if b.conn == nil {
		return nil, fmt.Errorf("yubihsm: no connector configured")
	}
	handle, publicDER, err := b.conn.GenerateKey(alg)
	if err != nil {
		return nil, fmt.Errorf("yubihsm: generate key: %w", err)
	}
	if len(publicDER) == 0 {
		return nil, fmt.Errorf("yubihsm: device returned an empty public key for %s", alg)
	}
	pub := crypto.PublicKey{Algorithm: alg, DER: publicDER}
	return &hsmSigner{conn: b.conn, handle: handle, alg: alg, pub: pub}, nil
}

// hsmSigner signs a digest via the device; the key never leaves the YubiHSM.
type hsmSigner struct {
	conn   Connector
	handle string
	alg    crypto.Algorithm
	pub    crypto.PublicKey
}

func (s *hsmSigner) Public() crypto.PublicKey    { return s.pub }
func (s *hsmSigner) Algorithm() crypto.Algorithm { return s.alg }

// Sign hashes message through the crypto boundary (AN-3) and signs the resulting digest on
// the device.
func (s *hsmSigner) Sign(message []byte, opts crypto.SignOptions) ([]byte, error) {
	digest, err := crypto.Digest(hashOf(opts), message)
	if err != nil {
		return nil, err
	}
	sig, err := s.conn.SignDigest(s.handle, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("yubihsm: sign: %w", err)
	}
	return sig, nil
}

func (b *Backend) GenerateManagedKey(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, crypto.KeyRef{}, err
	}
	signer, err := b.GenerateKey(alg)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	hs, ok := signer.(*hsmSigner)
	if !ok {
		return nil, crypto.KeyRef{}, fmt.Errorf("yubihsm2: unexpected signer type %T", signer)
	}
	return signer, crypto.KeyRef{ID: hs.handle, Algorithm: alg}, nil
}

func (b *Backend) GenerateManagedKeyForOperation(ctx context.Context, operationID string, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	if err := validateOperation(ctx, operationID); err != nil {
		return nil, crypto.KeyRef{}, err
	}
	connector, ok := b.conn.(OperationLifecycleConnector)
	if !ok {
		return nil, crypto.KeyRef{}, fmt.Errorf("yubihsm2: connector does not support durable operation reconciliation")
	}
	handle, publicDER, err := connector.GenerateKeyForOperation(operationID, alg)
	if err != nil {
		return nil, crypto.KeyRef{}, fmt.Errorf("yubihsm2: reconcile managed-key generation: %w", err)
	}
	if handle == "" || len(publicDER) == 0 {
		return nil, crypto.KeyRef{}, fmt.Errorf("yubihsm2: device returned an incomplete managed key")
	}
	signer := &hsmSigner{conn: b.conn, handle: handle, alg: alg, pub: crypto.PublicKey{Algorithm: alg, DER: publicDER}}
	return signer, crypto.KeyRef{ID: handle, Algorithm: alg}, nil
}

func (b *Backend) RotateKey(ctx context.Context, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if ref.ID == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("yubihsm2: rotate requires a key ref")
	}
	return b.GenerateManagedKey(ctx, ref.Algorithm)
}

func (b *Backend) RotateKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if ref.ID == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("yubihsm2: rotate requires a key ref")
	}
	return b.GenerateManagedKeyForOperation(ctx, operationID, ref.Algorithm)
}

func (b *Backend) RevokeKey(ctx context.Context, ref crypto.KeyRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ref.ID == "" {
		return fmt.Errorf("yubihsm2: revoke requires a key ref")
	}
	lifecycle, ok := b.conn.(LifecycleConnector)
	if !ok {
		return fmt.Errorf("yubihsm2: connector does not support object lifecycle")
	}
	return lifecycle.RevokeKey(ref.ID)
}

func (b *Backend) RevokeKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) error {
	if err := validateOperation(ctx, operationID); err != nil {
		return err
	}
	if ref.ID == "" {
		return fmt.Errorf("yubihsm2: revoke requires a key ref")
	}
	connector, ok := b.conn.(OperationLifecycleConnector)
	if !ok {
		return fmt.Errorf("yubihsm2: connector does not support durable operation reconciliation")
	}
	return connector.RevokeKeyForOperation(operationID, ref.ID)
}

func (b *Backend) ZeroizeKey(ctx context.Context, ref crypto.KeyRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ref.ID == "" {
		return fmt.Errorf("yubihsm2: zeroize requires a key ref")
	}
	lifecycle, ok := b.conn.(LifecycleConnector)
	if !ok {
		return fmt.Errorf("yubihsm2: connector does not support object lifecycle")
	}
	return lifecycle.ZeroizeKey(ref.ID)
}

func (b *Backend) ZeroizeKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) error {
	if err := validateOperation(ctx, operationID); err != nil {
		return err
	}
	if ref.ID == "" {
		return fmt.Errorf("yubihsm2: zeroize requires a key ref")
	}
	connector, ok := b.conn.(OperationLifecycleConnector)
	if !ok {
		return fmt.Errorf("yubihsm2: connector does not support durable operation reconciliation")
	}
	return connector.ZeroizeKeyForOperation(operationID, ref.ID)
}

func validateOperation(ctx context.Context, operationID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if operationID == "" || len(operationID) > 256 {
		return fmt.Errorf("yubihsm2: durable operation id is required and must be at most 256 bytes")
	}
	return nil
}

func (b *Backend) SignManagedDigest(ctx context.Context, ref crypto.KeyRef, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ref.ID == "" {
		return nil, fmt.Errorf("yubihsm2: sign requires a key ref")
	}
	return b.conn.SignDigest(ref.ID, digest, opts)
}

// hashOf defaults an empty hash to SHA-256, matching the software backend.
func hashOf(opts crypto.SignOptions) crypto.Hash {
	if opts.Hash == "" {
		return crypto.SHA256
	}
	return opts.Hash
}
