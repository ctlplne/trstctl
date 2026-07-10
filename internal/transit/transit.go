// SPDX-License-Identifier: MPL-2.0

// Package transit is encryption-as-a-service (S18.1, F66): applications encrypt,
// decrypt, sign, verify, HMAC, and rewrap via named keys held behind the crypto
// boundary — without ever holding the key. Keys are versioned and rotatable
// (rewrap upgrades a ciphertext to the latest version), non-exportable (no method
// returns key bytes), tenant-scoped (AN-1), and audited (AN-2). All crypto routes
// through internal/crypto (AN-3); key material is []byte and never logged (AN-8).
package transit

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Kind is a transit key type.
type Kind string

const (
	KindAEAD Kind = "aead"
	KindHMAC Kind = "hmac"
	KindSign Kind = "sign"
)

// Keyring holds a tenant's named transit keys.
type Keyring struct {
	tenantID string
	audit    auditsink.Auditor
	mu       sync.Mutex
	keys     map[string]*namedKey
}

// Service is the served, tenant-scoped transit composition. It is deliberately a
// compile-time Go interface/adaptor pattern, like crypto.Signer or a JCA provider
// selected by construction; it is not an OpenSSL ENGINE-style runtime plugin and
// it never lets policy register or select crypto providers at runtime.
type Service struct {
	mu    sync.Mutex
	audit auditsink.Auditor
	rings map[string]*Keyring
}

// KeyInfo is the key metadata returned by lifecycle operations. It never contains
// key bytes.
type KeyInfo struct {
	Name    string
	Kind    Kind
	Version int
}

type namedKey struct {
	kind   Kind
	aead   [][]byte               // version (1-based) -> 32-byte key
	hmac   [][]byte               // version -> 32-byte key
	sign   []*crypto.LockedSigner // version -> signer
	latest int
}

// New constructs a Keyring.
func New(tenantID string, audit auditsink.Auditor) *Keyring {
	if audit == nil {
		audit = auditsink.Nop{}
	}
	return &Keyring{tenantID: tenantID, audit: audit, keys: map[string]*namedKey{}}
}

// NewService constructs a tenant-scoped transit service.
func NewService(audit auditsink.Auditor) *Service {
	if audit == nil {
		audit = auditsink.Nop{}
	}
	return &Service{audit: audit, rings: map[string]*Keyring{}}
}

func (s *Service) ring(tenantID string) *Keyring {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rings == nil {
		s.rings = map[string]*Keyring{}
	}
	if k := s.rings[tenantID]; k != nil {
		return k
	}
	k := New(tenantID, s.audit)
	s.rings[tenantID] = k
	return k
}

// CreateKey creates a tenant-scoped key.
func (s *Service) CreateKey(ctx context.Context, tenantID, name string, kind Kind) (KeyInfo, error) {
	k := s.ring(tenantID)
	if err := k.CreateKey(ctx, name, kind); err != nil {
		return KeyInfo{}, err
	}
	return KeyInfo{Name: name, Kind: kind, Version: 1}, nil
}

// Rotate adds a new version to a tenant-scoped key.
func (s *Service) Rotate(ctx context.Context, tenantID, name string) (KeyInfo, error) {
	k := s.ring(tenantID)
	version, err := k.Rotate(ctx, name)
	if err != nil {
		return KeyInfo{}, err
	}
	kind, err := k.Kind(name)
	if err != nil {
		return KeyInfo{}, err
	}
	return KeyInfo{Name: name, Kind: kind, Version: version}, nil
}

func (s *Service) Encrypt(ctx context.Context, tenantID, name string, plaintext, aad []byte) (string, error) {
	return s.ring(tenantID).Encrypt(ctx, name, plaintext, aad)
}

func (s *Service) Decrypt(ctx context.Context, tenantID, name, ciphertext string, aad []byte) ([]byte, error) {
	return s.ring(tenantID).Decrypt(ctx, name, ciphertext, aad)
}

func (s *Service) Rewrap(ctx context.Context, tenantID, name, ciphertext string, aad []byte) (string, error) {
	return s.ring(tenantID).Rewrap(ctx, name, ciphertext, aad)
}

func (s *Service) HMAC(ctx context.Context, tenantID, name string, data []byte) ([]byte, error) {
	return s.ring(tenantID).HMAC(ctx, name, data)
}

func (s *Service) Sign(ctx context.Context, tenantID, name string, message []byte) ([]byte, []byte, error) {
	return s.ring(tenantID).Sign(ctx, name, message)
}

func (s *Service) Verify(ctx context.Context, tenantID string, message, sig, pubDER []byte) error {
	return s.ring(tenantID).Verify(ctx, message, sig, pubDER)
}

// Destroy zeroizes every tenant keyring.
func (s *Service) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.rings {
		k.Destroy()
	}
	s.rings = map[string]*Keyring{}
}

// CreateKey creates a named key of the given kind with an initial version.
func (k *Keyring) CreateKey(ctx context.Context, name string, kind Kind) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.keys[name]; ok {
		return fmt.Errorf("transit: key %q exists", name)
	}
	nk := &namedKey{kind: kind, latest: 1}
	switch kind {
	case KindAEAD:
		key, err := crypto.RandomBytes(32)
		if err != nil {
			return err
		}
		nk.aead = [][]byte{nil, key}
	case KindHMAC:
		key, err := crypto.RandomBytes(32)
		if err != nil {
			return err
		}
		nk.hmac = [][]byte{nil, key}
	case KindSign:
		s, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			return err
		}
		nk.sign = []*crypto.LockedSigner{nil, s}
	default:
		return fmt.Errorf("transit: unknown kind %q", kind)
	}
	k.keys[name] = nk
	k.event(ctx, "transit.key.created", name)
	return nil
}

// Kind reports a key's kind.
func (k *Keyring) Kind(name string) (Kind, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	nk, ok := k.keys[name]
	if !ok {
		return "", fmt.Errorf("transit: unknown key %q", name)
	}
	return nk.kind, nil
}

// Rotate adds a new version to a key and returns the new version number.
func (k *Keyring) Rotate(ctx context.Context, name string) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	nk, ok := k.keys[name]
	if !ok {
		return 0, fmt.Errorf("transit: unknown key %q", name)
	}
	switch nk.kind {
	case KindAEAD:
		key, err := crypto.RandomBytes(32)
		if err != nil {
			return 0, err
		}
		nk.aead = append(nk.aead, key)
	case KindHMAC:
		key, err := crypto.RandomBytes(32)
		if err != nil {
			return 0, err
		}
		nk.hmac = append(nk.hmac, key)
	case KindSign:
		s, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			return 0, err
		}
		nk.sign = append(nk.sign, s)
	}
	nk.latest++
	k.event(ctx, "transit.key.rotated", name)
	return nk.latest, nil
}

func (k *Keyring) aad(name string, extra []byte) []byte {
	return append([]byte(k.tenantID+"|"+name+"|"), extra...)
}

// Encrypt encrypts plaintext under the latest version of the named AEAD key.
func (k *Keyring) Encrypt(ctx context.Context, name string, plaintext, aad []byte) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	nk, ok := k.keys[name]
	if !ok || nk.kind != KindAEAD {
		return "", fmt.Errorf("transit: %q is not an AEAD key", name)
	}
	ct, err := crypto.AESGCMSeal(nk.aead[nk.latest], plaintext, k.aad(name, aad))
	if err != nil {
		return "", err
	}
	k.event(ctx, "transit.encrypt", name)
	return fmt.Sprintf("trv:%d:%s", nk.latest, base64.RawStdEncoding.EncodeToString(ct)), nil
}

// Decrypt decrypts a ciphertext (any version of the named key).
func (k *Keyring) Decrypt(ctx context.Context, name, ciphertext string, aad []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	nk, ok := k.keys[name]
	if !ok || nk.kind != KindAEAD {
		return nil, fmt.Errorf("transit: %q is not an AEAD key", name)
	}
	ver, ct, err := parseCT(ciphertext)
	if err != nil {
		return nil, err
	}
	if ver < 1 || ver >= len(nk.aead) {
		return nil, fmt.Errorf("transit: unknown key version %d", ver)
	}
	pt, err := crypto.AESGCMOpen(nk.aead[ver], ct, k.aad(name, aad))
	if err != nil {
		return nil, err
	}
	k.event(ctx, "transit.decrypt", name)
	return pt, nil
}

// Rewrap decrypts a ciphertext and re-encrypts it under the latest version.
func (k *Keyring) Rewrap(ctx context.Context, name, ciphertext string, aad []byte) (string, error) {
	pt, err := k.Decrypt(ctx, name, ciphertext, aad)
	if err != nil {
		return "", err
	}
	// Move the intermediate plaintext into a locked, non-dumpable buffer (AN-8)
	// for the duration of the re-encryption, then wipe the heap copy Decrypt
	// returned. This minimizes the window in which recovered plaintext lives in
	// ordinary heap memory during a rewrap (VDEC re-protection embodiment;
	// claim 5). The AEAD open itself allocates internally, so the window is
	// bounded rather than eliminated at this layer.
	buf, err := secret.NewFrom(pt)
	secret.Wipe(pt)
	if err != nil {
		return "", err
	}
	defer buf.Destroy()
	out, err := k.Encrypt(ctx, name, buf.Bytes(), aad)
	if err == nil {
		k.event(ctx, "transit.rewrap", name)
	}
	return out, err
}

// HMAC returns HMAC-SHA256 of data under the latest version of the named HMAC key.
func (k *Keyring) HMAC(ctx context.Context, name string, data []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	nk, ok := k.keys[name]
	if !ok || nk.kind != KindHMAC {
		return nil, fmt.Errorf("transit: %q is not an HMAC key", name)
	}
	mac := crypto.HMACSHA256(nk.hmac[nk.latest], data)
	k.event(ctx, "transit.hmac", name)
	return mac, nil
}

// Sign signs message under the latest version of the named signing key and returns
// the signature and the public key (for Verify).
func (k *Keyring) Sign(ctx context.Context, name string, message []byte) (sig, pubDER []byte, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	nk, ok := k.keys[name]
	if !ok || nk.kind != KindSign {
		return nil, nil, fmt.Errorf("transit: %q is not a signing key", name)
	}
	s := nk.sign[nk.latest]
	sig, err = crypto.SignMessage(s, message)
	if err != nil {
		return nil, nil, err
	}
	k.event(ctx, "transit.sign", name)
	return sig, s.Public().DER, nil
}

// Verify checks a transit signature.
func (k *Keyring) Verify(ctx context.Context, message, sig, pubDER []byte) error {
	err := crypto.VerifyMessage(pubDER, message, sig)
	if err == nil {
		k.event(ctx, "transit.verify", "signature")
	}
	return err
}

// Destroy zeroizes every key byte and destroys locked signing keys. The keyring is
// unusable afterward except to create fresh keys.
func (k *Keyring) Destroy() {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, nk := range k.keys {
		for _, b := range nk.aead {
			secret.Wipe(b)
		}
		for _, b := range nk.hmac {
			secret.Wipe(b)
		}
		for _, s := range nk.sign {
			if s != nil {
				s.Destroy()
			}
		}
	}
	k.keys = map[string]*namedKey{}
}

// CiphertextVersion reports the transit version encoded in a ciphertext.
func CiphertextVersion(ciphertext string) (int, error) {
	ver, _, err := parseCT(ciphertext)
	return ver, err
}

func (k *Keyring) event(ctx context.Context, ev, name string) {
	_ = auditsink.Emit(ctx, k.audit, nil, ev, k.tenantID, []byte(fmt.Sprintf(`{"key":%q}`, name)))
}

func parseCT(s string) (int, []byte, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 || parts[0] != "trv" {
		return 0, nil, fmt.Errorf("transit: malformed ciphertext")
	}
	ver, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, fmt.Errorf("transit: bad version")
	}
	ct, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, nil, fmt.Errorf("transit: bad ciphertext encoding")
	}
	return ver, ct, nil
}
