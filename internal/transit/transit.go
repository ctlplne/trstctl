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
		key, _ := crypto.RandomBytes(32)
		nk.aead = [][]byte{nil, key}
	case KindHMAC:
		key, _ := crypto.RandomBytes(32)
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
		key, _ := crypto.RandomBytes(32)
		nk.aead = append(nk.aead, key)
	case KindHMAC:
		key, _ := crypto.RandomBytes(32)
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
func (k *Keyring) Decrypt(_ context.Context, name, ciphertext string, aad []byte) ([]byte, error) {
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
	return crypto.AESGCMOpen(nk.aead[ver], ct, k.aad(name, aad))
}

// Rewrap decrypts a ciphertext and re-encrypts it under the latest version.
func (k *Keyring) Rewrap(ctx context.Context, name, ciphertext string, aad []byte) (string, error) {
	pt, err := k.Decrypt(ctx, name, ciphertext, aad)
	if err != nil {
		return "", err
	}
	out, err := k.Encrypt(ctx, name, pt, aad)
	for i := range pt {
		pt[i] = 0
	}
	return out, err
}

// HMAC returns HMAC-SHA256 of data under the latest version of the named HMAC key.
func (k *Keyring) HMAC(_ context.Context, name string, data []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	nk, ok := k.keys[name]
	if !ok || nk.kind != KindHMAC {
		return nil, fmt.Errorf("transit: %q is not an HMAC key", name)
	}
	return crypto.HMACSHA256(nk.hmac[nk.latest], data), nil
}

// Sign signs message under the latest version of the named signing key and returns
// the signature and the public key (for Verify).
func (k *Keyring) Sign(_ context.Context, name string, message []byte) (sig, pubDER []byte, err error) {
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
	return sig, s.Public().DER, nil
}

// Verify checks a transit signature.
func (k *Keyring) Verify(_ context.Context, message, sig, pubDER []byte) error {
	return crypto.VerifyMessage(pubDER, message, sig)
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
