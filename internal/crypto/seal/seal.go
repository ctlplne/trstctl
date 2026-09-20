// SPDX-License-Identifier: BUSL-1.1

package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"trstctl.com/trstctl/internal/crypto/secret"
)

const (
	dekSize   = 32 // AES-256 data-encryption key
	kekSize   = 32 // AES-256 key-encryption key
	nonceSize = 12 // AES-GCM standard nonce
	// version1 is the legacy deployment-KEK format. Open dispatches on the stored
	// version byte (SCHEMA-005), so its decode path remains frozen while version2
	// adds an independently routed tenant protection domain.
	version1 = 1
	// version2 adds a public, authenticated protection-domain label. The label
	// lets a migration select exactly one KEK without trial decryption or a
	// deployment-key fallback.
	version2       = 2
	domainTagSize  = sha256.Size
	maxUint16Value = int(^uint16(0))
)

// magic identifies the trstctl sealed-container family. The following byte
// selects the version-specific layout.
var magic = []byte{'C', 'S', 'L', '1'}

var domainTagContext = []byte("trstctl.seal.domain.v2")
var keyedDigestContext = []byte("trstctl.seal.keyed-digest.v1")

var (
	// ErrKeySize is returned when a local KEK is not a 256-bit key.
	ErrKeySize = errors.New("seal: KEK must be 32 bytes (AES-256)")
	// ErrFormat is returned for a malformed or truncated sealed blob.
	ErrFormat = errors.New("seal: malformed sealed blob")
	// ErrDecrypt is the single, generic failure for any unwrap/decrypt error. It
	// deliberately carries no detail and never includes the plaintext.
	ErrDecrypt = errors.New("seal: decrypt failed")
	// ErrDomain means a v2 container's authenticated protection domain is
	// missing, different from the caller's expected domain, or was tampered.
	ErrDomain = errors.New("seal: protection domain mismatch")
)

// KeyWrapper wraps and unwraps a data-encryption key (DEK). A local KEK or an
// HSM/KMS may implement it; only wrapped DEKs cross the boundary.
type KeyWrapper interface {
	WrapDEK(dek []byte) ([]byte, error)
	UnwrapDEK(wrapped []byte) ([]byte, error)
}

// LocalKEK wraps DEKs with a 256-bit key held in locked, zeroizable memory.
type LocalKEK struct {
	key *secret.Buffer
}

// NewLocalKEK copies a 32-byte key-encryption key into locked memory.
func NewLocalKEK(kek []byte) (*LocalKEK, error) {
	if len(kek) != kekSize {
		return nil, ErrKeySize
	}
	buf, err := secret.NewFrom(kek)
	if err != nil {
		return nil, err
	}
	return &LocalKEK{key: buf}, nil
}

// Destroy zeroizes and releases the KEK.
func (k *LocalKEK) Destroy() { k.key.Destroy() }

// WithKey runs fn with the raw key-encryption key bytes borrowed from locked,
// non-dumpable memory. The slice is valid ONLY for the duration of fn, which must
// not retain or copy it onto the heap. This is the single supported way to reach
// the raw KEK — for example to open a pre-binary-container legacy envelope through
// the crypto boundary — without lifting it into a heap []byte that the GC could
// duplicate (AN-8). The key is kept alive across the call so the compiler cannot
// free it early.
//
// The borrow holds the read side of the buffer lock for the whole of fn, so a
// concurrent Destroy waits rather than unmapping the region mid-read (ARCH-014).
// Two consequences for callers:
//
// On a destroyed KEK, WithKey does NOT call fn — it returns secret.ErrDestroyed.
// It used to call fn with a nil slice, which pushed the "is this key still alive?"
// check onto every caller and let a nil KEK reach a cipher constructor.
//
// fn must not call WithKey or Destroy on this same KEK: the buffer lock is a
// sync.RWMutex, which is neither reentrant nor writer-starving, so a nested borrow
// behind a queued Destroy deadlocks.
func (k *LocalKEK) WithKey(fn func(kek []byte) error) error {
	return k.key.Use(fn)
}

// KeyedDigest computes a domain-separated HMAC-SHA256 under the locked KEK
// without exposing or copying the KEK outside this crypto boundary. It is used
// for non-reversible command evidence: the result is safe to persist, while a log
// reader cannot test guesses for a low-entropy request or secret without the KEK.
func (k *LocalKEK) KeyedDigest(domain, material []byte) ([]byte, error) {
	if len(domain) == 0 {
		return nil, errors.New("seal: keyed digest requires a domain")
	}
	var digest []byte
	err := k.key.Use(func(kek []byte) error {
		mac := hmac.New(sha256.New, kek)
		_, _ = mac.Write(keyedDigestContext)
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(domain))) // #nosec G115 -- slice lengths cannot exceed uint64.
		_, _ = mac.Write(size[:])
		_, _ = mac.Write(domain)
		binary.BigEndian.PutUint64(size[:], uint64(len(material))) // #nosec G115 -- slice lengths cannot exceed uint64.
		_, _ = mac.Write(size[:])
		_, _ = mac.Write(material)
		digest = mac.Sum(nil)
		return nil
	})
	return digest, err
}

// GenerateKEK returns a fresh random 256-bit key-encryption key. The caller
// persists it securely (e.g. a 0600 file behind the crypto boundary) and wipes
// its copy once stored; key generation stays inside the boundary (AN-3).
func GenerateKEK() ([]byte, error) {
	kek := make([]byte, kekSize)
	if _, err := rand.Read(kek); err != nil {
		return nil, err
	}
	return kek, nil
}

func (k *LocalKEK) gcm() (cipher.AEAD, error) {
	var aead cipher.AEAD
	if err := k.key.Use(func(kek []byte) error {
		block, err := aes.NewCipher(kek)
		if err != nil {
			return err
		}
		g, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		aead = g
		return nil
	}); err != nil {
		return nil, err
	}
	return aead, nil
}

// WrapDEK encrypts a DEK under the KEK (AES-256-GCM): nonce || ciphertext+tag.
func (k *LocalKEK) WrapDEK(dek []byte) ([]byte, error) {
	g, err := k.gcm()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, g.Seal(nil, nonce, dek, nil)...), nil
}

// UnwrapDEK reverses WrapDEK, returning ErrDecrypt on any failure.
func (k *LocalKEK) UnwrapDEK(wrapped []byte) ([]byte, error) {
	g, err := k.gcm()
	if err != nil {
		return nil, err
	}
	if len(wrapped) < nonceSize {
		return nil, ErrFormat
	}
	dek, err := g.Open(nil, wrapped[:nonceSize], wrapped[nonceSize:], nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return dek, nil
}

// Seal envelope-encrypts plaintext: a fresh random DEK encrypts it with
// AES-256-GCM bound to aad, and the KEK wraps the DEK. The output is a
// self-describing, versioned blob safe to store at rest.
func Seal(w KeyWrapper, plaintext, aad []byte) ([]byte, error) {
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	defer secret.Wipe(dek)

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := g.Seal(nil, nonce, plaintext, aad)

	wrapped, err := w.WrapDEK(dek)
	if err != nil {
		return nil, err
	}
	if len(wrapped) == 0 || len(wrapped) > maxUint16Value {
		return nil, ErrFormat
	}

	// magic | version | wrappedLen(2) | wrapped | nonce | ciphertext
	out := make([]byte, 0, len(magic)+1+2+len(wrapped)+len(nonce)+len(ct))
	out = append(out, magic...)
	out = append(out, version1)
	out = binary.BigEndian.AppendUint16(out, uint16(len(wrapped))) // #nosec G115 -- bounded to maxUint16Value by the check above (CWE-190)
	out = append(out, wrapped...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// SealDomain envelope-encrypts plaintext into a v2 container whose public
// protection-domain label is authenticated by the fresh DEK. Domain is routing
// metadata, never key material. Callers use it to select one wrapper before
// OpenDomain verifies both the expected label and its authentication tag.
func SealDomain(w KeyWrapper, plaintext, aad, domain []byte) ([]byte, error) {
	if err := validateDomain(domain); err != nil {
		return nil, err
	}
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	defer secret.Wipe(dek)

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := g.Seal(nil, nonce, plaintext, aad)
	wrapped, err := w.WrapDEK(dek)
	if err != nil {
		return nil, err
	}
	return buildV2(domain, domainTag(dek, domain), wrapped, nonce, ct)
}

// Open reverses Seal. It reads the format magic and the version byte, then
// DISPATCHES to the reader for that version (SCHEMA-005) — rather than hard-
// rejecting anything that is not the single current version. A truly unknown
// version is still rejected with ErrFormat, but adding a future v2 layout means
// adding an openV2 branch here, and a deployed reader that already knows v2 can
// read a v2 blob written by a peer during a rolling upgrade. Any decrypt failure
// returns ErrDecrypt, which never contains the plaintext.
func Open(w KeyWrapper, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < len(magic)+1 {
		return nil, ErrFormat
	}
	if subtle.ConstantTimeCompare(sealed[:len(magic)], magic) != 1 {
		return nil, ErrFormat
	}
	ver := sealed[len(magic)]
	body := sealed[len(magic)+1:]
	switch ver {
	case version1:
		return openV1(w, body, aad)
	case version2:
		return openV2(w, body, aad, nil, false)
	default:
		// A version the reader does not understand: fail closed rather than guess a
		// layout. A newer writer's blob can only be read once this binary learns that
		// version (a new openVN branch).
		return nil, ErrFormat
	}
}

// OpenDomain opens a v2 container only when its authenticated protection domain
// exactly matches expectedDomain. It never accepts a legacy v1 container, which
// prevents a tenant-domain call site from falling back to the deployment KEK.
func OpenDomain(w KeyWrapper, sealed, aad, expectedDomain []byte) ([]byte, error) {
	if err := validateDomain(expectedDomain); err != nil {
		return nil, err
	}
	version, body, err := splitVersion(sealed)
	if err != nil {
		return nil, err
	}
	if version != version2 {
		return nil, ErrDomain
	}
	return openV2(w, body, aad, expectedDomain, true)
}

// Domain returns a copy of a v2 container's public protection-domain label. A
// v1 legacy container returns nil. The label is untrusted routing metadata until
// OpenDomain authenticates it; callers must never treat Domain alone as proof.
func Domain(sealed []byte) ([]byte, error) {
	version, body, err := splitVersion(sealed)
	if err != nil {
		return nil, err
	}
	if version == version1 {
		return nil, nil
	}
	if version != version2 {
		return nil, ErrFormat
	}
	parts, err := parseV2(body)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), parts.domain...), nil
}

// ValidateDomain authenticates a v2 container's wrapper and protection-domain
// label without decrypting its payload. Migration uses it to recognize an
// already-rewrapped container idempotently even though the row-specific payload
// AAD is intentionally unavailable at the bulk-rewrap layer.
func ValidateDomain(w KeyWrapper, sealed, expectedDomain []byte) error {
	if err := validateDomain(expectedDomain); err != nil {
		return err
	}
	version, body, err := splitVersion(sealed)
	if err != nil {
		return err
	}
	if version != version2 {
		return ErrDomain
	}
	parts, err := parseV2(body)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(parts.domain, expectedDomain) != 1 {
		return ErrDomain
	}
	dek, err := w.UnwrapDEK(parts.wrapped)
	if err != nil || len(dek) != dekSize {
		if len(dek) > 0 {
			secret.Wipe(dek)
		}
		return ErrDecrypt
	}
	defer secret.Wipe(dek)
	if subtle.ConstantTimeCompare(parts.domainTag, domainTag(dek, parts.domain)) != 1 {
		return ErrDomain
	}
	return nil
}

// RewrapDomain moves a legacy v1 or domain-aware v2 container's DEK from source
// to destination and binds it to destinationDomain. The payload nonce and
// ciphertext are copied byte for byte; plaintext is never materialized. V1 is
// unambiguously the deployment domain, while a v2 source authenticates its
// public domain before rewrapping. The unwrapped DEK is wiped before return.
func RewrapDomain(source, destination KeyWrapper, sealed, destinationDomain []byte) ([]byte, error) {
	if err := validateDomain(destinationDomain); err != nil {
		return nil, err
	}
	version, body, err := splitVersion(sealed)
	if err != nil {
		return nil, err
	}
	var parts containerParts
	switch version {
	case version1:
		parts, err = parseV1(body)
	case version2:
		parts, err = parseV2(body)
	default:
		return nil, ErrFormat
	}
	if err != nil {
		return nil, err
	}
	dek, err := source.UnwrapDEK(parts.wrapped)
	if err != nil || len(dek) != dekSize {
		if len(dek) > 0 {
			secret.Wipe(dek)
		}
		return nil, ErrDecrypt
	}
	defer secret.Wipe(dek)
	if version == version2 && subtle.ConstantTimeCompare(parts.domainTag, domainTag(dek, parts.domain)) != 1 {
		return nil, ErrDomain
	}
	wrapped, err := destination.WrapDEK(dek)
	if err != nil {
		return nil, err
	}
	return buildV2(destinationDomain, domainTag(dek, destinationDomain), wrapped, parts.nonce, parts.ciphertext)
}

// PayloadCiphertext returns a copy of nonce|ciphertext for a valid v1 or v2
// container. It exists so migration proofs can demonstrate a DEK-only rewrap
// without exposing or decrypting plaintext.
func PayloadCiphertext(sealed []byte) ([]byte, error) {
	version, body, err := splitVersion(sealed)
	if err != nil {
		return nil, err
	}
	switch version {
	case version1:
		parts, err := parseV1(body)
		if err != nil {
			return nil, err
		}
		return append(append([]byte(nil), parts.nonce...), parts.ciphertext...), nil
	case version2:
		parts, err := parseV2(body)
		if err != nil {
			return nil, err
		}
		return append(append([]byte(nil), parts.nonce...), parts.ciphertext...), nil
	default:
		return nil, ErrFormat
	}
}

// openV1 decrypts a v1 sealed body (everything after magic|version):
// wrappedLen(2) | wrapped | nonce | ciphertext. It is the layout Seal writes today.
func openV1(w KeyWrapper, body, aad []byte) ([]byte, error) {
	parts, err := parseV1(body)
	if err != nil {
		return nil, err
	}

	dek, err := w.UnwrapDEK(parts.wrapped)
	if err != nil {
		return nil, ErrDecrypt
	}
	defer secret.Wipe(dek)

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, ErrDecrypt
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecrypt
	}
	pt, err := g.Open(nil, parts.nonce, parts.ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func openV2(w KeyWrapper, body, aad, expectedDomain []byte, requireExpected bool) ([]byte, error) {
	parts, err := parseV2(body)
	if err != nil {
		return nil, err
	}
	if requireExpected && subtle.ConstantTimeCompare(parts.domain, expectedDomain) != 1 {
		return nil, ErrDomain
	}
	dek, err := w.UnwrapDEK(parts.wrapped)
	if err != nil || len(dek) != dekSize {
		if len(dek) > 0 {
			secret.Wipe(dek)
		}
		return nil, ErrDecrypt
	}
	defer secret.Wipe(dek)
	if subtle.ConstantTimeCompare(parts.domainTag, domainTag(dek, parts.domain)) != 1 {
		return nil, ErrDomain
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, ErrDecrypt
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecrypt
	}
	pt, err := g.Open(nil, parts.nonce, parts.ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

type containerParts struct {
	domain     []byte
	domainTag  []byte
	wrapped    []byte
	nonce      []byte
	ciphertext []byte
}

func splitVersion(sealed []byte) (byte, []byte, error) {
	if len(sealed) < len(magic)+1 {
		return 0, nil, ErrFormat
	}
	if subtle.ConstantTimeCompare(sealed[:len(magic)], magic) != 1 {
		return 0, nil, ErrFormat
	}
	return sealed[len(magic)], sealed[len(magic)+1:], nil
}

func parseV1(body []byte) (containerParts, error) {
	if len(body) < 2 {
		return containerParts{}, ErrFormat
	}
	off := 0
	wlen := int(binary.BigEndian.Uint16(body[off:]))
	off += 2
	if wlen == 0 || len(body) < off+wlen+nonceSize+1 {
		return containerParts{}, ErrFormat
	}
	wrapped := body[off : off+wlen]
	off += wlen
	nonce := body[off : off+nonceSize]
	off += nonceSize
	return containerParts{wrapped: wrapped, nonce: nonce, ciphertext: body[off:]}, nil
}

func parseV2(body []byte) (containerParts, error) {
	if len(body) < 2 {
		return containerParts{}, ErrFormat
	}
	off := 0
	dlen := int(binary.BigEndian.Uint16(body[off:]))
	off += 2
	if dlen == 0 || len(body) < off+dlen+domainTagSize+2 {
		return containerParts{}, ErrFormat
	}
	domain := body[off : off+dlen]
	off += dlen
	tag := body[off : off+domainTagSize]
	off += domainTagSize
	wlen := int(binary.BigEndian.Uint16(body[off:]))
	off += 2
	if wlen == 0 || len(body) < off+wlen+nonceSize+1 {
		return containerParts{}, ErrFormat
	}
	wrapped := body[off : off+wlen]
	off += wlen
	nonce := body[off : off+nonceSize]
	off += nonceSize
	return containerParts{
		domain: domain, domainTag: tag, wrapped: wrapped,
		nonce: nonce, ciphertext: body[off:],
	}, nil
}

func buildV2(domain, tag, wrapped, nonce, ciphertext []byte) ([]byte, error) {
	if err := validateDomain(domain); err != nil {
		return nil, err
	}
	if len(tag) != domainTagSize || len(wrapped) == 0 || len(wrapped) > maxUint16Value ||
		len(nonce) != nonceSize || len(ciphertext) == 0 {
		return nil, ErrFormat
	}
	out := make([]byte, 0, len(magic)+1+2+len(domain)+len(tag)+2+len(wrapped)+len(nonce)+len(ciphertext))
	out = append(out, magic...)
	out = append(out, version2)
	out = binary.BigEndian.AppendUint16(out, uint16(len(domain))) // #nosec G115 -- validateDomain above caps the length at maxUint16Value (CWE-190)
	out = append(out, domain...)
	out = append(out, tag...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(wrapped))) // #nosec G115 -- bounded to maxUint16Value by the guard above (CWE-190)
	out = append(out, wrapped...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func validateDomain(domain []byte) error {
	if len(domain) == 0 || len(domain) > maxUint16Value {
		return ErrDomain
	}
	return nil
}

func domainTag(dek, domain []byte) []byte {
	mac := hmac.New(sha256.New, dek)
	_, _ = mac.Write(domainTagContext)
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(domain)
	return mac.Sum(nil)
}
