package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"trstctl.com/trstctl/internal/crypto/secret"
)

const (
	dekSize   = 32 // AES-256 data-encryption key
	kekSize   = 32 // AES-256 key-encryption key
	nonceSize = 12 // AES-GCM standard nonce
	// version1 is the only sealed-container format version written today. Open
	// dispatches on the stored version byte (SCHEMA-005), so a future version2 is a
	// new openV2 branch + a writer behind a feature flag, not an edit to the v1
	// decode path.
	version1 = 1
)

// magic identifies the sealed-container format (trstctl seal, v1).
var magic = []byte{'C', 'S', 'L', '1'}

var (
	// ErrKeySize is returned when a local KEK is not a 256-bit key.
	ErrKeySize = errors.New("seal: KEK must be 32 bytes (AES-256)")
	// ErrFormat is returned for a malformed or truncated sealed blob.
	ErrFormat = errors.New("seal: malformed sealed blob")
	// ErrDecrypt is the single, generic failure for any unwrap/decrypt error. It
	// deliberately carries no detail and never includes the plaintext.
	ErrDecrypt = errors.New("seal: decrypt failed")
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
	block, err := aes.NewCipher(k.key.Bytes())
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
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

	// magic | version | wrappedLen(2) | wrapped | nonce | ciphertext
	out := make([]byte, 0, len(magic)+1+2+len(wrapped)+len(nonce)+len(ct))
	out = append(out, magic...)
	out = append(out, version1)
	out = binary.BigEndian.AppendUint16(out, uint16(len(wrapped)))
	out = append(out, wrapped...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
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
	default:
		// A version the reader does not understand: fail closed rather than guess a
		// layout. A newer writer's blob can only be read once this binary learns that
		// version (a new openVN branch).
		return nil, ErrFormat
	}
}

// openV1 decrypts a v1 sealed body (everything after magic|version):
// wrappedLen(2) | wrapped | nonce | ciphertext. It is the layout Seal writes today.
func openV1(w KeyWrapper, body, aad []byte) ([]byte, error) {
	if len(body) < 2 {
		return nil, ErrFormat
	}
	off := 0
	wlen := int(binary.BigEndian.Uint16(body[off:]))
	off += 2
	if len(body) < off+wlen+nonceSize {
		return nil, ErrFormat
	}
	wrapped := body[off : off+wlen]
	off += wlen
	nonce := body[off : off+nonceSize]
	off += nonceSize
	ct := body[off:]

	dek, err := w.UnwrapDEK(wrapped)
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
	pt, err := g.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
