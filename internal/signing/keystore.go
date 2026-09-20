// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// KeyStore persists signer keys to a directory, each sealed at rest with a KEK
// (R3.2): a key survives a signer restart, so the issuing CA is not silently
// rotated. Only sealed ciphertext is written to disk; the sealing/unsealing is
// the envelope-encryption boundary (internal/crypto/seal). The signer can use
// this without importing the store (AN-4).
type KeyStore struct {
	dir        string
	wrapper    seal.KeyWrapper
	keyFactory KeyFactory
	signMu     sync.Mutex
	signLocks  map[string]*signOperationLock

	journalDirMu     sync.Mutex
	journalParent    os.FileInfo
	journalDirectory os.FileInfo
}

type signOperationLock struct {
	mu   sync.Mutex
	refs int
}

// NewKeyStore returns a KeyStore over dir, sealing with wrapper.
func NewKeyStore(dir string, wrapper seal.KeyWrapper) *KeyStore {
	return &KeyStore{dir: dir, wrapper: wrapper, keyFactory: defaultKeyFactory{}, signLocks: make(map[string]*signOperationLock)}
}

// lockSignOperation serializes one operation ID from durable intent creation
// through completed-result rename. Therefore an existing "executing" record
// seen while holding this lock can only come from a prior signer process (or a
// failed call that returned no signature), and is safe to resume. Exact
// concurrent calls wait and replay the completed bytes instead of both signing.
func (ks *KeyStore) lockSignOperation(operationID string) func() {
	ks.signMu.Lock()
	lock := ks.signLocks[operationID]
	if lock == nil {
		lock = &signOperationLock{}
		ks.signLocks[operationID] = lock
	}
	lock.refs++
	ks.signMu.Unlock()

	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		ks.signMu.Lock()
		lock.refs--
		if lock.refs == 0 {
			delete(ks.signLocks, operationID)
		}
		ks.signMu.Unlock()
	}
}

func (ks *KeyStore) withKeyFactory(factory KeyFactory) {
	if factory != nil {
		ks.keyFactory = factory
	}
}

const keyFileExt = ".key"
const destroyedKeyFileExt = ".destroyed"

func (ks *KeyStore) path(stem string) string {
	return filepath.Join(ks.dir, stem+keyFileExt)
}

// metaMagic prefixes a sealed plaintext that carries a usage-constraint header
// (SIGNER-002/003) in front of the PKCS#8 DER. A sealed plaintext WITHOUT this
// prefix is a legacy bare-DER key written before constraints existed, and loads
// as unconstrained — so an existing keystore keeps working across the upgrade.
var metaMagic = []byte("CSKM")

// metaVersion is the current sealed-constraint header version. v1 framed only
// purposes+hashes; v2 appends a one-byte flags field (bit 0 = dual-control /
// requireAuth, RED-003); v3 appends a one-byte Algorithm enum so non-PKCS#8
// licensed key bytes can be reconstructed after restart. Older files still decode
// (requireAuth defaults false, algorithm defaults to legacy PKCS#8 inference), so
// an existing keystore keeps working across the upgrade.
const metaVersion = 3

// flagRequireAuth is bit 0 of the v2 flags byte: the key is dual-control.
const flagRequireAuth = 1 << 0

// encodeConstraintMeta frames the usage constraints into a deterministic,
// non-secret header: magic | version | nPurposes | purposes... | nHashes |
// hashes... | flags | algorithm. Enum values are bounded small (<256), so each
// fits in one byte. The trailing algorithm byte is the v3 addition.
func encodeConstraintMeta(kc keyConstraints, algorithm signerpb.Algorithm) []byte {
	purposes := kc.purposeList()
	hashes := kc.hashList()
	out := make([]byte, 0, len(metaMagic)+5+len(purposes)+len(hashes))
	out = append(out, metaMagic...)
	out = append(out, metaVersion)
	out = append(out, byte(len(purposes))) // #nosec G115 -- enum values and set sizes documented bounded <256 in the framing header (CWE-190)
	for _, p := range purposes {
		out = append(out, byte(p)) // #nosec G115 -- enum values and set sizes documented bounded <256 in the framing header (CWE-190)
	}
	out = append(out, byte(len(hashes))) // #nosec G115 -- enum values and set sizes documented bounded <256 in the framing header (CWE-190)
	for _, h := range hashes {
		out = append(out, byte(h)) // #nosec G115 -- enum values and set sizes documented bounded <256 in the framing header (CWE-190)
	}
	var flags byte
	if kc.requireAuth {
		flags |= flagRequireAuth
	}
	out = append(out, flags)
	out = append(out, byte(algorithm)) // #nosec G115 -- enum values and set sizes documented bounded <256 in the framing header (CWE-190)
	return out
}

// decodeConstraintMeta parses a framed plaintext. It returns the constraints and
// the remaining DER bytes (a sub-slice of plaintext). A plaintext without the
// magic prefix is a legacy bare-DER key: unconstrained, DER == plaintext. Every
// historical header version is accepted; v1 has no flags byte
// (requireAuth=false), and v1/v2 have no algorithm byte (legacy PKCS#8
// inference).
func decodeConstraintMeta(plaintext []byte) (keyConstraints, signerpb.Algorithm, []byte, error) {
	if len(plaintext) < len(metaMagic) || string(plaintext[:len(metaMagic)]) != string(metaMagic) {
		return keyConstraints{}, signerpb.Algorithm_ALGORITHM_UNSPECIFIED, plaintext, nil // legacy bare DER
	}
	off := len(metaMagic)
	if off >= len(plaintext) {
		return keyConstraints{}, signerpb.Algorithm_ALGORITHM_UNSPECIFIED, nil, errors.New("signing: truncated key metadata (version)")
	}
	ver := plaintext[off]
	if ver < 1 || ver > metaVersion {
		return keyConstraints{}, signerpb.Algorithm_ALGORITHM_UNSPECIFIED, nil, fmt.Errorf("signing: unsupported key metadata version %d", ver)
	}
	off++
	readList := func() ([]byte, error) {
		if off >= len(plaintext) {
			return nil, errors.New("signing: truncated key metadata (count)")
		}
		n := int(plaintext[off])
		off++
		if off+n > len(plaintext) {
			return nil, errors.New("signing: truncated key metadata (values)")
		}
		vals := plaintext[off : off+n]
		off += n
		return vals, nil
	}
	pvals, err := readList()
	if err != nil {
		return keyConstraints{}, signerpb.Algorithm_ALGORITHM_UNSPECIFIED, nil, err
	}
	hvals, err := readList()
	if err != nil {
		return keyConstraints{}, signerpb.Algorithm_ALGORITHM_UNSPECIFIED, nil, err
	}
	kc := keyConstraints{}
	if len(pvals) > 0 {
		kc.purposes = make(map[signerpb.KeyPurpose]bool, len(pvals))
		for _, v := range pvals {
			kc.purposes[signerpb.KeyPurpose(v)] = true
		}
	}
	if len(hvals) > 0 {
		kc.hashes = make(map[signerpb.Hash]bool, len(hvals))
		for _, v := range hvals {
			kc.hashes[signerpb.Hash(v)] = true
		}
	}
	// v2 appends a single flags byte before the DER; v1 has none.
	if ver >= 2 {
		if off >= len(plaintext) {
			return keyConstraints{}, signerpb.Algorithm_ALGORITHM_UNSPECIFIED, nil, errors.New("signing: truncated key metadata (flags)")
		}
		kc.requireAuth = plaintext[off]&flagRequireAuth != 0
		off++
	}
	alg := signerpb.Algorithm_ALGORITHM_UNSPECIFIED
	if ver >= 3 {
		if off >= len(plaintext) {
			return keyConstraints{}, signerpb.Algorithm_ALGORITHM_UNSPECIFIED, nil, errors.New("signing: truncated key metadata (algorithm)")
		}
		alg = signerpb.Algorithm(plaintext[off])
		off++
	}
	return kc, alg, plaintext[off:], nil
}

// Save seals the key's PKCS#8 material plus its usage-constraint header (bound to
// the handle as AAD) and writes it 0600. The unsealed key copy lives only for the
// moment of sealing, then is wiped (AN-8).
func (ks *KeyStore) Save(handle string, ls signerKey, constraints keyConstraints) error {
	staged, err := ks.stageSave(handle, ls, constraints)
	if err != nil {
		return err
	}
	return staged.commit()
}

// stagedSave is a sealed key written to a temp file, ready to be committed into
// place with a fast atomic rename. commit or discard must be called exactly once.
type stagedSave struct {
	ks        *KeyStore
	handle    string
	tmpPath   string
	finalPath string
}

// stageSave does the EXPENSIVE half of Save — extract, seal, and write the sealed
// ciphertext to a unique temp file, fsync'd — WITHOUT publishing it. A caller can
// run this outside a hot lock and hold that lock only for commit (a stat + a fast
// rename), so minting a key no longer stalls concurrent Sign RPCs behind a file
// write (AUD-201 follow-up, mint-lock contention). It deliberately does NOT check
// the destroyed tombstone: that check must be atomic with the rename to keep a
// concurrent destroy from being resurrected, so commit performs it.
func (ks *KeyStore) stageSave(handle string, ls signerKey, constraints keyConstraints) (*stagedSave, error) {
	stem := sanitizeHandle(handle)
	keyBytes, err := privateKeyBytesForSealing(ls)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(keyBytes)
	// Frame: metadata header || DER. The header is non-secret, but it shares the
	// plaintext buffer with the key, so the whole buffer is wiped after sealing.
	meta := encodeConstraintMeta(constraints, ks.keyFactory.ProtoFromAlgorithm(ls.Algorithm()))
	plaintext := make([]byte, 0, len(meta)+len(keyBytes))
	plaintext = append(plaintext, meta...)
	plaintext = append(plaintext, keyBytes...)
	defer secret.Wipe(plaintext)
	sealed, err := seal.Seal(ks.wrapper, plaintext, []byte(stem))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(ks.dir, 0o700); err != nil {
		return nil, err
	}
	finalPath := ks.path(stem)
	// A unique temp in the destination directory keeps the rename same-filesystem
	// atomic; the ".tmp-*" suffix keeps it out of Load's ".key" scan.
	tmp, err := os.CreateTemp(ks.dir, filepath.Base(finalPath)+".tmp-*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(sealed); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return nil, err
	}
	return &stagedSave{ks: ks, handle: handle, tmpPath: tmpName, finalPath: finalPath}, nil
}

// commit checks the destroyed tombstone and, if the handle is still alive,
// atomically renames the staged key into place. The check and rename are the
// caller's critical section: either the tombstone is seen here and the key is
// refused, or a concurrent destroy's own remove runs after the caller publishes.
func (st *stagedSave) commit() error {
	tmpPath, err := confinedKeystorePath(st.ks.dir, st.tmpPath)
	if err != nil {
		return fmt.Errorf("signing: staged key path: %w", err)
	}
	finalPath, err := confinedKeystorePath(st.ks.dir, st.finalPath)
	if err != nil {
		st.discard()
		return fmt.Errorf("signing: final key path: %w", err)
	}
	destroyed, err := st.ks.IsDestroyed(st.handle)
	if err != nil {
		st.discard()
		return err
	}
	if destroyed {
		st.discard()
		return errors.New("signing: destroyed key handle cannot be recreated")
	}
	if err := os.Rename(tmpPath, finalPath); err != nil { // #nosec G703 -- both absolute paths passed the explicit signer-keystore confinement check above (CWE-22)
		st.discard()
		return err
	}
	return nil
}

// discard removes the staged temp file for a key that will not be committed.
func (st *stagedSave) discard() {
	tmpPath, err := confinedKeystorePath(st.ks.dir, st.tmpPath)
	if err == nil {
		_ = os.Remove(tmpPath) // #nosec G703 -- tmpPath passed the explicit signer-keystore confinement check above (CWE-22)
	}
}

// Load reads and unseals every persisted key into a handle->heldKey map (key
// material plus restored usage constraints). A missing directory is an empty
// store (first boot), not an error.
func (ks *KeyStore) Load() (map[string]*heldKey, error) {
	out := map[string]*heldKey{}
	entries, err := os.ReadDir(ks.dir)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, keyFileExt) {
			continue
		}
		stem := strings.TrimSuffix(name, keyFileExt)
		destroyed, err := ks.IsDestroyed(stem)
		if err != nil {
			return nil, err
		}
		if destroyed {
			continue
		}
		sealed, err := os.ReadFile(filepath.Join(ks.dir, name)) // #nosec G304 -- the signer's own keystore/journal directory from its config (CWE-22)
		if err != nil {
			return nil, err
		}
		plaintext, err := seal.Open(ks.wrapper, sealed, []byte(stem))
		if err != nil {
			return nil, fmt.Errorf("signing: open sealed key %q: %w", stem, err)
		}
		constraints, alg, privateKey, err := decodeConstraintMeta(plaintext)
		if err != nil {
			secret.Wipe(plaintext)
			return nil, fmt.Errorf("signing: decode key metadata %q: %w", stem, err)
		}
		ls, err := ks.keyFactory.SigningKeyFromSealedBytes(alg, privateKey)
		secret.Wipe(plaintext)
		if err != nil {
			return nil, fmt.Errorf("signing: load key %q: %w", stem, err)
		}
		out[stem] = &heldKey{signer: ls, constraints: constraints}
	}
	return out, nil
}

// LoadHandle reads and unseals a SINGLE persisted key by handle, or returns
// (nil, nil) when no file exists for it (RESIL-002 shared-keystore HA). It exists so
// a signer can pick up a key that another replica's signer PERSISTED to a SHARED
// keystore after this signer had already started: the issuing-CA key is generated by
// whichever replica wins the first-boot provisioning lock and sealed to the shared
// store, and a follower signer that booted earlier reloads it on the next lookup
// rather than reporting the handle missing. It opens only the named handle (not the
// whole directory) so a runtime miss is a cheap, targeted read.
func (ks *KeyStore) LoadHandle(handle string) (*heldKey, error) {
	stem := sanitizeHandle(handle)
	destroyed, err := ks.IsDestroyed(handle)
	if err != nil {
		return nil, err
	}
	if destroyed {
		return nil, nil
	}
	sealed, err := os.ReadFile(ks.path(stem))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // genuinely absent from the (possibly shared) store
	}
	if err != nil {
		return nil, err
	}
	plaintext, err := seal.Open(ks.wrapper, sealed, []byte(stem))
	if err != nil {
		return nil, fmt.Errorf("signing: open sealed key %q: %w", stem, err)
	}
	constraints, alg, privateKey, err := decodeConstraintMeta(plaintext)
	if err != nil {
		secret.Wipe(plaintext)
		return nil, fmt.Errorf("signing: decode key metadata %q: %w", stem, err)
	}
	ls, err := ks.keyFactory.SigningKeyFromSealedBytes(alg, privateKey)
	secret.Wipe(plaintext)
	if err != nil {
		return nil, fmt.Errorf("signing: load key %q: %w", stem, err)
	}
	return &heldKey{signer: ls, constraints: constraints}, nil
}

// Remove deletes a persisted key. A missing file is not an error.
func (ks *KeyStore) Remove(handle string) error {
	err := os.Remove(ks.path(sanitizeHandle(handle)))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// MarkDestroyed durably prevents a signer replica from loading or continuing
// to use a shared persisted handle. The marker is public state but lives in the
// signer-owned 0700 keystore and is fsynced before local key zeroization.
func (ks *KeyStore) MarkDestroyed(handle string) error {
	stem := sanitizeHandle(handle)
	if err := os.MkdirAll(ks.dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(ks.dir, stem+destroyedKeyFileExt)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path joins a sanitized handle to the signer-owned 0700 keystore (CWE-22).
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := file.Write([]byte("trstctl-destroyed-key-v1\n")); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return syncDirectory(ks.dir)
}

func (ks *KeyStore) IsDestroyed(handle string) (bool, error) {
	path, err := confinedKeystorePath(ks.dir, filepath.Join(ks.dir, sanitizeHandle(handle)+destroyedKeyFileExt))
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path) // #nosec G703 -- path passed the explicit signer-keystore confinement check above (CWE-22)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// confinedKeystorePath returns candidate as an absolute path only when it is a
// child of the configured signer keystore. It is a second boundary behind handle
// sanitization: even a corrupted stagedSave cannot rename or remove a file outside
// the signer's private directory.
func confinedKeystorePath(root, candidate string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("absolute keystore path: %w", err)
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("absolute candidate path: %w", err)
	}
	rel, err := filepath.Rel(rootAbs, candidateAbs)
	if err != nil {
		return "", fmt.Errorf("relative keystore path: %w", err)
	}
	if rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes keystore", candidate)
	}
	return candidateAbs, nil
}

// sanitizeHandle restricts a handle to a safe filename charset. Real handles are
// hex ids or fixed names like "issuing-ca", so this is identity for them.
func sanitizeHandle(h string) string {
	var b strings.Builder
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
