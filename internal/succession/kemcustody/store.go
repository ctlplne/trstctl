// SPDX-License-Identifier: BUSL-1.1

// Package kemcustody keeps PCAS KEM private keys inside the isolated signer
// process. It has no HTTP, SQL, or NATS dependency; persistence, when enabled, is
// sealed file storage under the signer keystore directory.
package kemcustody

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pqc"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

const kemFileExt = ".kem"

var kemMagic = []byte("KEM1")

type Store struct {
	mu      sync.Mutex
	dir     string
	wrapper seal.KeyWrapper
	keys    map[string]*pqc.KEMPrivateKey
}

func NewStore(dir string, wrapper seal.KeyWrapper) (*Store, error) {
	if dir != "" && wrapper == nil {
		return nil, errors.New("kem custody: signer keystore wrapper required for persistent KEM custody")
	}
	return &Store{dir: dir, wrapper: wrapper, keys: map[string]*pqc.KEMPrivateKey{}}, nil
}

func (s *Store) GenerateSuccessorKEM(_ context.Context, handle string, protoAlg signerpb.Algorithm) (signerpb.Algorithm, []byte, error) {
	if handle == "" {
		return signerpb.Algorithm_ALGORITHM_UNSPECIFIED, nil, errors.New("kem custody: handle required")
	}
	alg, err := pqc.KEMAlgorithmFromProto(protoAlg)
	if err != nil {
		return signerpb.Algorithm_ALGORITHM_UNSPECIFIED, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.keys[handle]; ok {
		return existingKEMResult(handle, protoAlg, alg, existing)
	}
	if s.dir != "" {
		if exists, err := s.fileExists(handle); err != nil {
			return signerpb.Algorithm_ALGORITHM_UNSPECIFIED, nil, err
		} else if exists {
			existing, err := s.loadLocked(handle)
			if err != nil {
				return signerpb.Algorithm_ALGORITHM_UNSPECIFIED, nil, err
			}
			if existing == nil {
				return signerpb.Algorithm_ALGORITHM_UNSPECIFIED, nil, fmt.Errorf("kem custody: handle %q vanished during replay", handle)
			}
			s.keys[handle] = existing
			return existingKEMResult(handle, protoAlg, alg, existing)
		}
	}
	key, err := pqc.GenerateKEMKey(alg)
	if err != nil {
		return signerpb.Algorithm_ALGORITHM_UNSPECIFIED, nil, err
	}
	if s.dir != "" {
		if err := s.saveLocked(handle, protoAlg, key); err != nil {
			key.Destroy()
			return signerpb.Algorithm_ALGORITHM_UNSPECIFIED, nil, err
		}
	}
	s.keys[handle] = key
	return protoAlg, append([]byte(nil), key.Public().DER...), nil
}

func existingKEMResult(handle string, requestedProto signerpb.Algorithm, requestedAlg crypto.Algorithm, key *pqc.KEMPrivateKey) (signerpb.Algorithm, []byte, error) {
	if key.Algorithm() != requestedAlg {
		return signerpb.Algorithm_ALGORITHM_UNSPECIFIED, nil,
			fmt.Errorf("kem custody: handle %q already exists with a different algorithm", handle)
	}
	return requestedProto, append([]byte(nil), key.Public().DER...), nil
}

func (s *Store) Decapsulate(_ context.Context, handle string, ciphertext []byte) ([]byte, error) {
	if handle == "" {
		return nil, errors.New("kem custody: handle required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key, err := s.lookupLocked(handle)
	if err != nil {
		return nil, err
	}
	return key.Decapsulate(ciphertext)
}

func (s *Store) ZeroizeKey(_ context.Context, handle string) error {
	if handle == "" {
		return errors.New("kem custody: handle required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if key, ok := s.keys[handle]; ok {
		key.Destroy()
		delete(s.keys, handle)
	}
	if s.dir == "" {
		return nil
	}
	err := os.Remove(s.path(handle))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *Store) DestroyAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for handle, key := range s.keys {
		key.Destroy()
		delete(s.keys, handle)
	}
}

func (s *Store) lookupLocked(handle string) (*pqc.KEMPrivateKey, error) {
	if key, ok := s.keys[handle]; ok {
		return key, nil
	}
	if s.dir == "" {
		return nil, fmt.Errorf("kem custody: unknown handle %q", handle)
	}
	key, err := s.loadLocked(handle)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, fmt.Errorf("kem custody: unknown handle %q", handle)
	}
	s.keys[handle] = key
	return key, nil
}

func (s *Store) saveLocked(handle string, protoAlg signerpb.Algorithm, key *pqc.KEMPrivateKey) error {
	privateBytes, err := key.PrivateKeyBytes()
	if err != nil {
		return err
	}
	defer secret.Wipe(privateBytes)
	algByte, err := algorithmByte(protoAlg)
	if err != nil {
		return err
	}
	plaintext := make([]byte, 0, len(kemMagic)+1+len(privateBytes))
	plaintext = append(plaintext, kemMagic...)
	plaintext = append(plaintext, algByte)
	plaintext = append(plaintext, privateBytes...)
	defer secret.Wipe(plaintext)
	sealed, err := seal.Seal(s.wrapper, plaintext, []byte(sanitizeHandle(handle)))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	// Publish a complete, synced sealed key only after its temp file is durable.
	// Link is an atomic no-replace operation: a second signer cannot overwrite
	// the first writer's key at the same handle after a lost response.
	tmp, err := os.CreateTemp(s.dir, ".kem-tmp-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(sealed); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpPath, s.path(handle)); err != nil {
		return err
	}
	dir, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

// algorithmByte narrows a proto algorithm to the single byte used by the sealed
// KEM record header. The record format reserves exactly one byte for the
// algorithm, so any value outside 0..255 is unrepresentable and fails closed
// rather than being silently truncated into a different algorithm.
func algorithmByte(protoAlg signerpb.Algorithm) (byte, error) {
	v := int32(protoAlg)
	if v < 0 || v > math.MaxUint8 {
		return 0, fmt.Errorf("kem custody: algorithm %d is not representable in the sealed KEM record", v)
	}
	return byte(v), nil
}

func (s *Store) loadLocked(handle string) (*pqc.KEMPrivateKey, error) {
	sealed, err := os.ReadFile(s.path(handle))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	plaintext, err := seal.Open(s.wrapper, sealed, []byte(sanitizeHandle(handle)))
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(plaintext)
	if len(plaintext) <= len(kemMagic) || string(plaintext[:len(kemMagic)]) != string(kemMagic) {
		return nil, errors.New("kem custody: malformed sealed KEM key")
	}
	protoAlg := signerpb.Algorithm(plaintext[len(kemMagic)])
	alg, err := pqc.KEMAlgorithmFromProto(protoAlg)
	if err != nil {
		return nil, err
	}
	privateBytes := plaintext[len(kemMagic)+1:]
	return pqc.NewKEMPrivateKey(alg, privateBytes)
}

func (s *Store) fileExists(handle string) (bool, error) {
	_, err := os.Stat(s.path(handle))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) path(handle string) string {
	return filepath.Join(s.dir, sanitizeHandle(handle)+kemFileExt)
}

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
