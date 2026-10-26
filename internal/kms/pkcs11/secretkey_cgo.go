// SPDX-License-Identifier: BUSL-1.1

//go:build cgo

package pkcs11

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	p11 "github.com/miekg/pkcs11"

	"trstctl.com/trstctl/internal/crypto"
)

const (
	gcmIVSize      = 12
	gcmTagBits     = 128
	aesKeyBytes    = 32
	maxKeyLabel    = 128
	maxSealedValue = 4 << 10
	// ckrAEADDecryptFailed is PKCS#11 3.0's answer for an AEAD tag that does
	// not verify; 2.40 modules answer CKR_ENCRYPTED_DATA_INVALID instead.
	ckrAEADDecryptFailed = 0x00000035
)

// SealWithKey encrypts plaintext with AES-256-GCM under the token key labeled
// label, binding aad, and returns iv || ciphertext || tag.
func (s *moduleSession) SealWithKey(label string, plaintext, aad []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext) > maxSealedValue {
		return nil, fmt.Errorf("pkcs11: a sealed value must be 1 to %d bytes", maxSealedValue)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key, err := s.secretKeyLocked(label)
	if err != nil {
		return nil, err
	}
	return s.sealLocked(key, plaintext, aad)
}

// OpenWithKey reverses SealWithKey. A value that does not authenticate under
// the key and aad is ErrSealedValueInvalid; any other failure is the token's.
// The binding returns the plaintext through a C buffer it frees without
// zeroing; the caller copies it into locked memory and wipes this copy.
func (s *moduleSession) OpenWithKey(label string, sealed, aad []byte) ([]byte, error) {
	overhead := gcmIVSize + gcmTagBits/8
	if len(sealed) <= overhead || len(sealed) > maxSealedValue+overhead {
		return nil, ErrSealedValueInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key, err := s.secretKeyLocked(label)
	if err != nil {
		return nil, err
	}
	plain, err := s.openLocked(key, sealed, aad)
	if err == nil {
		return plain, nil
	}
	// Modules disagree on how to report a tag that does not verify: 3.0
	// modules say so, 2.40 modules mostly say the encrypted data is invalid,
	// and SoftHSM says CKR_GENERAL_ERROR. For an unspecific answer, a fresh
	// probe sealed and opened under the same key tells a healthy token (the
	// value did not authenticate) from a failing one.
	if isPKCS11Error(err, p11.CKR_ENCRYPTED_DATA_INVALID) ||
		isPKCS11Error(err, p11.CKR_ENCRYPTED_DATA_LEN_RANGE) ||
		isPKCS11Error(err, ckrAEADDecryptFailed) ||
		s.keyRoundTripsLocked(key) {
		return nil, ErrSealedValueInvalid
	}
	return nil, fmt.Errorf("pkcs11: AES-GCM decrypt: %w", err)
}

// sealLocked draws a random IV; a module that chooses its own writes it back,
// and that one is kept.
func (s *moduleSession) sealLocked(key p11.ObjectHandle, plaintext, aad []byte) ([]byte, error) {
	iv, err := crypto.RandomBytes(gcmIVSize)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: generate an AES-GCM IV: %w", err)
	}
	params := p11.NewGCMParams(iv, aad, gcmTagBits)
	defer params.Free()
	if err := s.ctx.EncryptInit(s.session, []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_GCM, params)}, key); err != nil {
		return nil, fmt.Errorf("pkcs11: AES-GCM encrypt init: %w", err)
	}
	sealed, err := s.ctx.Encrypt(s.session, plaintext)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: AES-GCM encrypt: %w", err)
	}
	if used := params.IV(); len(used) == gcmIVSize {
		iv = used
	}
	if len(sealed) != len(plaintext)+gcmTagBits/8 {
		return nil, fmt.Errorf("pkcs11: the token returned %d bytes of AES-GCM output for %d bytes", len(sealed), len(plaintext))
	}
	return append(iv, sealed...), nil
}

func (s *moduleSession) openLocked(key p11.ObjectHandle, sealed, aad []byte) ([]byte, error) {
	params := p11.NewGCMParams(append([]byte(nil), sealed[:gcmIVSize]...), aad, gcmTagBits)
	defer params.Free()
	if err := s.ctx.DecryptInit(s.session, []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_GCM, params)}, key); err != nil {
		return nil, fmt.Errorf("pkcs11: AES-GCM decrypt init: %w", err)
	}
	return s.ctx.Decrypt(s.session, sealed[gcmIVSize:])
}

// keyRoundTripsLocked reports whether a fresh random probe seals and opens
// back to itself under key.
func (s *moduleSession) keyRoundTripsLocked(key p11.ObjectHandle) bool {
	probe, err := crypto.RandomBytes(16)
	if err != nil {
		return false
	}
	aad := []byte("trstctl.pkcs11.aes-gcm-probe.v1")
	sealed, err := s.sealLocked(key, probe, aad)
	if err != nil {
		return false
	}
	opened, err := s.openLocked(key, sealed, aad)
	return err == nil && crypto.ConstantTimeEqual(opened, probe)
}

// secretKeyLocked finds the one token AES key labeled label and checks it is a
// sensitive, non-extractable AES-256 key allowed to encrypt and decrypt.
func (s *moduleSession) secretKeyLocked(label string) (p11.ObjectHandle, error) {
	if s.closed {
		return 0, errors.New("pkcs11: session is closed")
	}
	if label == "" || strings.TrimSpace(label) != label || len(label) > maxKeyLabel {
		return 0, fmt.Errorf("pkcs11: a key label must be 1 to %d bytes with no surrounding space", maxKeyLabel)
	}
	if err := s.ctx.FindObjectsInit(s.session, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_AES),
		p11.NewAttribute(p11.CKA_LABEL, label),
	}); err != nil {
		return 0, fmt.Errorf("pkcs11: find AES key: %w", err)
	}
	objects, _, findErr := s.ctx.FindObjects(s.session, 2)
	finalErr := s.ctx.FindObjectsFinal(s.session)
	if findErr != nil {
		return 0, fmt.Errorf("pkcs11: find AES key: %w", findErr)
	}
	if finalErr != nil {
		return 0, fmt.Errorf("pkcs11: find AES key: %w", finalErr)
	}
	switch len(objects) {
	case 0:
		return 0, ErrSecretKeyNotFound
	case 1:
	default:
		return 0, fmt.Errorf("%w: the label names more than one AES key", ErrSecretKeyPolicy)
	}
	attrs, err := s.ctx.GetAttributeValue(s.session, objects[0], []*p11.Attribute{
		p11.NewAttribute(p11.CKA_VALUE_LEN, nil),
		p11.NewAttribute(p11.CKA_SENSITIVE, nil),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, nil),
		p11.NewAttribute(p11.CKA_ENCRYPT, nil),
		p11.NewAttribute(p11.CKA_DECRYPT, nil),
	})
	if err != nil {
		return 0, fmt.Errorf("pkcs11: read AES key attributes: %w", err)
	}
	if !secretKeyPolicyHolds(attrs) {
		return 0, ErrSecretKeyPolicy
	}
	return objects[0], nil
}

// secretKeyPolicyHolds reports whether the attributes describe a 32-byte key
// that is sensitive, not extractable, and allowed to encrypt and decrypt.
func secretKeyPolicyHolds(attrs []*p11.Attribute) bool {
	flags := map[uint]bool{
		p11.CKA_SENSITIVE: true, p11.CKA_EXTRACTABLE: false,
		p11.CKA_ENCRYPT: true, p11.CKA_DECRYPT: true,
	}
	seen := 0
	for _, attr := range attrs {
		if attr == nil {
			return false
		}
		if attr.Type == p11.CKA_VALUE_LEN {
			if ulongValue(attr.Value) != aesKeyBytes {
				return false
			}
			seen++
			continue
		}
		want, known := flags[attr.Type]
		if !known || len(attr.Value) != 1 || (attr.Value[0] != 0) != want {
			return false
		}
		seen++
	}
	return seen == len(flags)+1
}

// ulongValue decodes a CK_ULONG attribute, which the module writes in the
// platform's byte order and width.
func ulongValue(raw []byte) uint64 {
	switch len(raw) {
	case 8:
		return binary.NativeEndian.Uint64(raw)
	case 4:
		return uint64(binary.NativeEndian.Uint32(raw))
	default:
		return 0
	}
}
