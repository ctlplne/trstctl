// SPDX-License-Identifier: BUSL-1.1
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"unsafe"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// cipher.NewGCM always uses the standard 16-byte authentication tag.
const rewrapGCMTagSize = 16

// OpenIntoLocked authenticates a container while placing AEAD plaintext only
// in protected, explicitly destroyed memory. A nil expectedDomain accepts v1
// alone; a nonnil expectedDomain accepts v2 under that exact domain alone.
func OpenIntoLocked(w KeyWrapper, container, aad, expectedDomain []byte) (*secret.Buffer, error) {
	if w == nil {
		return nil, ErrDecrypt
	}
	version, body, err := splitVersion(container)
	if err != nil {
		return nil, err
	}
	var parts containerParts
	switch version {
	case version1:
		if expectedDomain != nil {
			return nil, ErrDomain
		}
		parts, err = parseV1(body)
	case version2:
		if err := validateDomain(expectedDomain); err != nil {
			return nil, err
		}
		parts, err = parseV2(body)
		if err == nil && subtle.ConstantTimeCompare(parts.domain, expectedDomain) != 1 {
			return nil, ErrDomain
		}
	default:
		return nil, ErrFormat
	}
	if err != nil {
		return nil, err
	}
	dek, err := w.UnwrapDEK(parts.wrapped)
	if err != nil || len(dek) != dekSize {
		if len(dek) != 0 {
			secret.Wipe(dek)
		}
		return nil, ErrDecrypt
	}
	defer secret.Wipe(dek)
	if version == version2 && subtle.ConstantTimeCompare(parts.domainTag, domainTag(dek, parts.domain)) != 1 {
		return nil, ErrDomain
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, ErrDecrypt
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecrypt
	}
	if len(parts.ciphertext) < aead.Overhead() {
		return nil, ErrFormat
	}
	plainSize := len(parts.ciphertext) - aead.Overhead()
	allocationSize := plainSize
	if allocationSize == 0 {
		allocationSize = 1
	}
	protected, err := secret.NewProtected(allocationSize)
	if err != nil {
		return nil, err
	}
	if err := protected.Use(func(backing []byte) error {
		opened, openErr := aead.Open(backing[:0], parts.nonce, parts.ciphertext, aad)
		if openErr != nil {
			secret.Wipe(opened)
			return ErrDecrypt
		}
		// #nosec G103 -- compare slice addresses only to prove AEAD wrote into protected memory
		if len(opened) != plainSize || unsafe.SliceData(opened) != unsafe.SliceData(backing) {
			secret.Wipe(opened)
			return errors.New("seal: protected AEAD destination was not used")
		}
		return nil
	}); err != nil {
		protected.Destroy()
		return nil, err
	}
	return protected, nil
}

// AuthenticatedRewrapPair accepts only the DEK-only transformation made by a
// supported rewrap: both copies authenticate under their exact wrapper/domain
// and field AAD, and the payload nonce and ciphertext stay byte-identical.
// Plaintext never leaves the protected crypto buffer.
func AuthenticatedRewrapPair(
	beforeWrapper KeyWrapper, before, beforeDomain []byte,
	afterWrapper KeyWrapper, after, afterDomain []byte,
	aad []byte,
) (bool, error) {
	first, err := OpenIntoLocked(beforeWrapper, before, aad, beforeDomain)
	if err != nil {
		return false, err
	}
	defer first.Destroy()
	second, err := OpenIntoLocked(afterWrapper, after, aad, afterDomain)
	if err != nil {
		return false, err
	}
	defer second.Destroy()
	beforePayload, err := payloadView(before)
	if err != nil {
		return false, err
	}
	afterPayload, err := payloadView(after)
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(beforePayload, afterPayload) != 1 {
		return false, nil
	}
	plainSize := len(beforePayload) - nonceSize - rewrapGCMTagSize
	if plainSize < 0 {
		return false, ErrFormat
	}
	var matched bool
	err = first.Use(func(a []byte) error {
		return second.Use(func(b []byte) error {
			matched = subtle.ConstantTimeCompare(a[:plainSize], b[:plainSize]) == 1
			return nil
		})
	})
	return matched, err
}

func payloadView(container []byte) ([]byte, error) {
	version, body, err := splitVersion(container)
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
	return container[len(container)-len(parts.nonce)-len(parts.ciphertext):], nil
}
