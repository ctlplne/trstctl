// SPDX-License-Identifier: BUSL-1.1

package seal

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// A198: the deployment KEK's generations. A data key wrapped under the
// deployment KEK's original local key (generation 0) is the LocalKEK output it
// always was. A data key wrapped under a later generation carries that
// generation in front, so a reader routes it to exactly one key-encryption key
// without trial decryption, and a rotation can tell which containers still
// need re-wrapping without opening a payload.

// LocalWrappedDEKSize is the length of a data key a LocalKEK wraps: nonce,
// the 32-byte key's ciphertext, and the GCM tag. Routing reads this length
// first, so no untagged value can be taken for a tagged one.
const LocalWrappedDEKSize = nonceSize + dekSize + 16

// generationHeaderSize is the tag in front of a later generation's wrapped
// data key: four magic bytes and the generation (big-endian uint32).
const generationHeaderSize = 8

var generationMagic = []byte{'D', 'K', 'G', '1'}

// ErrGeneration means a wrapped data key carries no valid generation.
var ErrGeneration = errors.New("seal: wrapped data key generation is malformed")

// TagGeneration prefixes a wrapped data key with the deployment KEK generation
// (1 or later) that wrapped it.
func TagGeneration(generation uint32, wrapped []byte) ([]byte, error) {
	size := generationHeaderSize + len(wrapped)
	if generation == 0 || len(wrapped) == 0 || size == LocalWrappedDEKSize || size > maxUint16Value {
		return nil, ErrGeneration
	}
	out := make([]byte, 0, size)
	out = append(out, generationMagic...)
	out = binary.BigEndian.AppendUint32(out, generation)
	return append(out, wrapped...), nil
}

// WrappedGeneration reads which generation wrapped a data key: 0 for the
// untagged LocalKEK form, otherwise the tagged generation and the wrapped key
// behind the tag. The returned slice aliases wrapped.
func WrappedGeneration(wrapped []byte) (uint32, []byte, error) {
	if len(wrapped) == LocalWrappedDEKSize {
		return 0, wrapped, nil
	}
	if len(wrapped) <= generationHeaderSize ||
		subtle.ConstantTimeCompare(wrapped[:len(generationMagic)], generationMagic) != 1 {
		return 0, nil, ErrGeneration
	}
	generation := binary.BigEndian.Uint32(wrapped[len(generationMagic):generationHeaderSize])
	if generation == 0 {
		return 0, nil, ErrGeneration
	}
	return generation, wrapped[generationHeaderSize:], nil
}

// ContainerWrappedDEK returns a copy of a v1 or v2 container's wrapped data key
// and whether the container carries a protection-domain label (v2). The
// payload is not opened.
func ContainerWrappedDEK(sealed []byte) (wrapped []byte, labeled bool, err error) {
	version, parts, err := parseContainer(sealed)
	if err != nil {
		return nil, false, err
	}
	return append([]byte(nil), parts.wrapped...), version == version2, nil
}

// RewrapContainerDEK replaces a v1 or v2 container's wrapped data key with the
// one rewrap returns, or keeps the container when rewrap reports no change.
// Every other byte (version, domain label and tag, nonce, ciphertext) is
// copied, and the payload is never opened.
func RewrapContainerDEK(sealed []byte, rewrap func(wrapped []byte) ([]byte, bool, error)) ([]byte, bool, error) {
	version, parts, err := parseContainer(sealed)
	if err != nil {
		return nil, false, err
	}
	next, changed, err := rewrap(parts.wrapped)
	if err != nil {
		return nil, false, err
	}
	if !changed {
		return sealed, false, nil
	}
	var out []byte
	if version == version1 {
		out, err = buildV1(next, parts.nonce, parts.ciphertext)
	} else {
		out, err = buildV2(parts.domain, parts.domainTag, next, parts.nonce, parts.ciphertext)
	}
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// ValidateRewrappedDEK proves that after differs from before only in its
// wrapped data key, and that w unwraps both wrapped keys to the same data key.
// Neither payload is opened.
func ValidateRewrappedDEK(w KeyWrapper, before, after []byte) error {
	beforeVersion, beforeParts, err := parseContainer(before)
	if err != nil {
		return err
	}
	afterVersion, afterParts, err := parseContainer(after)
	if err != nil {
		return err
	}
	if beforeVersion != afterVersion ||
		subtle.ConstantTimeCompare(beforeParts.domain, afterParts.domain) != 1 ||
		subtle.ConstantTimeCompare(beforeParts.domainTag, afterParts.domainTag) != 1 ||
		subtle.ConstantTimeCompare(beforeParts.nonce, afterParts.nonce) != 1 ||
		subtle.ConstantTimeCompare(beforeParts.ciphertext, afterParts.ciphertext) != 1 {
		return ErrFormat
	}
	beforeDEK, err := w.UnwrapDEK(beforeParts.wrapped)
	if err != nil || len(beforeDEK) != dekSize {
		secret.Wipe(beforeDEK)
		return ErrDecrypt
	}
	defer secret.Wipe(beforeDEK)
	afterDEK, err := w.UnwrapDEK(afterParts.wrapped)
	if err != nil || len(afterDEK) != dekSize {
		secret.Wipe(afterDEK)
		return ErrDecrypt
	}
	defer secret.Wipe(afterDEK)
	if subtle.ConstantTimeCompare(beforeDEK, afterDEK) != 1 {
		return ErrDecrypt
	}
	return nil
}

func parseContainer(sealed []byte) (byte, containerParts, error) {
	version, body, err := splitVersion(sealed)
	if err != nil {
		return 0, containerParts{}, err
	}
	var parts containerParts
	switch version {
	case version1:
		parts, err = parseV1(body)
	case version2:
		parts, err = parseV2(body)
	default:
		return 0, containerParts{}, ErrFormat
	}
	if err != nil {
		return 0, containerParts{}, err
	}
	return version, parts, nil
}

func buildV1(wrapped, nonce, ciphertext []byte) ([]byte, error) {
	if len(wrapped) == 0 || len(wrapped) > maxUint16Value || len(nonce) != nonceSize || len(ciphertext) == 0 {
		return nil, ErrFormat
	}
	out := make([]byte, 0, len(magic)+1+2+len(wrapped)+len(nonce)+len(ciphertext))
	out = append(out, magic...)
	out = append(out, version1)
	out = binary.BigEndian.AppendUint16(out, uint16(len(wrapped))) // #nosec G115 -- bounded to maxUint16Value by the guard above (CWE-190)
	out = append(out, wrapped...)
	out = append(out, nonce...)
	return append(out, ciphertext...), nil
}
