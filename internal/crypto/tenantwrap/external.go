// SPDX-License-Identifier: BUSL-1.1

package tenantwrap

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Wrapper keys held outside the process (A123). The isolated signer keeps a
// tenant's domain KEK wrapped by an AES-256 key on an operator HSM, which never
// enters the signer's memory: an ExternalWrapper seals and opens the
// container's plaintext with it. The plaintext is the same marker, binding hash
// and domain KEK as a local-file container, and the binding hash is also the
// AES-GCM associated data, so the binding holds even under a module that
// mishandles associated data. The container has its own magic and is never
// read as a local-file one.

const (
	externalFormatMagic = "TDH1"
	externalIVSize      = 12
	externalTagSize     = 16
	externalWrappedSize = externalIVSize + wrappedPlainSize + externalTagSize
	externalPayloadSize = headerSize + externalWrappedSize
	externalEncodedSize = externalPayloadSize + sha256.Size
)

var externalAADContext = []byte("trstctl.tenantwrap.external-aad.v1")

// ExternalWrapper seals and opens with a wrapper key held outside this
// process, such as an AES-256 key on an HSM. Seal returns iv || ciphertext ||
// tag for AES-256-GCM with a 12-byte IV and a 16-byte tag. A value that does
// not authenticate must be reported as an error matching ErrUnwrap; any other
// failure as one matching ErrUnavailable.
type ExternalWrapper interface {
	Seal(plaintext, aad []byte) ([]byte, error)
	Open(sealed, aad []byte) ([]byte, error)
}

// CreateDomainKEKExternal creates a fresh tenant domain KEK in locked memory
// and returns it with its container wrapped by w, bound to domainBinding as
// CreateDomainKEK binds it. The returned LocalKEK belongs to the caller, which
// must call Destroy; on every error no usable material is returned.
func CreateDomainKEKExternal(w ExternalWrapper, domainBinding []byte) (*seal.LocalKEK, []byte, error) {
	return createDomainKEKExternal(w, domainBinding, seal.GenerateKEK, seal.NewLocalKEK)
}

func createDomainKEKExternal(
	w ExternalWrapper,
	domainBinding []byte,
	generate generateFunc,
	newLocalKEK localKEKFactory,
) (*seal.LocalKEK, []byte, error) {
	if len(domainBinding) == 0 {
		return nil, nil, ErrDomainBinding
	}
	if w == nil {
		return nil, nil, ErrUnavailable
	}
	domainRaw, err := generate()
	defer secret.Wipe(domainRaw)
	if err != nil || len(domainRaw) != localKeySize {
		return nil, nil, ErrCustody
	}
	domainKEK, err := newLocalKEK(domainRaw)
	if err != nil {
		if domainKEK != nil {
			domainKEK.Destroy()
		}
		return nil, nil, ErrCustody
	}
	keep := false
	defer func() {
		if !keep {
			domainKEK.Destroy()
		}
	}()

	wrappedPlain, err := secret.New(wrappedPlainSize)
	if err != nil {
		return nil, nil, ErrCustody
	}
	defer wrappedPlain.Destroy()
	plain := wrappedPlain.Bytes()
	bindingHash := hashDomainBinding(domainBinding)
	copy(plain, wrappedPlainMarker)
	copy(plain[len(wrappedPlainMarker):], bindingHash[:])
	copy(plain[len(wrappedPlainMarker)+sha256.Size:], domainRaw)

	sealed, err := w.Seal(plain, externalAAD(bindingHash))
	if err != nil {
		return nil, nil, externalError(err)
	}
	if len(sealed) != externalWrappedSize {
		return nil, nil, ErrCustody
	}
	keep = true
	return domainKEK, encodeExternalDomainKEK(sealed), nil
}

// OpenDomainKEKExternal opens a container CreateDomainKEKExternal made, with
// the same wrapper and the exact binding, and returns the domain KEK in locked
// memory for the caller to Destroy. A malformed container is ErrCorrupt; a
// wrong wrapper key, wrong binding or tampered container is ErrUnwrap.
func OpenDomainKEKExternal(w ExternalWrapper, wrapped, expectedDomainBinding []byte) (*seal.LocalKEK, error) {
	return openDomainKEKExternal(w, wrapped, expectedDomainBinding, seal.NewLocalKEK)
}

func openDomainKEKExternal(
	w ExternalWrapper,
	encoded, expectedDomainBinding []byte,
	newLocalKEK localKEKFactory,
) (*seal.LocalKEK, error) {
	if len(expectedDomainBinding) == 0 {
		return nil, ErrDomainBinding
	}
	sealed, err := parseExternalDomainKEK(encoded)
	if err != nil {
		return nil, err
	}
	if w == nil {
		return nil, ErrUnavailable
	}
	bindingHash := hashDomainBinding(expectedDomainBinding)
	plain, err := w.Open(sealed, externalAAD(bindingHash))
	defer secret.Wipe(plain)
	if err != nil {
		return nil, externalError(err)
	}
	if len(plain) != wrappedPlainSize ||
		subtle.ConstantTimeCompare(plain[:len(wrappedPlainMarker)], []byte(wrappedPlainMarker)) != 1 ||
		subtle.ConstantTimeCompare(plain[len(wrappedPlainMarker):len(wrappedPlainMarker)+sha256.Size], bindingHash[:]) != 1 {
		return nil, ErrUnwrap
	}
	domainKEK, err := newLocalKEK(plain[len(wrappedPlainMarker)+sha256.Size:])
	if err != nil {
		if domainKEK != nil {
			domainKEK.Destroy()
		}
		return nil, ErrCustody
	}
	return domainKEK, nil
}

// externalError keeps the wrapper's classification and treats anything it did
// not classify as an unavailable wrapper.
func externalError(err error) error {
	switch {
	case errors.Is(err, ErrUnwrap):
		return ErrUnwrap
	case errors.Is(err, ErrUnavailable):
		return err
	default:
		return errors.Join(ErrUnavailable, err)
	}
}

func externalAAD(bindingHash [sha256.Size]byte) []byte {
	aad := make([]byte, 0, len(externalAADContext)+1+sha256.Size)
	aad = append(aad, externalAADContext...)
	aad = append(aad, 0)
	return append(aad, bindingHash[:]...)
}

func encodeExternalDomainKEK(sealed []byte) []byte {
	out := make([]byte, externalPayloadSize, externalEncodedSize)
	copy(out[:len(externalFormatMagic)], externalFormatMagic)
	out[len(externalFormatMagic)] = formatVersion
	offset := len(externalFormatMagic) + 1
	binary.BigEndian.PutUint16(out[offset:offset+2], uint16(externalWrappedSize))
	copy(out[offset+2:], sealed)
	sum := sha256.Sum256(out)
	return append(out, sum[:]...)
}

func parseExternalDomainKEK(encoded []byte) ([]byte, error) {
	if len(encoded) != externalEncodedSize ||
		subtle.ConstantTimeCompare(encoded[:len(externalFormatMagic)], []byte(externalFormatMagic)) != 1 ||
		encoded[len(externalFormatMagic)] != formatVersion {
		return nil, ErrCorrupt
	}
	offset := len(externalFormatMagic) + 1
	if int(binary.BigEndian.Uint16(encoded[offset:offset+2])) != externalWrappedSize {
		return nil, ErrCorrupt
	}
	sum := sha256.Sum256(encoded[:externalPayloadSize])
	if subtle.ConstantTimeCompare(encoded[externalPayloadSize:], sum[:]) != 1 {
		return nil, ErrCorrupt
	}
	return encoded[offset+2 : externalPayloadSize], nil
}
