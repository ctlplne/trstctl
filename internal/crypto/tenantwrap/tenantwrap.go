// SPDX-License-Identifier: MPL-2.0

package tenantwrap

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

const (
	localKeySize = 32

	formatMagic   = "TDK1"
	formatVersion = byte(1)

	// LocalKEK.WrapDEK is AES-GCM: a 12-byte nonce plus a 16-byte tag.
	localWrappedOverhead = 12 + 16
	wrappedPlainMarker   = "trstctl tenant domain KEK v1"
	wrappedPlainSize     = len(wrappedPlainMarker) + sha256.Size + localKeySize
	domainWrappedSize    = wrappedPlainSize + localWrappedOverhead

	// magic | version | wrapped length
	headerSize  = len(formatMagic) + 1 + 2
	payloadSize = headerSize + domainWrappedSize
	encodedSize = payloadSize + sha256.Size
)

var domainBindingContext = []byte("trstctl.tenantwrap.domain-binding.v1")

var (
	// ErrUnavailable means the explicitly configured local wrapper could not be
	// loaded into locked memory. The error deliberately omits paths and bytes.
	ErrUnavailable = errors.New("tenantwrap: local wrapper unavailable")
	// ErrInvalidWrapperKey means the provisioned wrapper file did not contain
	// exactly one AES-256 key.
	ErrInvalidWrapperKey = errors.New("tenantwrap: local wrapper key has invalid size")
	// ErrCustody means entropy generation, locked-memory allocation, or local
	// wrapping failed after the operator wrapper file was loaded successfully.
	// It must not be reported as wrapper_unavailable because operator file
	// recovery cannot fix process entropy or memory-pressure failures.
	ErrCustody = errors.New("tenantwrap: local custody operation failed")
	// ErrUnwrap means a structurally valid representation could not be opened
	// and authenticated with the supplied wrapper and domain binding. It
	// deliberately does not claim whether the wrapper, binding, or authenticated
	// ciphertext was wrong: those conditions cannot be distinguished soundly.
	ErrUnwrap = errors.New("tenantwrap: wrapped domain key cannot be opened")
	// ErrCorrupt means the persisted wrapped representation was malformed or
	// failed its unkeyed diagnostic checksum.
	ErrCorrupt = errors.New("tenantwrap: wrapped domain key is corrupt")
	// ErrDomainBinding means the caller omitted the non-secret tenant-domain
	// identity that is cryptographically bound to the wrapped key.
	ErrDomainBinding = errors.New("tenantwrap: domain binding is required")
)

type (
	loadFunc        func(string) ([]byte, error)
	generateFunc    func() ([]byte, error)
	localKEKFactory func([]byte) (*seal.LocalKEK, error)
)

// CreateDomainKEK creates a fresh tenant domain KEK, locks it in memory, and
// returns its persisted representation wrapped by wrapperPath's existing key.
// domainBinding must uniquely encode the tenant, domain ID, and generation. Its
// hash is authenticated inside the wrapped plaintext so records cannot be
// substituted between tenants or generations, even if wrapper keys are reused.
//
// wrapperPath is read with secretfile.Load and is NEVER created. The returned
// LocalKEK belongs to the caller, which must call Destroy. On every error this
// function destroys any locked KEK it created and returns no usable material.
func CreateDomainKEK(wrapperPath string, domainBinding []byte) (*seal.LocalKEK, []byte, error) {
	return createDomainKEK(wrapperPath, domainBinding, secretfile.Load, seal.GenerateKEK, seal.NewLocalKEK)
}

func createDomainKEK(
	wrapperPath string,
	domainBinding []byte,
	load loadFunc,
	generate generateFunc,
	newLocalKEK localKEKFactory,
) (domainKEK *seal.LocalKEK, encoded []byte, err error) {
	if len(domainBinding) == 0 {
		return nil, nil, ErrDomainBinding
	}
	wrapperRaw, err := load(wrapperPath)
	defer secret.Wipe(wrapperRaw)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	if len(wrapperRaw) != localKeySize {
		return nil, nil, ErrInvalidWrapperKey
	}

	wrapper, err := newLocalKEK(wrapperRaw)
	if err != nil {
		if wrapper != nil {
			wrapper.Destroy()
		}
		return nil, nil, ErrCustody
	}
	defer wrapper.Destroy()

	domainRaw, err := generate()
	defer secret.Wipe(domainRaw)
	if err != nil {
		return nil, nil, ErrCustody
	}
	if len(domainRaw) != localKeySize {
		return nil, nil, ErrCustody
	}

	domainKEK, err = newLocalKEK(domainRaw)
	if err != nil {
		if domainKEK != nil {
			domainKEK.Destroy()
		}
		return nil, nil, ErrCustody
	}
	ownedDomain := domainKEK
	keepDomain := false
	defer func() {
		if !keepDomain {
			ownedDomain.Destroy()
		}
	}()

	wrappedPlain, err := secret.New(wrappedPlainSize)
	if err != nil {
		return nil, nil, ErrCustody
	}
	defer wrappedPlain.Destroy()
	plain := wrappedPlain.Bytes()
	copy(plain, wrappedPlainMarker)
	bindingHash := hashDomainBinding(domainBinding)
	copy(plain[len(wrappedPlainMarker):], bindingHash[:])
	copy(plain[len(wrappedPlainMarker)+sha256.Size:], domainRaw)

	wrappedDomain, err := wrapper.WrapDEK(plain)
	defer secret.Wipe(wrappedDomain)
	if err != nil {
		return nil, nil, ErrCustody
	}
	if len(wrappedDomain) != domainWrappedSize {
		return nil, nil, ErrCustody
	}

	encoded = encodeWrappedDomainKEK(wrappedDomain)
	keepDomain = true
	return domainKEK, encoded, nil
}

// OpenDomainKEK opens a persisted tenant domain KEK with wrapperPath's existing
// operator key and returns the KEK in locked memory. expectedDomainBinding must
// be the exact tenant/domain/generation identity used at creation.
//
// The returned LocalKEK belongs to the caller, which must call Destroy.
// Structural/checksum corruption is ErrCorrupt. A wrong wrapper, wrong binding,
// or authenticated-ciphertext failure is the deliberately generic ErrUnwrap.
func OpenDomainKEK(wrapperPath string, wrapped, expectedDomainBinding []byte) (*seal.LocalKEK, error) {
	return openDomainKEK(wrapperPath, wrapped, expectedDomainBinding, secretfile.Load, seal.NewLocalKEK)
}

func openDomainKEK(
	wrapperPath string,
	encoded []byte,
	expectedDomainBinding []byte,
	load loadFunc,
	newLocalKEK localKEKFactory,
) (*seal.LocalKEK, error) {
	if len(expectedDomainBinding) == 0 {
		return nil, ErrDomainBinding
	}
	parts, err := parseWrappedDomainKEK(encoded)
	if err != nil {
		return nil, err
	}

	wrapperRaw, err := load(wrapperPath)
	defer secret.Wipe(wrapperRaw)
	if err != nil {
		return nil, ErrUnavailable
	}
	if len(wrapperRaw) != localKeySize {
		return nil, ErrInvalidWrapperKey
	}

	wrapper, err := newLocalKEK(wrapperRaw)
	if err != nil {
		if wrapper != nil {
			wrapper.Destroy()
		}
		return nil, ErrCustody
	}
	defer wrapper.Destroy()

	wrappedPlain, err := wrapper.UnwrapDEK(parts.wrappedDomain)
	defer secret.Wipe(wrappedPlain)
	if err != nil {
		return nil, ErrUnwrap
	}
	if len(wrappedPlain) != wrappedPlainSize {
		return nil, ErrUnwrap
	}
	marker := wrappedPlain[:len(wrappedPlainMarker)]
	if subtle.ConstantTimeCompare(marker, []byte(wrappedPlainMarker)) != 1 {
		return nil, ErrUnwrap
	}
	wantBindingHash := hashDomainBinding(expectedDomainBinding)
	gotBindingHash := wrappedPlain[len(wrappedPlainMarker) : len(wrappedPlainMarker)+sha256.Size]
	if subtle.ConstantTimeCompare(gotBindingHash, wantBindingHash[:]) != 1 {
		return nil, ErrUnwrap
	}
	domainRaw := wrappedPlain[len(wrappedPlainMarker)+sha256.Size:]
	domainKEK, err := newLocalKEK(domainRaw)
	if err != nil {
		if domainKEK != nil {
			domainKEK.Destroy()
		}
		return nil, ErrCustody
	}
	return domainKEK, nil
}

type wrappedDomainParts struct {
	wrappedDomain []byte
}

func encodeWrappedDomainKEK(wrappedDomain []byte) []byte {
	out := make([]byte, payloadSize, encodedSize)
	copy(out[:len(formatMagic)], formatMagic)
	out[len(formatMagic)] = formatVersion
	offset := len(formatMagic) + 1
	binary.BigEndian.PutUint16(out[offset:offset+2], uint16(len(wrappedDomain)))
	offset += 2
	copy(out[offset:offset+len(wrappedDomain)], wrappedDomain)
	sum := sha256.Sum256(out)
	out = append(out, sum[:]...)
	return out
}

func parseWrappedDomainKEK(encoded []byte) (wrappedDomainParts, error) {
	if len(encoded) != encodedSize {
		return wrappedDomainParts{}, ErrCorrupt
	}
	if subtle.ConstantTimeCompare(encoded[:len(formatMagic)], []byte(formatMagic)) != 1 {
		return wrappedDomainParts{}, ErrCorrupt
	}
	if encoded[len(formatMagic)] != formatVersion {
		return wrappedDomainParts{}, ErrCorrupt
	}
	offset := len(formatMagic) + 1
	domainLen := int(binary.BigEndian.Uint16(encoded[offset : offset+2]))
	offset += 2
	if domainLen != domainWrappedSize {
		return wrappedDomainParts{}, ErrCorrupt
	}

	sum := sha256.Sum256(encoded[:payloadSize])
	if subtle.ConstantTimeCompare(encoded[payloadSize:], sum[:]) != 1 {
		return wrappedDomainParts{}, ErrCorrupt
	}
	return wrappedDomainParts{
		wrappedDomain: encoded[offset:payloadSize],
	}, nil
}

func hashDomainBinding(domainBinding []byte) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write(domainBindingContext)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(domainBinding)
	var out [sha256.Size]byte
	h.Sum(out[:0])
	return out
}
