// SPDX-License-Identifier: BUSL-1.1

package tpm

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// TSS2 private key files (TPM-O1). A host endpoint key the TPM generated is
// kept as the TPM's wrapping of it: its public area and its private area
// encrypted under a parent storage key, which only that TPM can load. The
// file format is the one OpenSSL 3's tpm2 provider (and the TPM 2.0 OpenSSL
// engine before it) reads, so a service on the host loads the key through
// the provider and the private key never exists outside the TPM:
//
//	TPMKey ::= SEQUENCE {
//	    type      OBJECT IDENTIFIER,             -- id-loadablekey 2.23.133.10.1.3
//	    emptyAuth [0] EXPLICIT BOOLEAN OPTIONAL,
//	    parent    INTEGER,                       -- the parent's TPM handle
//	    pubkey    OCTET STRING,                  -- TPM2B_PUBLIC
//	    privkey   OCTET STRING }                 -- TPM2B_PRIVATE
//
// carried in a PEM block of type "TSS2 PRIVATE KEY".

// TSS2PEMType is the PEM block type of a TSS2 private key file.
const TSS2PEMType = "TSS2 PRIVATE KEY"

// HostSRKHandle is TCG's reserved persistent handle for the storage root key
// (TCG TPM v2.0 Provisioning Guidance): the parent a host key file names, so
// the provider loads the key under the same SRK the agent created it under.
const HostSRKHandle uint32 = 0x81000001

var oidTSS2LoadableKey = asn1.ObjectIdentifier{2, 23, 133, 10, 1, 3}

// maxTSS2Area bounds a public or private area (a TPM2B is at most 64 KiB).
const maxTSS2Area = 1 << 16

type tss2Key struct {
	Type      asn1.ObjectIdentifier
	EmptyAuth bool `asn1:"optional,explicit,tag:0"`
	Parent    int64
	Public    []byte
	Private   []byte
}

// EncodeTSS2PrivateKey wraps a TPM-generated key's public and private areas
// (each without its TPM2B size, as TPM2_Create returns them) as a TSS2 private
// key file naming parent, with an empty key authorization.
func EncodeTSS2PrivateKey(parent uint32, public, private []byte) ([]byte, error) {
	if len(public) == 0 || len(private) == 0 || len(public) >= maxTSS2Area || len(private) >= maxTSS2Area {
		return nil, errors.New("tpm: a TSS2 key needs its public and private areas")
	}
	der, err := asn1.Marshal(tss2Key{Type: oidTSS2LoadableKey, EmptyAuth: true, Parent: int64(parent),
		Public: tpm2b(public), Private: tpm2b(private)})
	if err != nil {
		return nil, fmt.Errorf("tpm: encode TSS2 key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: TSS2PEMType, Bytes: der}), nil
}

// DecodeTSS2PrivateKey reads a TSS2 private key file: a loadable key with an
// empty authorization under a persistent parent. It returns the parent and
// the public and private areas without their TPM2B sizes.
func DecodeTSS2PrivateKey(file []byte) (parent uint32, public, private []byte, err error) {
	block, rest := pem.Decode(file)
	if block != nil {
		defer secret.Wipe(block.Bytes)
	}
	if block == nil || block.Type != TSS2PEMType || len(block.Headers) != 0 || len(trimSpace(rest)) != 0 {
		return 0, nil, nil, errors.New("tpm: not one TSS2 PRIVATE KEY PEM block")
	}
	var key tss2Key
	trailing, err := asn1.Unmarshal(block.Bytes, &key)
	if err != nil || len(trailing) != 0 {
		return 0, nil, nil, errors.New("tpm: malformed TSS2 key")
	}
	if !key.Type.Equal(oidTSS2LoadableKey) || !key.EmptyAuth {
		return 0, nil, nil, errors.New("tpm: a host key file must be a loadable TSS2 key with an empty authorization")
	}
	if key.Parent < 0x81000000 || key.Parent > 0x81ffffff {
		return 0, nil, nil, fmt.Errorf("tpm: TSS2 key parent 0x%x is not a persistent handle", key.Parent)
	}
	if public, err = fromTPM2B(key.Public); err != nil {
		return 0, nil, nil, fmt.Errorf("tpm: TSS2 key public area: %w", err)
	}
	if private, err = fromTPM2B(key.Private); err != nil {
		return 0, nil, nil, fmt.Errorf("tpm: TSS2 key private area: %w", err)
	}
	return uint32(key.Parent), public, private, nil
}

func tpm2b(area []byte) []byte {
	out := make([]byte, 2, 2+len(area))
	binary.BigEndian.PutUint16(out, uint16(len(area))) // #nosec G115 -- bounded below 64 KiB by the caller (CWE-190)
	return append(out, area...)
}

func fromTPM2B(raw []byte) ([]byte, error) {
	if len(raw) < 3 || int(binary.BigEndian.Uint16(raw)) != len(raw)-2 {
		return nil, errors.New("its TPM2B size does not match its length")
	}
	return append([]byte(nil), raw[2:]...), nil
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\n' || b[0] == '\r' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}
