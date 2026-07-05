// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// Domain separators distinguish PCAS commitments from any other signed structure
// and from each other. They are frozen: changing one changes every commitment.
const (
	commitmentDomain = "trstctl/pcas/succession/commitment/v1"
	genesisDomain    = "trstctl/pcas/succession/genesis/v1"

	// HashAlgSHA256 is the registry identifier of the commitment hash function H,
	// bound in every commitment as hash_alg so verification stays well-defined
	// across hash migrations (INV-11).
	HashAlgSHA256 = "SHA-256"
)

// algRegistry maps each supported registry algorithm identifier to a stable
// numeric id bound in the commitment (COSE-style). Only these canonical
// crypto.Algorithm values are valid; free-form aliases (for example "P-256",
// "prime256v1", "secp256r1") are rejected by registryID, so aliasing cannot
// change commitment equality or signature validity (INV-11, r11 canonical
// encoding). Post-quantum identifiers are added, keyed by their canonical
// registry name, by the cards that implement them (PCAS-05/14) without importing
// ee/pqc into this package.
var algRegistry = map[crypto.Algorithm]uint64{
	crypto.RSA2048:   1,
	crypto.RSA3072:   2,
	crypto.RSA4096:   3,
	crypto.ECDSAP256: 10,
	crypto.ECDSAP384: 11,
	crypto.ECDSAP521: 12,
	crypto.Ed25519:   20,

	// Post-quantum and hybrid registry identifiers (algorithms implemented in
	// ee/pqc; classified in algclass.go). Bound here by canonical identifier so
	// commitments over PQ/hybrid records are well-defined without importing ee/pqc.
	crypto.Algorithm("ML-DSA-44"):            30,
	crypto.Algorithm("ML-DSA-65"):            31,
	crypto.Algorithm("ML-DSA-87"):            32,
	crypto.Algorithm("SLH-DSA-128s"):         33,
	crypto.Algorithm("SLH-DSA-128f"):         34,
	crypto.Algorithm("SLH-DSA-192s"):         35,
	crypto.Algorithm("SLH-DSA-256s"):         36,
	crypto.Algorithm("Ed25519+ML-DSA-65"):    40,
	crypto.Algorithm("ECDSA-P256+ML-DSA-65"): 41,
}

func registryID(alg crypto.Algorithm) (uint64, error) {
	id, ok := algRegistry[alg]
	if !ok {
		return 0, fmt.Errorf("succession: %q is not a registry algorithm identifier (aliases are rejected; INV-11)", alg)
	}
	return id, nil
}

// CommitmentFields are the fields bound by a succession commitment (r11
// §Commitment Construction). deployment_scope binds a trust-domain/deployment
// identifier so records minted by distinct deployments cannot verify against one
// another even where tenant and identity identifiers collide (INV-5 / claim 7).
type CommitmentFields struct {
	DeploymentScope  string
	IdentityID       string
	TenantID         string
	PredecessorEpoch uint64
	Epoch            uint64
	PredecessorAlg   crypto.Algorithm
	PredecessorPub   []byte // SubjectPublicKeyInfo (PKIX/DER)
	SuccessorAlg     crypto.Algorithm
	SuccessorPub     []byte
	PolicyRef        string
	HashAlg          string
	NotBefore        int64 // unix seconds
	NotAfter         int64
}

// encode produces the canonical, domain-separated, length-prefixed byte string
// over the bound fields. Every field is either an 8-byte big-endian integer or a
// length-prefixed (8-byte big-endian length) byte string, in a fixed order, so
// the encoding is deterministic and identical across runs, machines, and
// architectures (INV-11). Algorithm identifiers are bound as their fixed registry
// ids, never their free-form names.
func (f CommitmentFields) encode() ([]byte, error) {
	predID, err := registryID(f.PredecessorAlg)
	if err != nil {
		return nil, fmt.Errorf("predecessor alg: %w", err)
	}
	succID, err := registryID(f.SuccessorAlg)
	if err != nil {
		return nil, fmt.Errorf("successor alg: %w", err)
	}
	if f.HashAlg != HashAlgSHA256 {
		return nil, fmt.Errorf("succession: unsupported hash_alg %q (want %q)", f.HashAlg, HashAlgSHA256)
	}
	var b bytes.Buffer
	writeField(&b, []byte(commitmentDomain))
	writeField(&b, []byte(f.DeploymentScope))
	writeField(&b, []byte(f.IdentityID))
	writeField(&b, []byte(f.TenantID))
	writeUint(&b, f.PredecessorEpoch)
	writeUint(&b, f.Epoch)
	writeUint(&b, predID)
	writeField(&b, f.PredecessorPub)
	writeUint(&b, succID)
	writeField(&b, f.SuccessorPub)
	writeField(&b, []byte(f.PolicyRef))
	writeField(&b, []byte(f.HashAlg))
	writeUint(&b, uint64(f.NotBefore))
	writeUint(&b, uint64(f.NotAfter))
	return b.Bytes(), nil
}

// Commit returns the commitment digest H(encode(fields)), hashing through the
// core AN-3 crypto boundary (SHA-256). ee/ never imports crypto/* directly.
func Commit(f CommitmentFields) ([]byte, error) {
	enc, err := f.encode()
	if err != nil {
		return nil, err
	}
	return crypto.SHA256Sum(enc), nil
}

func writeField(b *bytes.Buffer, v []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(v)))
	b.Write(l[:])
	b.Write(v)
}

func writeUint(b *bytes.Buffer, v uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	b.Write(x[:])
}
