// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// bind.go computes the credential BINDING (INV-A3, AGID-claims-1/24/34): a digest of the
// verified chain head plus the agent-stack representation, and the MINIMAL X.509
// extension that carries that binding into the issued credential so a relying party
// verifies it offline (the RP verifier is AGID-09; the richer carriage encodings are
// AGID-08 -- 04b binds digests as an X.509 extension first, minimal). Every hash routes
// through internal/crypto (AN-3).
//
// IMPORTANT (AN-4): this signer-linked file does NOT import ee/agentid/agentstack. That
// package transitively imports internal/attest -> internal/graph -> database/sql, which
// must never link into the isolated signer. Instead the gate treats the agent-stack
// representation as OPAQUE CANONICAL BYTES supplied over the seam (produced by the
// control-plane AGID-03 agentstack package, outside the boundary): it binds the exact
// bytes plus their digest, so a byte-exact prompt/tool swap flips the binding, without
// the signer needing to understand agent-stack internals. A relying party (AGID-09)
// decodes the bound bytes with the agentstack package to recover the prompt/tool/model
// digests. This file performs NO key op on its own; MintCredential runs a key op that
// the caller (the signer's keyOp closure) invokes ONLY after the gate approved.

// bindingDomain domain-separates the credential-binding digest from every other hashed
// structure so it can never collide with a record, authority, or agent-stack digest.
const bindingDomain = "agid/agentid/binding/v1"

// agentStackDigestDomain domain-separates the agent-stack representation digest the gate
// computes over the opaque representation bytes.
const agentStackDigestDomain = "agid/agentid/agent-stack-repr/v1"

// AGIDBindingOID is the private-arc OID of the minimal AGID binding extension stamped on
// the issued credential. It carries the DER of BindingMaterial. A relying party reads
// THIS extension to recover the bound chain-head + agent-stack digests and re-verify them
// offline.
var AGIDBindingOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 58888, 4, 1}

// AGIDBindingOIDString is the dotted form of AGIDBindingOID, for the crypto boundary's
// backend-agnostic CertificateExtension (which takes a dotted OID string, not
// asn1.ObjectIdentifier, so callers never import encoding/asn1 for it).
const AGIDBindingOIDString = "1.3.6.1.4.1.58888.4.1"

// Binding errors.
var (
	// ErrNothingToBind is returned when neither a chain head nor an agent-stack
	// representation is present -- there is no subject to bind, so issuance is refused
	// fail-closed (the binding-target-absent check).
	ErrNothingToBind = errors.New("delegation: nothing to bind (no chain head and no agent-stack representation)")
	// ErrNoBindingExtension is returned when a credential carries no AGID binding
	// extension (a credential not minted by this gate, or one stripped of its binding).
	ErrNoBindingExtension = errors.New("delegation: credential carries no AGID binding extension")
)

// BindingMaterial is the non-secret material bound into the credential (INV-A3). It
// carries the chain-head record digest (empty in the attestation-gated fallback, claim
// 32), the digest of the agent-stack representation and the representation's opaque
// canonical bytes (empty in the chain-only fallback, AGID-claim-31; the bytes let a relying
// party recover the prompt+tool+model digests with the agentstack package), the
// designated authority class, the attestation-evidence digest (empty when no attestation
// was required), the comparator version so a verifier reproduces the decision
// deterministically, and the root-anchor phishing-resistant auth reference (AGID-claim-13). At
// least one of ChainHeadDigest / AgentStackDigest is present (enforced by
// NewBindingMaterial); a credential that binds neither is never minted.
type BindingMaterial struct {
	ChainHeadDigest   []byte `json:"chain_head_digest,omitempty"`
	AgentStackDigest  []byte `json:"agent_stack_digest,omitempty"`
	AgentStackRepr    []byte `json:"agent_stack_repr,omitempty"`
	DesignatedClass   string `json:"designated_class,omitempty"`
	AttestationDigest []byte `json:"attestation_digest,omitempty"`
	ComparatorVersion string `json:"comparator_version"`
	RootAnchorAuthRef string `json:"root_anchor_auth_ref,omitempty"`
	// TaskEnvelopeDigest is the canonical digest of the task envelope the chain head
	// references (AGID-05, AGID-claim-2 / INV-A4), bound ALONGSIDE the chain-head digest and
	// the agent-stack representation (INV-A3 is additive, not replaced). Empty when no
	// record references a task envelope -- in which case the binding is byte-identical to
	// AGID-04b (the field is omitempty and appended last in CanonicalBytes, so an
	// envelope-free binding's canonical bytes and digest are unchanged from 04b).
	TaskEnvelopeDigest []byte `json:"task_envelope_digest,omitempty"`
}

// AgentStackDigestOf returns the domain-separated digest of an agent-stack
// representation's opaque canonical bytes, through internal/crypto (AN-3). It is the
// value bound into the credential and recorded; a byte-exact change to the representation
// (a prompt or tool swap, which flips the AGID-03 canonical bytes) flips this digest.
func AgentStackDigestOf(reprBytes []byte) []byte {
	var b bytes.Buffer
	b.WriteString(agentStackDigestDomain)
	writeBytes(&b, reprBytes)
	return crypto.SHA256Sum(b.Bytes())
}

// NewBindingMaterial assembles the binding material fail-closed: at least one of
// chainHeadDigest or non-empty reprBytes must be present, else ErrNothingToBind. The
// agent-stack digest is computed over the opaque representation bytes. taskEnvelopeDigest
// is the AGID-05 task-envelope digest bound ALONGSIDE the chain head + agent-stack repr
// (INV-A3 additive); it is empty when no record references a task envelope, leaving the
// binding byte-identical to AGID-04b.
func NewBindingMaterial(chainHeadDigest, reprBytes []byte, designatedClass string, attestationDigest []byte, rootAnchorAuthRef string, taskEnvelopeDigest []byte) (BindingMaterial, error) {
	if len(chainHeadDigest) == 0 && len(reprBytes) == 0 {
		return BindingMaterial{}, ErrNothingToBind
	}
	bm := BindingMaterial{
		ChainHeadDigest:   append([]byte(nil), chainHeadDigest...),
		DesignatedClass:   designatedClass,
		AttestationDigest: append([]byte(nil), attestationDigest...),
		ComparatorVersion: ComparatorVersion,
		RootAnchorAuthRef: rootAnchorAuthRef,
	}
	if len(reprBytes) > 0 {
		bm.AgentStackRepr = append([]byte(nil), reprBytes...)
		bm.AgentStackDigest = AgentStackDigestOf(reprBytes)
	}
	if len(taskEnvelopeDigest) > 0 {
		bm.TaskEnvelopeDigest = append([]byte(nil), taskEnvelopeDigest...)
	}
	return bm, nil
}

// CanonicalBytes returns the stable, deterministic byte encoding of the binding material
// -- the exact bytes the binding DIGEST covers and the X.509 extension carries. It is
// length-prefixed and fixed-width so it reproduces across runs and machines.
func (bm BindingMaterial) CanonicalBytes() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(bindingDomain)
	writeField(&b, "chain_head_digest")
	writeBytes(&b, bm.ChainHeadDigest)
	writeField(&b, "agent_stack_digest")
	writeBytes(&b, bm.AgentStackDigest)
	writeField(&b, "agent_stack_repr")
	writeBytes(&b, bm.AgentStackRepr)
	writeField(&b, "designated_class")
	writeStr(&b, bm.DesignatedClass)
	writeField(&b, "attestation_digest")
	writeBytes(&b, bm.AttestationDigest)
	writeField(&b, "comparator_version")
	writeStr(&b, bm.ComparatorVersion)
	writeField(&b, "root_anchor_auth_ref")
	writeStr(&b, bm.RootAnchorAuthRef)
	// AGID-05: the task-envelope digest is bound alongside the fields above (INV-A3
	// additive). It is appended LAST and length-prefixed so the encoding stays
	// unambiguous, and an envelope-free binding contributes only the field tag + a zero
	// length. This is a v1 binding-format extension: the ComparatorVersion carried in the
	// binding still pins the exact decision semantics a relying party reproduces, and the
	// AGID-04b GATE BEHAVIOR (which fields are populated for an envelope-free chain) is
	// unchanged -- TaskEnvelopeDigest is simply empty there.
	writeField(&b, "task_envelope_digest")
	writeBytes(&b, bm.TaskEnvelopeDigest)
	return b.Bytes(), nil
}

// Digest returns the SHA-256 of the binding material's canonical bytes (AN-3). This is
// the value recorded as the credential's chain digest in the issuance event and the
// value a relying party recomputes from the credential's binding extension.
func (bm BindingMaterial) Digest() ([]byte, error) {
	cb, err := bm.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	return crypto.SHA256Sum(cb), nil
}

// Encode serializes the binding material as JSON for the X.509 extension value and the
// IssuanceDecision.BindingMaterial body.
func (bm BindingMaterial) Encode() ([]byte, error) { return json.Marshal(bm) }

// DecodeBindingMaterial deserializes binding material from the JSON payload carried in
// IssuanceDecision.BindingMaterial or unwrapped from the X.509 extension.
func DecodeBindingMaterial(b []byte) (BindingMaterial, error) {
	var bm BindingMaterial
	if err := json.Unmarshal(b, &bm); err != nil {
		return BindingMaterial{}, err
	}
	return bm, nil
}

// BindingExtension builds the MINIMAL X.509 extension carrying the binding material, as a
// backend-agnostic crypto.CertificateExtension (so callers never import crypto/x509 or
// encoding/asn1; AN-3). The extension value is the DER of an ASN.1 OCTET STRING wrapping
// the JSON-encoded binding material. It is marked non-critical: a legacy relying party
// that does not understand AGID can still parse the certificate, while an AGID-aware
// relying party (AGID-09) reads the extension and re-verifies the binding offline (claim
// 34).
func BindingExtension(bm BindingMaterial) (crypto.CertificateExtension, error) {
	payload, err := bm.Encode()
	if err != nil {
		return crypto.CertificateExtension{}, err
	}
	der, err := asn1.Marshal(payload) // OCTET STRING wrapper
	if err != nil {
		return crypto.CertificateExtension{}, err
	}
	return crypto.CertificateExtension{
		OID:      AGIDBindingOIDString,
		Critical: false,
		Value:    der,
	}, nil
}

// ExtractBindingMaterial recovers the binding material from an issued credential's DER by
// reading the AGID binding extension and unwrapping it. It is the offline-verify entry
// point a relying party uses (AGID-09 builds on it). It fails closed: a credential
// without the extension, or with a malformed one, returns an error.
func ExtractBindingMaterial(certDER []byte) (BindingMaterial, error) {
	raw, _, found, err := crypto.LeafExtensionValue(certDER, AGIDBindingOIDString)
	if err != nil {
		return BindingMaterial{}, err
	}
	if !found {
		return BindingMaterial{}, ErrNoBindingExtension
	}
	var payload []byte
	if _, err := asn1.Unmarshal(raw, &payload); err != nil {
		return BindingMaterial{}, err
	}
	return DecodeBindingMaterial(payload)
}

// CredentialTTL is the default validity of a minted agent credential when a caller passes
// a non-positive ttl. Short by AGID convention (agent credentials are short-lived and
// renewed; TTL/renewal policy proper is AGID-07).
const CredentialTTL = 24 * 3600 // seconds

// MintCredential is the credential-CERTIFY half of the key op (INV-A1's after-approval
// arm): it issues a MINIMAL leaf credential for an already-generated agent key, chaining
// to the signer's issuing CA and stamping the AGID binding extension carrying bm. It is
// invoked by the signer's keyOp closure ONLY after the gate approved -- this function
// does NOT itself decide approval and must never be called on a refusal.
//
// caCertDER + caSigner are the signer-held issuing CA (its private key is signer-held;
// only the digest to sign crosses into the crypto boundary). agentSigner is the agent key
// generated inside the signer boundary (its private key never leaves the keystore; only
// its public key is certified here via a CSR). The leaf carries the agent public key as
// its subject, the binding extension, and a short validity, and is verified against the CA
// before return (SignLeafFromCSRWithProfile fails closed on an unverifiable signature).
func MintCredential(caCertDER []byte, caSigner crypto.DigestSigner, agentSigner crypto.DigestSigner, subjectCN string, ttlSeconds int64, bm BindingMaterial) (credentialDER []byte, err error) {
	ext, err := BindingExtension(bm)
	if err != nil {
		return nil, err
	}
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: subjectCN}, agentSigner)
	if err != nil {
		return nil, err
	}
	if ttlSeconds <= 0 {
		ttlSeconds = CredentialTTL
	}
	return crypto.SignLeafFromCSRWithProfile(caCertDER, caSigner, csrDER, secondsToDuration(ttlSeconds), crypto.LeafProfile{
		ExtraExtensions: []crypto.CertificateExtension{ext},
	})
}

// secondsToDuration converts an integer second count into a time.Duration.
func secondsToDuration(sec int64) time.Duration { return time.Duration(sec) * time.Second }
