// SPDX-License-Identifier: LicenseRef-trstctl-EE

package agentstack

import (
	"bytes"
	"sort"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
)

// digest.go holds the canonical digesting of the environment-attestation
// evidence that the agent-stack representation is bound against. The attestation
// itself is produced and VERIFIED by the existing core internal/attest pipeline
// (S11.2, F30) — a hardware/cloud/platform proof turned into a verified
// attest.Attestation. This package CONSUMES that verified result READ-ONLY (§1.6
// zero-removal — internal/attest is never modified or forked here) and computes a
// stable, canonical digest of it, so the digest can be carried alongside the
// prompt/tool/model digests and bound into the credential by the signer (AGID-04).
//
// This file performs no verification of its own and no key operation: it does not
// decide whether an attestation is genuine (that is internal/attest's job); it
// only digests an already-verified attestation deterministically.

// attestationDigestDomain domain-separates the environment-attestation digest
// from the prompt/tool/model digests so the three can never collide.
const attestationDigestDomain = "agid/agentstack/env-attestation/v1"

// AttestationDigest returns a canonical, byte-stable digest of a verified
// environment attestation, routed through the internal/crypto AN-3 boundary. The
// same attestation — regardless of the map iteration order of its Claims or the
// order of its Selectors — produces identical bytes and therefore an identical
// digest, so the environment-attestation evidence contributes a reproducible
// value to the bound representation. Any change to the attested method, subject,
// selectors, or claims flips the digest.
//
// The input MUST be an attestation already verified by internal/attest; this
// function neither re-verifies nor mutates it (read-only consumption). It
// performs no key operation.
func AttestationDigest(att attest.Attestation) []byte {
	var b bytes.Buffer
	b.WriteString(attestationDigestDomain)
	writeField(&b, "id")
	writeStr(&b, att.ID)
	writeField(&b, "method")
	writeStr(&b, att.Method)
	writeField(&b, "subject")
	writeStr(&b, att.Subject)

	// selectors: sorted so ordering does not change the digest.
	selectors := append([]string(nil), att.Selectors...)
	sort.Strings(selectors)
	writeField(&b, "selectors")
	writeU64(&b, uint64(len(selectors)))
	for _, s := range selectors {
		writeStr(&b, s)
	}

	// claims: sorted by key so map iteration order does not change the digest.
	keys := make([]string, 0, len(att.Claims))
	for k := range att.Claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeField(&b, "claims")
	writeU64(&b, uint64(len(keys)))
	for _, k := range keys {
		writeStr(&b, k)
		writeStr(&b, att.Claims[k])
	}
	return crypto.SHA256Sum(b.Bytes())
}
