// SPDX-License-Identifier: LicenseRef-trstctl-EE

package verify

import (
	"testing"
	"time"

	"trstctl.com/trstctl/ee/agentid/delegation/carriage"
	"trstctl.com/trstctl/ee/agentid/taskenv"
	"trstctl.com/trstctl/internal/crypto"
)

// harness_test.go builds real X.509 and workload-identity credentials and real
// task envelopes for the tests, using only the crypto boundary + carriage
// encoders, so every case exercises the genuine offline verify path.

// x509Cred mints a real leaf certificate carrying the AGID carriage extension,
// signed by a fresh CA, with the CA pinned as the trust root. The certificate's
// own NotBefore/NotAfter (ttl) is the credential's short-TTL window.
func x509Cred(t *testing.T, bv carriage.BoundValues, ttl time.Duration) (Credential, TrustRoot) {
	t.Helper()
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "AGID Test CA", ttl)
	if err != nil {
		t.Fatalf("SelfSignedCACert: %v", err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	t.Cleanup(leafKey.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "agent.leaf"}, leafKey)
	if err != nil {
		t.Fatalf("CSR: %v", err)
	}
	ext, err := carriage.Extension(bv)
	if err != nil {
		t.Fatalf("carriage.Extension: %v", err)
	}
	leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, ttl, crypto.LeafProfile{
		ExtraExtensions: []crypto.CertificateExtension{ext},
	})
	if err != nil {
		t.Fatalf("mint leaf: %v", err)
	}
	return Credential{Form: FormX509, Bytes: leafDER}, TrustRoot{CACertDER: caDER}
}

// workloadCred builds a real workload-identity document carrying bv plus nbf/exp
// standard claims, and a detached issuer signature over the document bytes, with
// the issuer public key pinned as the trust root.
func workloadCred(t *testing.T, bv carriage.BoundValues, nbf, exp int64) (Credential, TrustRoot) {
	t.Helper()
	issuer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	t.Cleanup(issuer.Destroy)
	docJSON := workloadDocWithValidity(t, bv, nbf, exp)
	sig, err := crypto.SignMessage(issuer, docJSON)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	return Credential{Form: FormWorkloadIdentity, Bytes: docJSON, Signature: sig},
		TrustRoot{IssuerPublicDER: issuer.Public().DER}
}

// workloadDocWithValidity builds a workload-identity document JSON carrying the
// AGID binding claim (via carriage) plus nbf/exp standard claims, by encoding a
// carriage workload doc and splicing in the validity claims (the carriage decoder
// ignores sibling claims; windowFromStandardClaims reads nbf/exp).
func workloadDocWithValidity(t *testing.T, bv carriage.BoundValues, nbf, exp int64) []byte {
	t.Helper()
	// Start from the carriage-encoded doc so the binding claim is byte-faithful.
	base, err := carriage.EncodeWorkloadDoc(bv, "spiffe://agent", "aud", "iss")
	if err != nil {
		t.Fatalf("EncodeWorkloadDoc: %v", err)
	}
	// Splice nbf/exp into the JSON object.
	return spliceValidity(t, base, nbf, exp)
}

// buildTaskEnvelope builds a signed AGID-05 task envelope with the given
// commitments (used to bind + enforce task scope). The signature is not verified
// by the RP verifier (task-scope enforcement uses the envelope DIGEST, which the
// RP recomputes), but a well-formed intent is required so Digest is meaningful.
func buildTaskEnvelope(t *testing.T, commitments []taskenv.Commitment) taskenv.Envelope {
	t.Helper()
	env := taskenv.Envelope{
		RequesterID:  "requester-1",
		RequesterKey: taskenv.KeyRef{ID: "rk-1", Algorithm: "ECDSA-P256"},
		Task: taskenv.TaskIntent{
			Description:      "sample task",
			InputCommitments: commitments,
		},
		Expiry: taskenv.Window{NotBefore: 0, NotAfter: 0},
	}
	if err := env.Validate(); err != nil {
		t.Fatalf("envelope validate: %v", err)
	}
	return env
}
