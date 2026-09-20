// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// FuzzGate_PreconditionDecode fuzzes the untrusted precondition/subject/attestation
// decode path (the bytes an assumed-compromisable control plane ships over the seam). The
// gate must NEVER panic and must NEVER approve on garbage: every fuzz input either yields
// a refusal (Approved=false) or the free single-hop approval (only for a genuinely empty
// gated body), and NEVER a hard error. This guards the fail-closed decode boundary
// (INV-A1) against malformed input.
func FuzzGate_PreconditionDecode(f *testing.F) {
	// Seeds: empty (single-hop), obvious garbage, truncated JSON, a JSON object, a huge
	// nesting, and bytes that look like a chain.
	f.Add([]byte(nil), []byte(nil), []byte(nil))
	f.Add([]byte("{"), []byte("}"), []byte("not-json"))
	f.Add([]byte(`{"chain":[]}`), []byte(`{}`), []byte(`{"method":"tpm"}`))
	f.Add([]byte(`{"chain":[{"record":{}}]}`), []byte(`{"system_prompt_digest":"AA=="}`), []byte(`{"payload":"AAAA"}`))
	f.Add([]byte(`{"designated_class":"x"}`), []byte("\x00\x01\x02"), []byte("\xff\xfe"))

	// A gate over an empty trust store and no attestor: fuzz can never satisfy the
	// root-anchor or attestation checks, so nothing untrusted should be approved unless
	// it is the genuinely empty single-hop path.
	gate, err := NewGate(Config{
		SignerID:      "fuzz-signer",
		Roots:         NewTrustStore(nil),
		RefusalSigner: fuzzRefusalSigner(f),
		Revocations:   NeverRevoked{},
	})
	if err != nil {
		f.Fatalf("NewGate: %v", err)
	}

	f.Fuzz(func(t *testing.T, pre, repr, att []byte) {
		req := signing.IssuancePreconditions{
			TenantID:       "t1",
			TrustAnchorRef: "subj",
			Preconditions:  pre,
			SubjectRepr:    repr,
			Attestation:    att,
		}
		dec, err := gate.VerifyIssuancePreconditions(backgroundCtx(), req)
		if err != nil {
			t.Fatalf("gate returned a hard error on fuzz input (must fail closed with a decision): %v", err)
		}
		if dec.Approved {
			// The only approvable fuzz input is the empty single-hop path: no chain, no
			// designated class, no attestation, no subject repr.
			if !isUngatedSingleHop(req) {
				t.Fatalf("gate APPROVED a non-empty gated fuzz input (pre=%q repr=%q att=%q)", pre, repr, att)
			}
			// A single-hop approval must carry no binding (nothing was verified to bind).
			if len(dec.BindingMaterial) != 0 {
				t.Fatalf("single-hop approval carried binding material %q", dec.BindingMaterial)
			}
		}
	})
}

// fuzzRefusalSigner builds a software refusal signer for the fuzz gate.
func fuzzRefusalSigner(f *testing.F) crypto.Signer {
	be := crypto.NewSoftwareBackend()
	s, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		f.Fatalf("generate refusal key: %v", err)
	}
	return s
}
