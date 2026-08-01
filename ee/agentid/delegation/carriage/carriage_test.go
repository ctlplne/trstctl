// SPDX-License-Identifier: LicenseRef-trstctl-EE

package carriage_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/agentid/delegation"
	"trstctl.com/trstctl/ee/agentid/delegation/carriage"
	"trstctl.com/trstctl/internal/crypto"
)

// boundFromBinding projects the AGID-04 binding material (the AUTHORITATIVE bound values
// the signer produced) into the carriage package's BoundValues. It copies field-for-field
// so the test proves the carriage forms carry exactly what AGID-04 bound -- if the two
// structs ever diverge this projection (and thus the byte-equality assertions) breaks.
func boundFromBinding(bm delegation.BindingMaterial) carriage.BoundValues {
	return carriage.BoundValues{
		ChainHeadDigest:    bm.ChainHeadDigest,
		AgentStackDigest:   bm.AgentStackDigest,
		AgentStackRepr:     bm.AgentStackRepr,
		DesignatedClass:    bm.DesignatedClass,
		AttestationDigest:  bm.AttestationDigest,
		ComparatorVersion:  bm.ComparatorVersion,
		RootAnchorAuthRef:  bm.RootAnchorAuthRef,
		TaskEnvelopeDigest: bm.TaskEnvelopeDigest,
	}
}

// bindingCase is one AGID-04-bound triple (chain-head digest, agent-stack representation,
// optional task-envelope digest) built through delegation.NewBindingMaterial -- the same
// constructor the signer uses -- so the carriage tests operate on genuine bound values,
// not hand-rolled structs.
type bindingCase struct {
	name string
	bm   delegation.BindingMaterial
}

// mustBinding builds binding material or fails the test.
func mustBinding(t *testing.T, chainHead, repr []byte, class string, att []byte, authRef string, taskEnv []byte) delegation.BindingMaterial {
	t.Helper()
	bm, err := delegation.NewBindingMaterial(chainHead, repr, class, att, authRef, taskEnv)
	if err != nil {
		t.Fatalf("NewBindingMaterial: %v", err)
	}
	return bm
}

// bindingCases returns the bound triples the carriage tests exercise: a full binding
// (chain head + agent-stack repr + task envelope), a chain-only binding (no repr, no
// envelope -- AGID-claim-31 fallback), and an agent-stack-only binding (no chain head -- claim
// 32 fallback). Each is a real NewBindingMaterial output.
func bindingCases(t *testing.T) []bindingCase {
	t.Helper()
	// A realistic opaque agent-stack representation: a small JSON blob standing in for the
	// AGID-03 canonical bytes the control plane ships over the seam. Carriage treats it as
	// opaque, so any bytes exercise the transport.
	repr, err := json.Marshal(map[string]any{
		"system_prompt_digest": "cHJvbXB0",
		"tool_manifest_digest": "dG9vbHM",
		"model":                map[string]any{"form": 1, "provider_model_id": "m", "model_version": "v1"},
	})
	if err != nil {
		t.Fatalf("marshal repr: %v", err)
	}
	chainHead := bytes.Repeat([]byte{0xA1}, 32)
	att := bytes.Repeat([]byte{0xB2}, 32)
	taskEnv := bytes.Repeat([]byte{0xC3}, 32)
	return []bindingCase{
		{"full", mustBinding(t, chainHead, repr, "class-a", att, "fido2:root", taskEnv)},
		{"chain-only", mustBinding(t, chainHead, nil, "", nil, "", nil)},
		{"agent-stack-only", mustBinding(t, nil, repr, "class-b", nil, "webauthn:root", nil)},
	}
}

// eqBytes reports byte-equality treating nil and empty as equal (a decoded empty digest
// may come back as nil).
func eqBytes(a, b []byte) bool { return bytes.Equal(a, b) }

// assertCarriedEqualsBound asserts every carried field equals the AGID-04 bound field
// byte-for-byte (AGID-claim-27 / INV-A3): the carriage is a faithful transport, so decode(form)
// reproduces exactly what the signer bound.
func assertCarriedEqualsBound(t *testing.T, form string, got carriage.BoundValues, bm delegation.BindingMaterial) {
	t.Helper()
	if !eqBytes(got.ChainHeadDigest, bm.ChainHeadDigest) {
		t.Fatalf("%s: chain-head digest = %x, want bound %x", form, got.ChainHeadDigest, bm.ChainHeadDigest)
	}
	if !eqBytes(got.AgentStackDigest, bm.AgentStackDigest) {
		t.Fatalf("%s: agent-stack digest = %x, want bound %x", form, got.AgentStackDigest, bm.AgentStackDigest)
	}
	if !eqBytes(got.AgentStackRepr, bm.AgentStackRepr) {
		t.Fatalf("%s: agent-stack repr = %x, want bound %x", form, got.AgentStackRepr, bm.AgentStackRepr)
	}
	if got.DesignatedClass != bm.DesignatedClass {
		t.Fatalf("%s: designated class = %q, want bound %q", form, got.DesignatedClass, bm.DesignatedClass)
	}
	if !eqBytes(got.AttestationDigest, bm.AttestationDigest) {
		t.Fatalf("%s: attestation digest = %x, want bound %x", form, got.AttestationDigest, bm.AttestationDigest)
	}
	if got.ComparatorVersion != bm.ComparatorVersion {
		t.Fatalf("%s: comparator version = %q, want bound %q", form, got.ComparatorVersion, bm.ComparatorVersion)
	}
	if got.RootAnchorAuthRef != bm.RootAnchorAuthRef {
		t.Fatalf("%s: root-anchor auth ref = %q, want bound %q", form, got.RootAnchorAuthRef, bm.RootAnchorAuthRef)
	}
	if !eqBytes(got.TaskEnvelopeDigest, bm.TaskEnvelopeDigest) {
		t.Fatalf("%s: task-envelope digest = %x, want bound %x", form, got.TaskEnvelopeDigest, bm.TaskEnvelopeDigest)
	}
}

// TestCarriage_X509_WorkloadDoc_Token is the canonical carriage test (AGID-claim-27 / INV-A3
// carriage half). For each of the three interchangeable forms -- X.509 non-critical
// extension, workload-identity document, signed token -- it encodes a KNOWN
// (chain-head digest, agent-stack representation, optional task-envelope digest) triple
// that the signer bound in AGID-04, decodes it back, and asserts BYTE-EQUALITY with the
// bound values. For the X.509 form it additionally asserts the extension is NON-CRITICAL
// and that the same bound values survive a round trip through a REAL minted certificate
// (stamped and read back through the internal/crypto boundary). Every form's carried
// digests equal exactly the values AGID-04 bound.
func TestCarriage_X509_WorkloadDoc_Token(t *testing.T) {
	// A signer for the credential forms that require one (a real minted X.509 leaf; a
	// signed JWT). LockedSigner is a DigestSigner (its private key is memory-locked, as in
	// the isolated signer). Only the signature routes through internal/crypto (AN-3).
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	defer caKey.Destroy()
	caDER, err := crypto.SelfSignedCACert(caKey, "AGID Carriage Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("SelfSignedCACert: %v", err)
	}

	for _, bc := range bindingCases(t) {
		bc := bc
		bv := boundFromBinding(bc.bm)

		t.Run(bc.name+"/x509", func(t *testing.T) {
			// The AGID extension the carriage encoder produces.
			ext, err := carriage.Extension(bv)
			if err != nil {
				t.Fatalf("Extension: %v", err)
			}
			// The X.509 extension MUST be non-critical (a legacy relying party still parses
			// the certificate).
			if ext.Critical {
				t.Fatal("AGID x509 carriage extension is critical; it must be NON-CRITICAL")
			}
			if ext.OID != carriage.AGIDCarriageOIDString {
				t.Fatalf("extension OID = %q, want %q", ext.OID, carriage.AGIDCarriageOIDString)
			}
			// Round-trip 1: decode straight from the backend-agnostic extension.
			gotExt, err := carriage.DecodeExtension(ext)
			if err != nil {
				t.Fatalf("DecodeExtension: %v", err)
			}
			assertCarriedEqualsBound(t, "x509-ext", gotExt, bc.bm)

			// Round-trip 2: stamp the extension onto a REAL leaf certificate via the crypto
			// boundary, then decode it back out of the certificate DER.
			leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
			if err != nil {
				t.Fatalf("leaf key: %v", err)
			}
			defer leafKey.Destroy()
			csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "agent.leaf"}, leafKey)
			if err != nil {
				t.Fatalf("CSR: %v", err)
			}
			leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, time.Hour, crypto.LeafProfile{
				ExtraExtensions: []crypto.CertificateExtension{ext},
			})
			if err != nil {
				t.Fatalf("SignLeafFromCSRWithProfile: %v", err)
			}
			// Sanity: the minted leaf actually chains to the CA (carriage never breaks the
			// credential the issuer produced).
			if err := crypto.VerifyLeafSignedByCA(leafDER, caDER); err != nil {
				t.Fatalf("minted leaf does not verify against CA: %v", err)
			}
			gotCert, err := carriage.DecodeCertificate(leafDER)
			if err != nil {
				t.Fatalf("DecodeCertificate: %v", err)
			}
			assertCarriedEqualsBound(t, "x509-cert", gotCert, bc.bm)
		})

		t.Run(bc.name+"/workload-doc", func(t *testing.T) {
			doc, err := carriage.EncodeWorkloadDoc(bv, "spiffe://agent", "rp", "issuer")
			if err != nil {
				t.Fatalf("EncodeWorkloadDoc: %v", err)
			}
			got, err := carriage.DecodeWorkloadDoc(doc)
			if err != nil {
				t.Fatalf("DecodeWorkloadDoc: %v", err)
			}
			assertCarriedEqualsBound(t, "workload-doc", got, bc.bm)
		})

		t.Run(bc.name+"/token", func(t *testing.T) {
			tok, err := carriage.EncodeSignedToken(caKey, "kid-1", bv, "spiffe://agent", "rp", "issuer")
			if err != nil {
				t.Fatalf("EncodeSignedToken: %v", err)
			}
			// Pure carriage decode (claims only): byte-equality with the bound values.
			gotClaims, err := carriage.DecodeToken([]byte(tok))
			if err != nil {
				t.Fatalf("DecodeToken: %v", err)
			}
			assertCarriedEqualsBound(t, "token-claims", gotClaims, bc.bm)

			// Verified decode: the signature verifies through internal/crypto (AN-3) and
			// the recovered bound values still equal what AGID-04 bound.
			jwk, err := crypto.PublicJWK(caKey.Public(), "kid-1")
			if err != nil {
				t.Fatalf("PublicJWK: %v", err)
			}
			gotVerified, err := carriage.DecodeVerifiedToken(tok, crypto.JWKS{Keys: []crypto.JWK{jwk}})
			if err != nil {
				t.Fatalf("DecodeVerifiedToken: %v", err)
			}
			assertCarriedEqualsBound(t, "token-verified", gotVerified, bc.bm)
		})
	}
}

// TestCarriage_CrossForm_CommonDecoder proves the cross-form property: the SAME bound
// values encoded into all three forms are read IDENTICALLY by the common Decoder helper.
// A single relying-party path (AGID-09) can thus consume any of the three carriages and
// obtain the same bound values (AGID-claim-27 / INV-A3).
func TestCarriage_CrossForm_CommonDecoder(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	defer caKey.Destroy()
	caDER, err := crypto.SelfSignedCACert(caKey, "AGID CrossForm CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("SelfSignedCACert: %v", err)
	}

	bm := mustBinding(t,
		bytes.Repeat([]byte{0x11}, 32),
		[]byte(`{"opaque":"agent-stack-bytes"}`),
		"class-x",
		bytes.Repeat([]byte{0x22}, 32),
		"fido2:root",
		bytes.Repeat([]byte{0x33}, 32),
	)
	bv := boundFromBinding(bm)

	// Build one carriage per form.
	ext, err := carriage.Extension(bv)
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	defer leafKey.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "agent.leaf"}, leafKey)
	if err != nil {
		t.Fatalf("CSR: %v", err)
	}
	certForm, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, time.Hour, crypto.LeafProfile{
		ExtraExtensions: []crypto.CertificateExtension{ext},
	})
	if err != nil {
		t.Fatalf("mint leaf: %v", err)
	}
	docForm, err := carriage.EncodeWorkloadDoc(bv, "sub", "aud", "iss")
	if err != nil {
		t.Fatalf("EncodeWorkloadDoc: %v", err)
	}
	tokForm, err := carriage.EncodeSignedToken(caKey, "kid-1", bv, "sub", "aud", "iss")
	if err != nil {
		t.Fatalf("EncodeSignedToken: %v", err)
	}

	// The common Decoder set, keyed by kind, each reading its matching form.
	forms := map[string][]byte{
		"x509":              certForm,
		"workload-identity": docForm,
		"signed-token":      []byte(tokForm),
	}
	var first *carriage.BoundValues
	var firstDigest []byte
	for _, dec := range carriage.Decoders() {
		form, ok := forms[dec.Kind()]
		if !ok {
			t.Fatalf("no form for decoder kind %q", dec.Kind())
		}
		got, err := dec.Decode(form)
		if err != nil {
			t.Fatalf("%s decode: %v", dec.Kind(), err)
		}
		// Each form independently reproduces the bound values.
		assertCarriedEqualsBound(t, dec.Kind(), got, bm)
		// And all three read to the identical BoundValues (structural + digest identity).
		if first == nil {
			g := got
			first = &g
			firstDigest = got.CarriageDigest()
			continue
		}
		if !reflect.DeepEqual(*first, got) {
			t.Fatalf("%s decoded BoundValues differ from the first form", dec.Kind())
		}
		if !bytes.Equal(firstDigest, got.CarriageDigest()) {
			t.Fatalf("%s carriage digest differs from the first form", dec.Kind())
		}
	}
}

// TestCarriage_CanonicalBytesMatchBinding pins the carriage canonical framing to the
// AGID-04 binding framing: BoundValues.CanonicalBytes must equal
// BindingMaterial.CanonicalBytes for the same bound values, so the carriage-integrity
// digest is the same preimage the signer bound. If the binding layout changes and this
// mirror is not updated, this test fails -- catching silent drift between the bound bytes
// and the carried bytes.
func TestCarriage_CanonicalBytesMatchBinding(t *testing.T) {
	for _, bc := range bindingCases(t) {
		bv := boundFromBinding(bc.bm)
		wantCB, err := bc.bm.CanonicalBytes()
		if err != nil {
			t.Fatalf("%s: binding CanonicalBytes: %v", bc.name, err)
		}
		gotCB := bv.CanonicalBytes()
		if !bytes.Equal(gotCB, wantCB) {
			t.Fatalf("%s: carriage CanonicalBytes != binding CanonicalBytes\n got=%x\nwant=%x", bc.name, gotCB, wantCB)
		}
		wantDigest, err := bc.bm.Digest()
		if err != nil {
			t.Fatalf("%s: binding Digest: %v", bc.name, err)
		}
		if !bytes.Equal(bv.CarriageDigest(), wantDigest) {
			t.Fatalf("%s: carriage digest != binding digest", bc.name)
		}
	}
}
