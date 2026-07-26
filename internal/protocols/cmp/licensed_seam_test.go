// SPDX-License-Identifier: MPL-2.0

package cmp_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	cmpsrv "trstctl.com/trstctl/internal/protocols/cmp"
)

// stubEnroller returns a pre-issued leaf and records the CSR it was handed, so a
// seam test can assert exactly which bytes reached the enrollment path.
type stubEnroller struct {
	leafDER []byte
	gotCSR  []byte
}

func (e *stubEnroller) Enroll(_ context.Context, csrDER []byte, _, _, _ string) ([]byte, error) {
	e.gotCSR = append([]byte(nil), csrDER...)
	return e.leafDER, nil
}

// TestCMPCSRVerifierSeamConsulted proves the served CMP path consults the injected
// CSR verifier for the carried PKCS#10 — the same feature-neutral seam EST carries
// for subject algorithms the Go toolchain cannot check — while PKIMessage
// protection verification stays with the core parser. The fixture CSR carries a
// signature the core parser rejects; a custom verifier standing in for the
// licensed parser accepts it, and the exact CSR bytes reach the enroller.
func TestCMPCSRVerifierSeamConsulted(t *testing.T) {
	ca := newRSACA(t)
	clientCert, clientKey, csrDER := newClient(t)

	// A CSR whose proof-of-possession the CORE parser fails: flip one
	// signature byte. The message protection over the PKIMessage body is
	// computed by the client afterwards, so it still verifies.
	opaqueCSR := append([]byte(nil), csrDER...)
	opaqueCSR[len(opaqueCSR)-1] ^= 0x01
	reqDER := buildRequest(t, clientCert, clientKey, opaqueCSR)

	// Without the seam the strict core parser refuses the carried CSR.
	strict := cmpsrv.New(cmpsrv.Config{
		Enroller: &stubEnroller{}, CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
	})
	strictTS := httptest.NewServer(strict)
	defer strictTS.Close()
	resp, err := http.Post(strictTS.URL+"/cmp", "application/pkixcmp", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("strict server status = %d, want 400 (core parser must reject the opaque CSR)", resp.StatusCode)
	}

	// With the seam, the injected verifier owns the carried-CSR check and the
	// exact bytes flow to the enroller.
	goodLeaf, err := crypto.SignLeafFromCSR(ca.certDER, ca.signer, csrDER, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	enroller := &stubEnroller{leafDER: goodLeaf}
	var verified [][]byte
	seam := cmpsrv.New(cmpsrv.Config{
		Enroller: enroller, CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
		CSRVerifier: func(der []byte) error {
			verified = append(verified, append([]byte(nil), der...))
			return nil
		},
	})
	seamTS := httptest.NewServer(seam)
	defer seamTS.Close()
	resp2, err := http.Post(seamTS.URL+"/cmp", "application/pkixcmp", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("seam server status = %d, want 200", resp2.StatusCode)
	}
	replyDER, _ := io.ReadAll(resp2.Body)
	if _, err := crypto.ParseCMPResponse(replyDER); err != nil {
		t.Fatalf("parse CMP response: %v", err)
	}
	if len(verified) != 1 || !bytes.Equal(verified[0], opaqueCSR) {
		t.Fatalf("verifier saw %d CSRs, want exactly the opaque CSR bytes", len(verified))
	}
	if !bytes.Equal(enroller.gotCSR, opaqueCSR) {
		t.Fatal("enroller did not receive the exact opaque CSR bytes")
	}

	// A refusing verifier fails closed.
	refuse := cmpsrv.New(cmpsrv.Config{
		Enroller: &stubEnroller{}, CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
		CSRVerifier: func([]byte) error { return errors.New("refused") },
	})
	refuseTS := httptest.NewServer(refuse)
	defer refuseTS.Close()
	resp3, err := http.Post(refuseTS.URL+"/cmp", "application/pkixcmp", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("refusing verifier status = %d, want 400", resp3.StatusCode)
	}
}

// TestCMPSeamNeverBypassesProtection proves the seam delegates ONLY the carried
// CSR check: a tampered PKIMessage protection still fails closed even when the
// injected verifier accepts everything.
func TestCMPSeamNeverBypassesProtection(t *testing.T) {
	ca := newRSACA(t)
	clientCert, clientKey, csrDER := newClient(t)
	reqDER := buildRequest(t, clientCert, clientKey, csrDER)

	// Flip a byte inside the protected body (the embedded CSR) WITHOUT
	// recomputing the protection, so the signature over header+body no
	// longer verifies.
	tampered := append([]byte(nil), reqDER...)
	idx := bytes.Index(tampered, csrDER)
	if idx < 0 {
		t.Fatal("fixture CSR not found inside the PKIMessage")
	}
	tampered[idx+10] ^= 0x01

	srv := cmpsrv.New(cmpsrv.Config{
		Enroller: &stubEnroller{}, CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
		CSRVerifier: func([]byte) error { return nil },
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/cmp", "application/pkixcmp", bytes.NewReader(tampered))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("tampered protection status = %d, want 400 even with an accepting verifier", resp.StatusCode)
	}
}
