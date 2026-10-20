// SPDX-License-Identifier: BUSL-1.1

package scep_test

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
	"trstctl.com/trstctl/internal/pqc"
	"trstctl.com/trstctl/internal/protocols/scep"
)

// A SCEP client's CMS transport identity (its self-signed RSA certificate) is
// separate from the subject key in its PKCS#10. A pure ML-DSA request enveloped
// to the RA under an RSA transport identity must therefore enroll: the inner
// CSR is verified and inspected through the PQC-aware seam, the leaf is issued
// for the ML-DSA subject, and the CertRep is enveloped back to the RSA
// transport certificate exactly as for a classical request.
func TestSCEPPureMLDSACSREnrollsUnderRSATransport(t *testing.T) {
	ca := newRSACA(t)
	var enrolled [][]byte
	srv := scep.New(scep.Config{
		Enroller: enrollerFunc(func(_ context.Context, csrDER []byte, _, _, _ string) ([]byte, error) {
			enrolled = append(enrolled, csrDER)
			return pqc.SignLicensedLeafFromCSRWithProfile(ca.certDER, ca.signer, csrDER, time.Hour, crypto.LeafProfile{})
		}),
		CAChainDER: [][]byte{ca.certDER}, RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
		CSRVerifier: pqcAwareVerifier, CSRInspector: pqcAwareInspector,
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	clientCert, clientKey, _ := newClient(t) // RSA transport identity, CN=device-1
	subject, err := pqc.GenerateHostMLDSASubjectKey(crypto.CertificateRequestTemplate{
		CommonName: "device-1", DNSNames: []string{"device-1"},
	}, pqc.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Destroy()
	reqDER, err := crypto.BuildSCEPRequest(subject.CSRDER, clientCert, clientKey, ca.certDER, "txn-mldsa-1")
	if err != nil {
		t.Fatalf("build SCEP request: %v", err)
	}
	resp, err := http.Post(ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PKIOperation with a pure ML-DSA CSR: status %d", resp.StatusCode)
	}
	replyDER, _ := io.ReadAll(resp.Body)
	issued, err := crypto.ParseSCEPResponse(replyDER, clientCert, clientKey)
	if err != nil {
		t.Fatalf("parse SCEP CertRep: %v", err)
	}
	if len(enrolled) != 1 || !bytes.Equal(enrolled[0], subject.CSRDER) {
		t.Fatalf("enroller saw %d CSRs; want the exact enveloped ML-DSA CSR", len(enrolled))
	}
	info, recognized, err := pqc.ParsePureMLDSACSR(subject.CSRDER)
	if err != nil || !recognized || info.KeyAlgorithm != string(pqc.MLDSA65) {
		t.Fatalf("fixture CSR is not a recognized pure ML-DSA request: %+v %v %v", info, recognized, err)
	}
	if len(issued) == 0 {
		t.Fatal("CertRep carried no certificate")
	}
}

func pqcAwareVerifier(csrDER []byte) error {
	_, err := pqcAwareInspector(csrDER)
	return err
}

func pqcAwareInspector(csrDER []byte) (crypto.CSRInfo, error) {
	info, coreErr := crypto.InspectCSR(csrDER)
	if coreErr == nil {
		return info, nil
	}
	pure, recognized, err := pqc.ParsePureMLDSACSR(csrDER)
	if err != nil {
		return crypto.CSRInfo{}, err
	}
	if recognized {
		return pure, nil
	}
	return crypto.CSRInfo{}, errors.Join(coreErr, errors.New("csr: not a recognized post-quantum request"))
}

type enrollerFunc func(context.Context, []byte, string, string, string) ([]byte, error)

func (f enrollerFunc) Enroll(ctx context.Context, csrDER []byte, profile, protocol, key string) ([]byte, error) {
	return f(ctx, csrDER, profile, protocol, key)
}
