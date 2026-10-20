// SPDX-License-Identifier: BUSL-1.1

package cmp_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/pqc"
	cmpsrv "trstctl.com/trstctl/internal/protocols/cmp"
	"trstctl.com/trstctl/internal/testutil/openssltest"
)

// A pure ML-DSA PKCS#10 carried in a classically protected p10cr must enroll
// through CMP the way it does through EST: the carried CSR is verified by the
// PQC-aware seam, and the identity binding between the CSR and the protection
// certificate is evaluated on the same parsed names rather than by re-parsing
// the CSR with the core parser, which cannot read an ML-DSA public key.
func TestCMPPureMLDSACSREnrollsUnderClassicalProtection(t *testing.T) {
	ca := newRSACA(t)
	clientCert, clientKey, _ := newClient(t) // CN=device-1 protection identity
	subject, err := pqc.GenerateHostMLDSASubjectKey(crypto.CertificateRequestTemplate{
		CommonName: "device-1", DNSNames: []string{"device-1"},
	}, pqc.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Destroy()
	var enrolled [][]byte
	srv := cmpsrv.New(cmpsrv.Config{
		Enroller: enrollerFunc(func(_ context.Context, csrDER []byte, _, _, _ string) ([]byte, error) {
			enrolled = append(enrolled, csrDER)
			return pqc.SignLicensedLeafFromCSRWithProfile(ca.certDER, ca.signer, csrDER, time.Hour, crypto.LeafProfile{})
		}),
		CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
		CSRVerifier:           pqcAwareVerifier,
		CSRInspector:          pqcAwareInspector,
		ClientTrustAnchorsDER: [][]byte{clientCert},
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	reqDER := buildRequest(t, clientCert, clientKey, subject.CSRDER)
	resp, err := http.Post(ts.URL+"/cmp", "application/pkixcmp", strings.NewReader(string(reqDER)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("CMP p10cr with a pure ML-DSA CSR: status=%d body=%s", resp.StatusCode, body)
	}
	if len(enrolled) != 1 || string(enrolled[0]) != string(subject.CSRDER) {
		t.Fatalf("enroller saw %d CSRs; want the exact carried ML-DSA CSR", len(enrolled))
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

// The same journey with a stock client: OpenSSL generates a pure ML-DSA-65 key
// and PKCS#10, then `openssl cmp -cmd p10cr` carries it under a classical
// protection identity. The issued leaf must be the ML-DSA subject.
func TestCMPOpenSSLClientP10CRPureMLDSA(t *testing.T) {
	ossl := openssltest.RequireCMP(t)
	if out, err := exec.Command(ossl, "list", "-signature-algorithms").CombinedOutput(); err != nil || !bytes.Contains(out, []byte("ML-DSA-65")) { // #nosec G204 -- fixed local tool (CWE-78)
		t.Skip("stock OpenSSL lacks ML-DSA-65")
	}
	ca := newRSACA(t)
	srv := cmpsrv.New(cmpsrv.Config{
		Enroller: enrollerFunc(func(_ context.Context, csrDER []byte, _, _, _ string) ([]byte, error) {
			return pqc.SignLicensedLeafFromCSRWithProfile(ca.certDER, ca.signer, csrDER, time.Hour, crypto.LeafProfile{})
		}),
		CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
		CSRVerifier: pqcAwareVerifier, CSRInspector: pqcAwareInspector,
	})
	srv.AllowUnauthenticatedClientsForTest()
	ts := httptest.NewServer(srv)
	defer ts.Close()
	clientCert, clientKey, _ := newClient(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "mldsa.key")
	csrFile := filepath.Join(dir, "mldsa.csr")
	for _, args := range [][]string{
		{"genpkey", "-algorithm", "ML-DSA-65", "-out", keyFile},
		{"req", "-new", "-key", keyFile, "-subj", "/CN=device-1", "-addext", "subjectAltName=DNS:device-1", "-out", csrFile},
	} {
		if out, err := exec.Command(ossl, args...).CombinedOutput(); err != nil { // #nosec G204 -- fixed local tool and tempdir paths (CWE-78)
			t.Fatalf("openssl %v: %v\n%s", args, err, out)
		}
	}
	caFile := writePEMFile(t, dir, "ca.pem", "CERTIFICATE", ca.certDER)
	clientCertFile := writePEMFile(t, dir, "client.pem", "CERTIFICATE", clientCert)
	clientKeyFile := writePEMFile(t, dir, "client.key", "PRIVATE KEY", clientKey)
	certOut := filepath.Join(dir, "issued.pem")
	cmd := exec.Command(ossl, "cmp", // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		"-config", "", "-cmd", "p10cr", "-server", ts.URL, "-path", "/cmp", "-csr", csrFile,
		"-cert", clientCertFile, "-key", clientKeyFile, "-extracerts", clientCertFile, "-srvcert", caFile,
		"-ignore_keyusage", "-disable_confirm", "-certout", certOut, "-batch")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl cmp p10cr with a pure ML-DSA CSR failed: %v\n%s", err, out)
	}
	issuedPEM, err := os.ReadFile(certOut) // #nosec G304 -- test reads its own tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(issuedPEM)
	if block == nil {
		t.Fatalf("certout is not PEM:\n%s", issuedPEM)
	}
	info, err := certinfo.Inspect(block.Bytes)
	if err != nil {
		t.Fatalf("inspect issued leaf: %v", err)
	}
	if info.KeyAlgorithm != string(pqc.MLDSA65) || info.Subject != "CN=device-1" {
		t.Fatalf("issued leaf = %+v; want an ML-DSA-65 subject for device-1", info)
	}
}
