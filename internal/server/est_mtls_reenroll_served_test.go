// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// EST /simplereenroll on the dedicated mutual-TLS listener authenticates the
// device by the certificate it presents (one this control plane's enrollment
// CA issued) and binds the renewal CSR to that certificate's identifiers. No
// bootstrap token is involved: devices keep nothing but their certificate.
func TestServedESTReenrollAuthenticatesByClientCertificate(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{
		EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})
	token := seedAPIToken(t, h.store, servedTestTenant)
	main := httptest.NewTLSServer(h.srv.Handler())
	t.Cleanup(main.Close)

	// First enrollment with the bootstrap token, as a device does once.
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "device-42.est.test", DNSNames: []string{"device-42.est.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	leafDER := estEnroll(t, main.Client(), main.URL+"/.well-known/est/simpleenroll", token, csrDER, http.StatusOK)
	keyPKCS8, err := key.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := mtls.ClientCertSourceFromDER(leafDER, keyPKCS8)
	if err != nil {
		t.Fatal(err)
	}

	// The mutual-TLS listener, served the way RunESTMTLS serves it.
	sc, err := mtls.SelfSignedServerCert([]string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go h.srv.serveESTMTLS(ctx, ln, sc)
	mtlsURL := "https://" + ln.Addr().String() + "/.well-known/est/simplereenroll"
	clientWith := func(src mtls.ClientCertSource) *http.Client {
		transport, err := mtls.AgentHTTPTransport(src, sc.TrustPEM, "localhost", nil)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Client{Transport: transport}
	}

	// Renewal: same key, same name, authenticated by the certificate alone.
	renewCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "device-42.est.test", DNSNames: []string{"device-42.est.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	renewed := estEnroll(t, clientWith(clientCert), mtlsURL, "", renewCSR, http.StatusOK)
	if bytes.Equal(renewed, leafDER) {
		t.Fatal("re-enrollment returned the original certificate instead of a renewal")
	}
	if err := crypto.VerifyLeafSignedByCA(renewed, h.srv.caCertDER); err != nil {
		t.Fatalf("renewed leaf is not signed by the enrollment CA: %v", err)
	}

	// A CSR for another name under the same certificate is refused: the
	// certificate authenticates exactly the identifiers it carries.
	otherCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "someone-else.est.test", DNSNames: []string{"someone-else.est.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	estEnroll(t, clientWith(clientCert), mtlsURL, "", otherCSR, http.StatusForbidden)

	// No certificate: the listener refuses the handshake before EST starts.
	if _, err := clientWith(nil).Post(mtlsURL, "application/pkcs10", strings.NewReader(base64.StdEncoding.EncodeToString(renewCSR))); err == nil {
		t.Fatal("the mutual-TLS listener accepted a connection without a client certificate")
	}

	// The main listener still asks for a token on re-enrollment and never
	// requests a client certificate, so browsers are not prompted.
	estEnroll(t, main.Client(), main.URL+"/.well-known/est/simplereenroll", "", renewCSR, http.StatusUnauthorized)

	if bin := os.Getenv("EST_LIBEST"); bin != "" {
		dir := t.TempDir()
		certFile := filepath.Join(dir, "device.pem")
		keyFile := filepath.Join(dir, "device.key")
		trustFile := filepath.Join(dir, "trust.pem")
		for path, data := range map[string][]byte{
			certFile:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: renewed}),
			keyFile:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyPKCS8}),
			trustFile: sc.TrustPEM,
		} {
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		outDir := filepath.Join(dir, "out")
		if err := os.MkdirAll(outDir, 0o700); err != nil {
			t.Fatal(err)
		}
		// libest caps at TLS 1.2, so the stock-client proof runs on a listener
		// with the documented TRSTCTL_SERVER_TLS_MIN_VERSION=1.2 opt-in (A7).
		sc12, err := mtls.SelfSignedServerCert([]string{"localhost", "127.0.0.1"}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		sc12.AllowTLS12 = true
		if err := os.WriteFile(trustFile, sc12.TrustPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		ln12, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go h.srv.serveESTMTLS(ctx, ln12, sc12)
		_, port, _ := net.SplitHostPort(ln12.Addr().String())
		cmd := exec.Command(bin, "-r", "-c", certFile, "-k", keyFile, "-x", keyFile, "-s", "127.0.0.1", "-p", port, "-o", outDir, "-v") // #nosec G204 G702 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		cmd.Env = append(os.Environ(), "EST_OPENSSL_CACERT="+trustFile)
		out, runErr := cmd.CombinedOutput()
		p7Path := filepath.Join(outDir, "cert-0-0.pkcs7")
		if _, err := os.Stat(p7Path); err != nil || runErr != nil {
			t.Fatalf("libest re-enrollment by client certificate failed: run=%v p7=%v\n%s", runErr, err, out)
		}
		gotB64, err := os.ReadFile(p7Path) // #nosec G304 -- test reads its own tempdir path (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		der, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(gotB64)))
		if err != nil {
			t.Fatalf("libest wrote a non-base64 PKCS#7: %v", err)
		}
		certs, err := crypto.CertsFromPKCS7(der)
		if err != nil || len(certs) != 1 || crypto.VerifyLeafSignedByCA(certs[0], h.srv.caCertDER) != nil {
			t.Fatalf("libest re-enrollment reply is not one leaf from the enrollment CA: certs=%d err=%v", len(certs), err)
		}
	}
}

// estEnroll posts a PKCS#10 and returns the single certificate from the
// PKCS#7 reply when the status is 200; for any other expected status it
// returns nil.
func estEnroll(t *testing.T, client *http.Client, url, token string, csrDER []byte, want int) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(base64.StdEncoding.EncodeToString(csrDER)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/pkcs10")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("POST %s: status=%d want %d body=%s", url, resp.StatusCode, want, strings.TrimSpace(string(body)))
	}
	if want != http.StatusOK {
		return nil
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		t.Fatalf("EST reply is not base64 PKCS#7: %v", err)
	}
	certs, err := crypto.CertsFromPKCS7(der)
	if err != nil || len(certs) != 1 {
		t.Fatalf("EST reply PKCS#7: certs=%d err=%v", len(certs), err)
	}
	return certs[0]
}
