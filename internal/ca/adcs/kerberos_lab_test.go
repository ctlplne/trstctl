// SPDX-License-Identifier: BUSL-1.1

package adcs

import (
	"bytes"
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"

	"trstctl.com/trstctl/internal/crypto/kerberos"
)

// TestLabKDCWebEnrollmentAuthenticatesWithKerberos is A158's AD CS proof
// against a real KDC: the Web Enrollment transport submits and retrieves with
// only a Kerberos Negotiate authenticator built from a keytab (no username or
// password configured), and a stand-in certsrv that verifies tickets with the
// service keytab admits it. It runs only with the lab KDC variables set.
func TestLabKDCWebEnrollmentAuthenticatesWithKerberos(t *testing.T) {
	addr, keytabPath := os.Getenv("TRSTCTL_LAB_KDC_ADDR"), os.Getenv("TRSTCTL_LAB_KDC_KEYTAB")
	user, passwordFile := os.Getenv("TRSTCTL_LAB_KDC_USER"), os.Getenv("TRSTCTL_LAB_KDC_PASSWORD_FILE")
	if addr == "" || keytabPath == "" || user == "" || passwordFile == "" {
		t.Skip("lab KDC not configured")
	}
	password, err := os.ReadFile(passwordFile) // #nosec G304 G703 -- lab password file named by the test environment, never by a request (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	account := keytab.New()
	if err := account.AddEntry(user, "LAB.TEST", strings.TrimSpace(string(password)), time.Now().Add(-time.Hour), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	accountKeytab, err := account.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	serviceKeytab, err := keytab.Load(keytabPath)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := kerberos.NewFromKeytab(serviceKeytab, kerberos.Config{Realm: "LAB.TEST"})
	if err != nil {
		t.Fatal(err)
	}
	issued := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("certificate-der")})
	admitted := 0
	certsrv := httptest.NewServer(svc.Handler(func(w http.ResponseWriter, r *http.Request, id kerberos.Identity) {
		if id.Principal != user+"@LAB.TEST" {
			http.Error(w, "unexpected principal", http.StatusForbidden)
			return
		}
		admitted++
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<a href="certnew.cer?ReqID=42&Enc=b64">certificate</a>`))
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(issued)
	}))
	t.Cleanup(certsrv.Close)

	negotiate, err := kerberos.NewClientAuthenticator(kerberos.ClientConfig{Realm: "LAB.TEST", Principal: user, KDCs: []string{addr}, Keytab: accountKeytab, SPN: "HTTP/localhost"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(negotiate.Destroy)
	transport, err := NewWebEnrollmentTransport(WebEnrollmentConfig{BaseURL: certsrv.URL + "/certsrv", Authenticator: negotiate, HTTPClient: certsrv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := transport.Submit(context.Background(), `HOST\CA`, "WebServer", []byte("csr-der"))
	if err != nil || sub.Disposition != DispUnderSubmission || sub.RequestID != 42 {
		t.Fatalf("Kerberos-authenticated Submit = %+v, %v", sub, err)
	}
	sub, err = transport.RetrievePending(context.Background(), `HOST\CA`, sub.RequestID)
	if err != nil || sub.Disposition != DispIssued || !bytes.Equal(bytes.TrimSpace(sub.CertChainPEM), bytes.TrimSpace(issued)) {
		t.Fatalf("Kerberos-authenticated RetrievePending = %+v, %v", sub, err)
	}
	if admitted != 2 {
		t.Fatalf("certsrv admitted %d Kerberos requests; want 2", admitted)
	}
}
