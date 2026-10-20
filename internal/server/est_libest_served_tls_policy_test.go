// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// The conformance proof for cisco libest used to run against a Go test server
// that still negotiated TLS 1.2 on its own. This drives the stock estclient
// against the control plane's own listener policy (mtls.ServerCert.ServeHTTPS,
// the code serveControlPlane runs): the TLS 1.3-only default must refuse the
// handshake, and the documented TRSTCTL_SERVER_TLS_MIN_VERSION=1.2 opt-in must
// enroll.
func TestServedESTLibestAgainstServedTLSPolicy(t *testing.T) {
	bin := os.Getenv("EST_LIBEST")
	if bin == "" {
		if os.Getenv("TRSTCTL_REQUIRE_LIBEST") == "1" || os.Getenv("TRSTCTL_REQUIRE_ESTCLIENT") == "1" {
			t.Fatal("EST_LIBEST is not set; CI must provide the pinned libest estclient")
		}
		t.Skip("EST_LIBEST not set; set TRSTCTL_REQUIRE_LIBEST=1 in CI to make libest mandatory")
	}
	h := newOperatingServedHarness(t, config.Protocols{
		EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})
	token := seedAPIToken(t, h.store, servedTestTenant)
	for _, tc := range []struct {
		name       string
		allowTLS12 bool
		wantEnroll bool
	}{
		{"tls13-only default refuses a TLS 1.2 client", false, false},
		{"min_version=1.2 opt-in enrolls", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc, err := mtls.SelfSignedServerCert([]string{"localhost", "127.0.0.1"}, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			sc.AllowTLS12 = tc.allowTLS12
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			srv := &http.Server{Handler: h.srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
			go func() { _ = sc.ServeHTTPS(srv, ln) }()
			t.Cleanup(func() { _ = srv.Close() })
			dir := t.TempDir()
			caFile := filepath.Join(dir, "served-https-trust.pem")
			if err := os.WriteFile(caFile, sc.TrustPEM, 0o600); err != nil {
				t.Fatal(err)
			}
			_, port, _ := net.SplitHostPort(ln.Addr().String())
			outDir := filepath.Join(dir, "out")
			if err := os.MkdirAll(outDir, 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(bin, // #nosec G204 G702 -- test executes a fixed local tool or fixture it built itself (CWE-78)
				"-e", "-s", "127.0.0.1", "-p", port, "-o", outDir,
				"--auth-token", token, "--common-name", "libest-served-policy-device", "-v")
			cmd.Env = append(os.Environ(), "EST_OPENSSL_CACERT="+caFile)
			out, runErr := cmd.CombinedOutput()
			safeOut := bytes.ReplaceAll(out, []byte(token), []byte("[REDACTED]"))
			safeOut = bytes.ReplaceAll(safeOut, []byte(base64.StdEncoding.EncodeToString([]byte(token))), []byte("[REDACTED]"))
			if !bytes.Equal(out, safeOut) {
				t.Fatal("libest output attempted to expose the Bearer credential; use the checksum-pinned redacted build")
			}
			p7Path := filepath.Join(outDir, "cert-0-0.pkcs7")
			_, p7Err := os.Stat(p7Path)
			if tc.wantEnroll {
				if runErr != nil || p7Err != nil {
					t.Fatalf("libest against the served TLS 1.2 opt-in listener: err=%v p7=%v\n%s", runErr, p7Err, safeOut)
				}
				return
			}
			if runErr == nil && p7Err == nil {
				t.Fatalf("libest enrolled against the TLS 1.3-only listener; the served default is supposed to refuse a TLS 1.2-capped client\n%s", safeOut)
			}
			if !strings.Contains(strings.ToLower(string(safeOut)), "ssl") && !strings.Contains(strings.ToLower(string(safeOut)), "tls") {
				t.Logf("libest refusal output did not name TLS; recorded for the ledger:\n%s", safeOut)
			}
			_ = strconv.Itoa
		})
	}
}
