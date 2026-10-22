// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/postgresql"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

// A60: the PostgreSQL connector's proof used to be sandboxed file and process
// operations alone. This drives it against the pinned bundled PostgreSQL
// runtime started with ssl=on: the server serves the first certificate, the
// connector replaces the files through real local ops and runs the allowlisted
// pg_ctl reload, and a real SSLRequest handshake then sees the renewed
// certificate. No external or customer PostgreSQL is involved, and the support
// row says exactly that.
func TestPostgreSQLConnectorReloadServesTheRenewedCertificateOnTheBundledServer(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	h := newOperatingServedHarness(t, config.Protocols{})
	firstCert, firstKey := servedNativeDeployCredential(t, h, "pg-live-first.served.test")
	defer secret.Wipe(firstKey)
	renewedCert, renewedKey := servedNativeDeployCredential(t, h, "pg-live-renewed.served.test")
	defer secret.Wipe(renewedKey)

	root := t.TempDir()
	tlsDir := filepath.Join(root, "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(tlsDir, "server.crt")
	keyPath := filepath.Join(tlsDir, "server.key")
	if err := os.WriteFile(certPath, firstCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, firstKey, 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(root, "pg")
	port := freeTCPPort(t)
	_, binaries, stop, err := startBundledPostgresWith(config.Postgres{Mode: config.PostgresBundled, DataDir: dataDir, Port: port},
		map[string]string{"ssl": "on", "ssl_cert_file": certPath, "ssl_key_file": keyPath})
	if err != nil {
		t.Fatalf("start bundled postgres with TLS: %v", err)
	}
	defer func() {
		if err := stop(); err != nil {
			t.Errorf("stop bundled postgres: %v", err)
		}
	}()
	addr := "127.0.0.1:" + strconv.Itoa(port)
	served := func() string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		result, err := tlsprobe.ProbeWithNativeFallback(ctx, "", addr,
			tlsprobe.WithPreHandshake(tlsprobe.PostgresSSLRequest), tlsprobe.WithTimeout(10*time.Second))
		if err != nil {
			t.Fatalf("SSLRequest handshake with the bundled server: %v", err)
		}
		if len(result.PeerCertificates) == 0 {
			t.Fatal("the bundled server presented no certificate")
		}
		return connector.CertificateFingerprint(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: result.PeerCertificates[0]}))
	}
	if got, want := served(), connector.CertificateFingerprint(firstCert); got != want {
		t.Fatalf("before the deploy the server serves %s, want the first certificate %s", got, want)
	}

	// The operator profile pins the exact reload the connector may run: this
	// runtime's pg_ctl against this data directory, nothing else.
	ops, err := connector.NewLocalOps(connector.LocalOpsConfig{
		AllowedRoots: []string{tlsDir},
		Actions: []connector.LocalAction{{
			LogicalName: "pg_ctl", LogicalArgs: []string{"reload"},
			Command: filepath.Join(binaries, "bin", "pg_ctl"),
			Args:    []string{"reload", "-s", "-D", filepath.Join(dataDir, "db")},
			Timeout: 30 * time.Second,
		}},
	})
	if err != nil {
		t.Fatalf("local ops: %v", err)
	}
	dep := connector.NewDeployment("postgresql", renewedCert, renewedKey)
	if _, err := connector.Run(context.Background(), postgresql.New(certPath, keyPath), ops, dep); err != nil {
		t.Fatalf("deploy renewed certificate: %v", err)
	}
	if got, want := served(), connector.CertificateFingerprint(renewedCert); got != want {
		t.Fatalf("after the reload the server serves %s, want the renewed certificate %s", got, want)
	}
	// Idempotent: the same material again neither rewrites nor reloads.
	if _, err := connector.Run(context.Background(), postgresql.New(certPath, keyPath), ops, dep); err != nil {
		t.Fatalf("redeploy: %v", err)
	}
	if got, want := served(), connector.CertificateFingerprint(renewedCert); got != want {
		t.Fatalf("after the redeploy the server serves %s, want the renewed certificate %s", got, want)
	}
}
