// SPDX-License-Identifier: BUSL-1.1

package pqc

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

func writePreparedPQCLeafFixtures(t *testing.T, leaf, ca []byte) (string, string) {
	t.Helper()
	dir := t.TempDir()
	leafPath := filepath.Join(dir, "leaf.pem")
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(leafPath, leaf, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca, 0600); err != nil {
		t.Fatal(err)
	}
	return leafPath, caPath
}

// This handshake intentionally uses classical X25519 key exchange. Success
// establishes ML-DSA certificate authentication independently of hybrid KEX;
// it is a local stock-client proof, not an installed connector qualification.
func checkPreparedPQCTLS(t *testing.T, openssl string, key *HostMLDSASubjectKey, certificatePath, caPath string) {
	t.Helper()
	material, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(material)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, material, 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	logPath := filepath.Join(dir, "server.log")
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304 -- fixed server.log filename in this test's private TempDir; no user path.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	server := exec.CommandContext(ctx, openssl, "s_server", "-accept", address, "-cert", certificatePath, "-key", keyPath, "-www", "-tls1_3", "-groups", "X25519") // #nosec G204 -- LookPath-resolved OpenSSL, fixed verbs, loopback and TempDir artifacts.
	server.Stdout = log
	server.Stderr = log
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Process.Kill(); _ = server.Wait() }()
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			ready = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatal("stock OpenSSL listener did not start")
	}
	client := exec.CommandContext(ctx, openssl, "s_client", "-connect", address, "-servername", "api.example.test", "-verify_hostname", "api.example.test", "-CAfile", caPath, "-verify_return_error", "-tls1_3", "-groups", "X25519", "-sigalgs", "mldsa65:ecdsa_secp256r1_sha256", "-quiet") // #nosec G204 -- Fixed stock TLS validation command against the owned loopback server.
	client.Stdin = bytes.NewBufferString("GET / HTTP/1.0\r\nHost: api.example.test\r\n\r\n")
	output, err := client.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("HTTP/1.0 200 ok")) {
		t.Fatalf("stock ML-DSA TLS/application check failed: %v\n%s", err, output)
	}
}
