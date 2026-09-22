// SPDX-License-Identifier: BUSL-1.1

package pqc

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

// Real certificate authentication and peer-chain readback, independent of the
// issuance result. X25519 is deliberate: this does not confuse hybrid key
// exchange with an ML-DSA subject key authenticating a TLS listener.
func TestNativeProbeReadsActualMLDSACertificate(t *testing.T) {
	openssl := requireOpenSSLMLDSA(t)
	resolved, err := filepath.EvalSymlinks(openssl)
	if err != nil {
		t.Fatal(err)
	}
	openssl = resolved
	ca, err := boundarycrypto.GenerateLockedKey(boundarycrypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := boundarycrypto.SelfSignedCACert(ca, "native probe test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []boundarycrypto.Algorithm{MLDSA44, MLDSA65, MLDSA87} {
		t.Run(string(algorithm), func(t *testing.T) {
			key, err := GenerateHostMLDSASubjectKey(boundarycrypto.CertificateRequestTemplate{CommonName: "api.example.test", DNSNames: []string{"api.example.test"}}, algorithm)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Destroy()
			prepared, err := boundarycrypto.NewLeafPreparation()
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := SignPQCLeafFromCSRWithPreparation(caDER, ca, key.CSRDER, 10*time.Minute, boundarycrypto.LeafProfile{ClampTTLToIssuer: true}, prepared)
			if err != nil {
				t.Fatal(err)
			}
			certPath, caPath := writePreparedPQCLeafFixtures(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.DER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
			private, err := key.PrivateKeyPEM()
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Wipe(private)
			keyPath := filepath.Join(t.TempDir(), "key.pem")
			if err := os.WriteFile(keyPath, private, 0600); err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := listener.Addr().String()
			_ = listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			server := exec.CommandContext(ctx, openssl, "s_server", "-accept", addr, "-cert", certPath, "-cert_chain", caPath, "-key", keyPath, "-quiet", "-tls1_3", "-groups", "X25519", "-alpn", "http/1.1") // #nosec G204 -- pinned local stock executable and owned loopback fixture.
			server.Stdout, server.Stderr = io.Discard, io.Discard
			if err := server.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = server.Process.Kill(); _ = server.Wait() }()
			ready := false
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
				conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
				if err == nil {
					_ = conn.Close()
					ready = true
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			if !ready {
				t.Fatal("owned native TLS fixture did not listen")
			}
			got, err := tlsprobe.ProbeWithOpenSSL(ctx, openssl, addr, tlsprobe.WithServerName("api.example.test"), tlsprobe.WithALPN("http/1.1"))
			if err != nil {
				t.Fatalf("served ML-DSA certificate could not be read back: %v", err)
			}
			if got.TLSVersion != 0x0304 || got.NegotiatedProtocol != "http/1.1" || len(got.PeerCertificates) != 2 || !bytes.Equal(got.PeerCertificates[0], leaf.DER) || !bytes.Equal(got.PeerCertificates[1], caDER) {
				t.Fatal("native TLS readback disagreed with exact leaf, chain or negotiated protocol")
			}
		})
	}
}
