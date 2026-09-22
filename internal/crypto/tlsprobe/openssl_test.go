// SPDX-License-Identifier: BUSL-1.1

package tlsprobe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func requireNativeProbeOpenSSL(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("native OpenSSL executable unavailable")
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNativeProbeCompletesTLSWithoutApplicationData(t *testing.T) {
	openssl := requireNativeProbeOpenSSL(t)
	var calls atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	srv.StartTLS()
	defer srv.Close()
	result, err := ProbeWithOpenSSL(context.Background(), openssl, srv.Listener.Addr().String(), WithServerName("example.test"), WithALPN("http/1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if result.TLSVersion != tls.VersionTLS13 || result.NegotiatedProtocol != "http/1.1" || len(result.PeerCertificates) != 1 || !bytes.Equal(result.PeerCertificates[0], srv.Certificate().Raw) {
		t.Fatal("native probe did not retain the exact served certificate and negotiated protocol")
	}
	srv.CloseClientConnections()
	if calls.Load() != 0 {
		t.Fatal("inventory probe sent an application request")
	}
}

func TestNativeProbeFailsClosedAndIsBounded(t *testing.T) {
	openssl := requireNativeProbeOpenSSL(t)
	t.Run("protocol rejection", func(t *testing.T) {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected application request") }))
		srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12} // #nosec G402 -- negative control: this fixture must reject the TLS 1.3-only native probe.
		srv.StartTLS()
		defer srv.Close()
		got, err := ProbeWithOpenSSL(context.Background(), openssl, srv.Listener.Addr().String())
		if err == nil || len(got.PeerCertificates) != 0 {
			t.Fatal("failed TLS handshake became certificate evidence")
		}
	})
	t.Run("deadline", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		stop := make(chan struct{})
		done := make(chan struct{})
		defer func() { _ = listener.Close(); close(stop); <-done }()
		go func() {
			defer close(done)
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			<-stop
		}()
		start := time.Now()
		got, err := ProbeWithOpenSSL(context.Background(), openssl, listener.Addr().String(), WithTimeout(150*time.Millisecond))
		if err == nil || len(got.PeerCertificates) != 0 || time.Since(start) > 3*time.Second {
			t.Fatal("silent peer did not fail within its deadline")
		}
	})
	for _, tc := range []struct {
		name, path, addr string
		options          []Option
	}{
		{"relative executable", "openssl", "127.0.0.1:443", nil},
		{"bad port", openssl, "127.0.0.1:0", nil},
		{"option address", openssl, "-connect:443", nil},
		{"name newline", openssl, "127.0.0.1:443", []Option{WithServerName("ok\nCONNECTION ESTABLISHED")}},
		{"protocol injection", openssl, "127.0.0.1:443", []Option{WithALPN("h2\nALPN protocol: h2")}},
		{"unsupported upgrade", openssl, "127.0.0.1:443", []Option{WithPreHandshake(func(context.Context, net.Conn) error { t.Fatal("upgrade callback must not be ignored"); return nil })}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ProbeWithOpenSSL(context.Background(), tc.path, tc.addr, tc.options...); err == nil || len(got.PeerCertificates) != 0 {
				t.Fatal("invalid native probe request accepted")
			}
		})
	}
}

func nativeOutputFixture(certificate []byte) ([]byte, []byte) {
	stdout := append([]byte("---\nCertificate chain\n 0 s:CN=example.test\n"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})...)
	stdout = append(stdout, []byte("---\nServer certificate\nsubject=CN=example.test\n---\nNew, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256\nProtocol: TLSv1.3\nNo ALPN negotiated\nEarly data was not sent\nVerify return code: 18 (self-signed certificate)\n---\n")...)
	return stdout, []byte("CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nDONE\n")
}

func TestNativeProbeParserRequiresCompletedBoundedEvidence(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	stdout, stderr := nativeOutputFixture(srv.Certificate().Raw)
	if got, err := parseNativeProbeOutput(stdout, stderr, nil); err != nil || len(got.PeerCertificates) != 1 || !bytes.Equal(got.PeerCertificates[0], srv.Certificate().Raw) {
		t.Fatal("valid public certificate evidence rejected")
	}
	for _, tc := range []struct {
		name            string
		out, diagnostic []byte
	}{
		{"certificate without handshake", stdout, nil},
		{"marker inside a name", stdout, []byte("subject=CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\n")},
		{"wrong protocol", stdout, bytes.ReplaceAll(stderr, []byte("TLSv1.3"), []byte("TLSv1.2"))},
		{"ambiguous handshakes", stdout, append(append([]byte(nil), stderr...), stderr...)},
		{"no chain section", []byte("-----BEGIN CERTIFICATE-----\nnot a handshake\n-----END CERTIFICATE-----\n"), stderr},
		{"ambiguous chain", append(append([]byte(nil), stdout...), stdout...), stderr},
		{"malformed first PEM", bytes.Replace(stdout, []byte("-----BEGIN CERTIFICATE-----\n"), []byte("-----BEGIN CERTIFICATE-----\n!\n-----BEGIN CERTIFICATE-----\n"), 1), stderr},
		{"extra malformed PEM", bytes.Replace(stdout, []byte("---\nServer certificate\n"), []byte("-----BEGIN MALFORMED-----\n---\nServer certificate\n"), 1), stderr},
		{"unoffered ALPN", bytes.ReplaceAll(stdout, []byte("No ALPN negotiated"), []byte("ALPN protocol: h2")), stderr},
		{"oversize", bytes.Repeat([]byte{'x'}, nativeProbeOutputLimit), stderr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseNativeProbeOutput(tc.out, tc.diagnostic, nil)
			if err == nil || len(got.PeerCertificates) != 0 {
				t.Fatal("malformed output produced usable partial evidence")
			}
			if strings.Contains(err.Error(), "BEGIN") {
				t.Fatal("raw output escaped into the error")
			}
		})
	}
	// Unsolicited peer output after the diagnostic footer must not change ALPN.
	spoof := append(append([]byte(nil), stdout...), []byte("ALPN protocol: h2\n")...)
	if got, err := parseNativeProbeOutput(spoof, stderr, []string{"h2"}); err != nil || got.NegotiatedProtocol != "" {
		t.Fatal("application bytes changed negotiated ALPN")
	}
	for _, size := range []int{0, 31, 32, 33} {
		buffer := make([]byte, 32)
		n, err := readNativeProbeOutput(bytes.NewReader(bytes.Repeat([]byte{'x'}, size)), buffer)
		if size < len(buffer) {
			if err != nil || n != size {
				t.Fatal("bounded output truncated")
			}
		} else if err == nil || n != 0 {
			t.Fatal("overflow returned usable output")
		}
	}
}

func FuzzNativeProbeOutput(f *testing.F) {
	public, err := os.ReadFile("../certinfo/testdata/der-whitespace/signature-09.pem")
	if err != nil {
		f.Fatal(err)
	}
	cert, _ := pem.Decode(public)
	if cert == nil {
		f.Fatal("public certificate seed missing")
	}
	out, diagnostic := nativeOutputFixture(cert.Bytes)
	f.Add(out, diagnostic)
	f.Add([]byte("---\nCertificate chain\n---\n"), []byte("CONNECTION ESTABLISHED\n"))
	f.Fuzz(func(t *testing.T, stdout, stderr []byte) {
		if len(stdout) > nativeProbeOutputLimit+1 || len(stderr) > nativeProbeOutputLimit+1 {
			return
		}
		result, err := parseNativeProbeOutput(stdout, stderr, nil)
		if err != nil && (len(result.PeerCertificates) != 0 || result.TLSVersion != 0 || result.NegotiatedProtocol != "") {
			t.Fatal("invalid evidence exposed partial result")
		}
		if err == nil && (len(result.PeerCertificates) == 0 || result.TLSVersion != tls.VersionTLS13) {
			t.Fatal("successful evidence has no completed TLS 1.3 chain")
		}
	})
}
