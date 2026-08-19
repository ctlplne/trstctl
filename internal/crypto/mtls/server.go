// SPDX-License-Identifier: MPL-2.0

package mtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
)

// ServerCert is a control-plane server's TLS material — its certificate and key,
// plus the PEM a client must trust to verify it. It is opaque to callers outside
// the crypto boundary, who use only ServeHTTPS and TrustPEM.
type ServerCert struct {
	cert tls.Certificate
	// reload is set for operator file-mode material: it hot-swaps a rotated
	// certificate/key pair via tls.Config.GetCertificate without a restart
	// (OPS-TLS-RELOAD-001). TrustPEM keeps the boot-time chain: file-mode
	// operators distribute trust out of band, so rotation does not mutate it.
	reload *reloadingServerCert
	// TrustPEM is the certificate a client adds to its root pool to verify this
	// server (for an internal cert, the self-signed certificate itself; for a
	// file cert, the provided chain).
	TrustPEM []byte
}

// SelfSignedServerCert generates a self-signed server (ServerAuth) certificate
// covering the given hostnames and IPs, valid for ttl. It is the control plane's
// default TLS material when no operator certificate is configured, so the server
// is never plaintext out of the box; clients trust ServerCert.TrustPEM (suitable
// for evaluation / internal deployments).
func SelfSignedServerCert(hosts []string, ttl time.Duration) (*ServerCert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	var dnsNames []string
	var ipAddrs []net.IP
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}
	cn := "trstctl"
	if len(hosts) > 0 {
		cn = hosts[0]
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             boundarycrypto.IssuanceNotBefore(now),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
		BasicConstraintsValid: true,
	}
	// Self-signed: the certificate is its own issuer and trust anchor.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &ServerCert{
		cert:     tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf},
		TrustPEM: certPEM,
	}, nil
}

// LoadOrCreateSelfSignedServerCert returns one stable internal-mode HTTPS
// identity from stateFile. The private key and certificate share one mode-0600
// PEM file so publication is one atomic filesystem operation: a restart can see
// the old complete identity or the new complete identity, never a mismatched
// cert/key pair. Existing malformed or over-permissive state fails closed and is
// never silently replaced, because a changed trust anchor must be an explicit
// operator decision.
func LoadOrCreateSelfSignedServerCert(stateFile string, hosts []string, ttl time.Duration) (*ServerCert, error) {
	stateFile = filepath.Clean(stateFile)
	if stateFile == "." || stateFile == string(filepath.Separator) {
		return nil, errors.New("mtls: persistent internal TLS state file is required")
	}
	if _, err := os.Stat(stateFile); err == nil {
		return loadSelfSignedServerState(stateFile)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("mtls: stat persistent internal TLS state: %w", err)
	}

	dir := filepath.Dir(stateFile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mtls: create persistent internal TLS directory: %w", err)
	}
	generated, err := SelfSignedServerCert(hosts, ttl)
	if err != nil {
		return nil, err
	}
	key, ok := generated.cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("mtls: generated internal TLS key is not ECDSA")
	}
	defer boundarycrypto.WipeECDSAPrivateKey(key)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("mtls: marshal persistent internal TLS key: %w", err)
	}
	defer wipeBytes(keyDER)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer wipeBytes(keyPEM)
	var combined []byte
	combined = append(combined, generated.TrustPEM...)
	combined = append(combined, keyPEM...)
	defer wipeBytes(combined)

	tmp, err := os.CreateTemp(dir, ".internal-server-*.pem")
	if err != nil {
		return nil, fmt.Errorf("mtls: create persistent internal TLS staging file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	closeWithError := func(in error) error {
		if closeErr := tmp.Close(); in == nil {
			return closeErr
		}
		return in
	}
	if err := tmp.Chmod(0o600); err != nil {
		return nil, closeWithError(err)
	}
	if _, err := tmp.Write(combined); err != nil {
		return nil, closeWithError(err)
	}
	if err := tmp.Sync(); err != nil {
		return nil, closeWithError(err)
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	// A hard link publishes the fully-written inode only if stateFile is still
	// absent. A concurrent first boot loses with EEXIST and loads the winner,
	// instead of two processes serving different certificates under one path.
	if err := os.Link(tmpName, stateFile); err != nil {
		if os.IsExist(err) {
			return loadSelfSignedServerState(stateFile)
		}
		return nil, fmt.Errorf("mtls: publish persistent internal TLS state: %w", err)
	}
	if err := syncStateDirectory(dir); err != nil {
		return nil, fmt.Errorf("mtls: sync persistent internal TLS directory: %w", err)
	}
	return loadSelfSignedServerState(stateFile)
}

// syncStateDirectory makes publication of the new state-file name durable.
// This local stdlib-only copy is intentional: packages inside internal/crypto
// cannot import a platform helper from outside the sacred crypto boundary.
func syncStateDirectory(path string) error {
	// Windows does not expose directory handles that os.File.Sync can flush.
	// The state file itself was synced before publication; skip only the
	// directory-entry flush that Windows cannot perform.
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path) // #nosec G304 -- parent of the validated internal TLS state path (CWE-22)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

// PublishServerTrust publishes a certificate-only PEM that clients can mount or
// copy without gaining access to the combined internal certificate/private-key
// state. Publication is atomic and idempotent. An existing different file fails
// closed because silently changing an explicitly pinned trust anchor would turn
// a deployment error into a certificate-verification bypass.
func PublishServerTrust(trustFile string, trustPEM []byte) error {
	trustFile = filepath.Clean(trustFile)
	if trustFile == "." || trustFile == string(filepath.Separator) {
		return errors.New("mtls: public internal TLS trust file is required")
	}
	if err := validateServerTrustPEM(trustPEM); err != nil {
		return err
	}
	validateExisting := func() error {
		info, err := os.Lstat(trustFile)
		if err != nil {
			return fmt.Errorf("mtls: inspect public internal TLS trust: %w", err)
		}
		if !info.Mode().IsRegular() {
			return errors.New("mtls: public internal TLS trust is not a regular file")
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("mtls: public internal TLS trust permissions are writable by group or other: %04o", info.Mode().Perm())
		}
		raw, err := os.ReadFile(trustFile) // #nosec G304 -- operator-selected public certificate path, validated as a regular file (CWE-22)
		if err != nil {
			return fmt.Errorf("mtls: read public internal TLS trust: %w", err)
		}
		if !bytes.Equal(raw, trustPEM) {
			return errors.New("mtls: existing public internal TLS trust contains a different certificate")
		}
		return nil
	}
	if _, err := os.Lstat(trustFile); err == nil {
		return validateExisting()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("mtls: inspect public internal TLS trust: %w", err)
	}

	dir := filepath.Dir(trustFile)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("mtls: create public internal TLS trust directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".internal-server-trust-*.crt")
	if err != nil {
		return fmt.Errorf("mtls: create public internal TLS trust staging file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	closeWithError := func(in error) error {
		if closeErr := tmp.Close(); in == nil {
			return closeErr
		}
		return in
	}
	if err := tmp.Chmod(0o644); err != nil {
		return closeWithError(err)
	}
	if _, err := tmp.Write(trustPEM); err != nil {
		return closeWithError(err)
	}
	if err := tmp.Sync(); err != nil {
		return closeWithError(err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpName, trustFile); err != nil {
		if os.IsExist(err) {
			return validateExisting()
		}
		return fmt.Errorf("mtls: publish public internal TLS trust: %w", err)
	}
	if err := syncStateDirectory(dir); err != nil {
		return fmt.Errorf("mtls: sync public internal TLS trust directory: %w", err)
	}
	return nil
}

func validateServerTrustPEM(trustPEM []byte) error {
	rest := trustPEM
	certificates := 0
	for len(bytes.TrimSpace(rest)) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return errors.New("mtls: public internal TLS trust contains malformed or trailing PEM data")
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("mtls: public internal TLS trust contains forbidden PEM block %q", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("mtls: parse public internal TLS certificate: %w", err)
		}
		certificates++
		rest = remaining
	}
	if certificates == 0 || strings.TrimSpace(string(trustPEM)) == "" {
		return errors.New("mtls: public internal TLS trust contains no certificate")
	}
	return nil
}

func loadSelfSignedServerState(stateFile string) (*ServerCert, error) {
	info, err := os.Stat(stateFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: stat persistent internal TLS state: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("mtls: persistent internal TLS state is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("mtls: persistent internal TLS state permissions are %04o, want 0600 or stricter", info.Mode().Perm())
	}
	raw, err := os.ReadFile(stateFile) // #nosec G304 -- operator-selected internal TLS state path, validated as a private regular file (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("mtls: read persistent internal TLS state: %w", err)
	}
	defer wipeBytes(raw)
	cert, err := tls.X509KeyPair(raw, raw)
	if err != nil {
		return nil, fmt.Errorf("mtls: parse persistent internal TLS state: %w", err)
	}
	if len(cert.Certificate) != 1 {
		return nil, fmt.Errorf("mtls: persistent internal TLS state has %d certificates, want exactly one self-signed leaf", len(cert.Certificate))
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("mtls: parse persistent internal TLS certificate: %w", err)
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		return nil, fmt.Errorf("mtls: persistent internal TLS certificate is not self-signed: %w", err)
	}
	hasServerAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		return nil, errors.New("mtls: persistent internal TLS certificate is not authorized for server authentication")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("mtls: persistent internal TLS certificate is outside its validity window (%s to %s)", leaf.NotBefore.UTC(), leaf.NotAfter.UTC())
	}
	cert.Leaf = leaf
	trustPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	return &ServerCert{cert: cert, TrustPEM: trustPEM}, nil
}

// ServerCertFromFiles loads an operator-provided server certificate chain and
// private key (PEM). It fails clearly when the files are missing or malformed,
// so a misconfiguration cannot silently fall back to plaintext.
func ServerCertFromFiles(certFile, keyFile string) (*ServerCert, error) {
	reload, err := newReloadingServerCert(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	chainPEM, err := os.ReadFile(certFile) // #nosec G304 -- operator-configured certificate/key path from deployment config (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("mtls: read server certificate: %w", err)
	}
	return &ServerCert{cert: *reload.current.Load(), reload: reload, TrustPEM: chainPEM}, nil
}

// MutualTLSServerListenerFromFiles wraps ln in a TLS 1.3 mutual-auth listener
// using operator-provided server material and a client CA. It keeps raw
// crypto/tls and crypto/x509 handling inside the AN-3 boundary while raw TCP
// protocols such as KMIP consume an ordinary net.Listener.
func MutualTLSServerListenerFromFiles(ln net.Listener, certFile, keyFile, clientCAFile string) (net.Listener, error) {
	reload, err := newReloadingServerCert(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	clientCAs, err := loadCAPool(clientCAFile)
	if err != nil {
		return nil, err
	}
	cfg := serverTLSConfig(*reload.current.Load(), clientCAs)
	cfg.Certificates = nil
	cfg.GetCertificate = reload.GetCertificate
	return tls.NewListener(ln, cfg), nil
}

// PeerCertificateDER returns the verified peer leaf certificate from a mutual-TLS
// connection. The TLS listener already performs chain validation; callers get only
// an opaque DER blob they can pass to their protocol authenticator.
func PeerCertificateDER(conn net.Conn) ([]byte, error) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("mtls: connection is %T, not TLS", conn)
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("mtls: handshake: %w", err)
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return nil, fmt.Errorf("mtls: no verified peer certificate")
	}
	return append([]byte(nil), state.PeerCertificates[0].Raw...), nil
}

// CurvePreferences returns the key-agreement groups offered by MPL-core served
// TLS paths.
func CurvePreferences() []tls.CurveID {
	return []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}
}

// ServeHTTPS serves srv over ln using this server certificate. The control-plane /
// operator surface pins a TLS 1.3 floor — matching the agent transport's pinned
// TLS 1.3 (mtls.go) rather than the old TLS 1.2 default — so a credential control
// plane never negotiates a legacy version or a non-AEAD cipher (WIRE-008). TLS 1.3
// negotiates only AEAD suites by protocol, so an explicit CipherSuites allowlist
// is unnecessary at this floor.
// HSTS is emitted by the server's security-headers middleware over TLS (SEC-003),
// not here. It blocks like (*http.Server).ServeTLS and returns its error.
func (s *ServerCert) ServeHTTPS(srv *http.Server, ln net.Listener) error {
	srv.TLSConfig = &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: CurvePreferences(),
	}
	if s.reload != nil {
		// File mode: serve through the reload hook so a rotated pair is
		// picked up without a restart (OPS-TLS-RELOAD-001).
		srv.TLSConfig.GetCertificate = s.reload.GetCertificate
	} else {
		srv.TLSConfig.Certificates = []tls.Certificate{s.cert}
	}
	return srv.ServeTLS(ln, "", "")
}

// LoopbackProbeClient returns an HTTP client for a LOCALHOST LIVENESS PROBE only
// (the container health check execs the binary, which has no shell or curl). It
// does NOT verify the server certificate, because the control plane's internal
// certificate is ephemeral and self-signed and the probe only confirms the
// process is alive and ready on loopback — it carries no credential and reads no
// data. It must never be used for data-bearing requests.
func LoopbackProbeClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// Loopback liveness only — see the doc comment above.
			// lgtm[go/disabled-certificate-check] This client can only be handed the
			// fixed loopback health URL by the binary's internal probe command.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, // #nosec G402 -- localhost liveness probe of this process's own ephemeral self-signed listener; no credential, no data (CWE-295)
		},
	}
}
