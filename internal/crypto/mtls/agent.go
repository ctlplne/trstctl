// SPDX-License-Identifier: MPL-2.0

package mtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"

	boundary "trstctl.com/trstctl/internal/crypto"
)

// (crypto/tls is already imported above for the ClientCertSource/credentials path;
// PeerCertInfoFromTLS reuses it to read a verified peer connection state.)

// This file adds the agent side of mutual TLS, inside the AN-3 crypto boundary:
// an agent generates its key here and never exports it — only a CSR crosses the
// wire — and the control plane signs that CSR. AgentIdentity holds the local key
// plus its issued certificate, presents it for handshakes (a ClientCertSource),
// and persists/reloads it so an agent survives restarts.

// AgentIdentity is an agent's local key plus its issued client certificate. The
// private key is generated and held here and never leaves the boundary.
type AgentIdentity struct {
	commonName string
	key        *ecdsa.PrivateKey
	chainPEM   []byte
	chainDER   [][]byte
	leaf       *x509.Certificate
}

// GenerateAgentKey generates a fresh local key for an agent identity (no
// certificate yet — call CSR, have it signed, then UseCertificate).
func GenerateAgentKey(commonName string) (*AgentIdentity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &AgentIdentity{commonName: commonName, key: key}, nil
}

// CSR returns a PKCS#10 certificate request (DER) for this identity's key. Only
// the CSR — carrying the public key, never the private key — is sent to the CA.
func (a *AgentIdentity) CSR() ([]byte, error) {
	if a == nil || a.key == nil {
		return nil, errors.New("mtls: agent identity is destroyed")
	}
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: a.commonName},
	}, a.key)
}

// UseCertificate adopts the certificate chain (PEM) the CA issued for this
// identity's CSR, after verifying the leaf carries this identity's public key.
func (a *AgentIdentity) UseCertificate(chainPEM []byte) error {
	if a == nil || a.key == nil {
		return errors.New("mtls: agent identity is destroyed")
	}
	var ders [][]byte
	rest := chainPEM
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			ders = append(ders, block.Bytes)
		}
		rest = r
	}
	if len(ders) == 0 {
		return errors.New("mtls: certificate chain has no certificates")
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return fmt.Errorf("mtls: parse issued leaf: %w", err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&a.key.PublicKey) {
		return errors.New("mtls: issued certificate does not match the agent's key")
	}
	a.chainPEM = append([]byte(nil), chainPEM...)
	a.chainDER = ders
	a.leaf = leaf
	return nil
}

// ClientCertificate implements ClientCertSource, presenting this identity's
// certificate for a TLS handshake.
func (a *AgentIdentity) ClientCertificate() (*tls.Certificate, error) {
	if a == nil || a.key == nil {
		return nil, errors.New("mtls: agent identity is destroyed")
	}
	if a.leaf == nil {
		return nil, errors.New("mtls: agent identity has no certificate yet")
	}
	return &tls.Certificate{Certificate: a.chainDER, PrivateKey: a.key, Leaf: a.leaf}, nil
}

// CommonName is the identity's subject common name.
func (a *AgentIdentity) CommonName() string { return a.commonName }

// Serial is the issued certificate's serial number in hex (empty if unissued).
func (a *AgentIdentity) Serial() string {
	if a.leaf == nil {
		return ""
	}
	return a.leaf.SerialNumber.Text(16)
}

// Roles is the capability grant this identity's certificate carries (epic A2).
// An agent reads it to know what it is: a host agent asks for host work, a relay
// asks for relay work. It is the same value the control plane reads off the
// presented certificate, so the two cannot disagree — and an agent that asked for
// more than its certificate carries would simply be handed nothing.
//
// An unissued identity, or one whose certificate predates roles, reports host.
func (a *AgentIdentity) Roles() []string {
	if a.leaf == nil {
		return []string{AgentRoleHost}
	}
	roles, err := AgentRolesFromClientCert(a.leaf.Raw)
	if err != nil {
		return []string{AgentRoleHost}
	}
	return roles
}

// CertificateDER is the issued leaf certificate (DER), or nil before issuance.
//
// It is what a receipt is verified against (epic A1) — the public half, which
// is the only half anyone but this identity ever needs.
func (a *AgentIdentity) CertificateDER() []byte {
	if a.leaf == nil {
		return nil
	}
	return append([]byte(nil), a.leaf.Raw...)
}

// TenantID is the tenant this identity's certificate attributes it to, read
// from the SPIFFE SAN.
//
// An agent needs this to sign a job receipt (epic A1), and it must come from
// the certificate rather than from the agent's config file: the server rebuilds
// the signed statement from the certificate it verified, so a config-supplied
// tenant that disagrees would produce a receipt that never verifies — and,
// worse, an agent that believes it is signing for a tenant it was not issued
// for. Empty for an unissued identity; a caller signing with an unissued
// identity has nothing to sign with either.
func (a *AgentIdentity) TenantID() string {
	if a.leaf == nil {
		return ""
	}
	tenantID, err := TenantFromClientCert(a.leaf.Raw)
	if err != nil {
		return ""
	}
	return tenantID
}

// NotAfter is the issued certificate's expiry.
func (a *AgentIdentity) NotAfter() time.Time {
	if a.leaf == nil {
		return time.Time{}
	}
	return a.leaf.NotAfter
}

// CertificatePEM returns the issued certificate chain (PEM).
func (a *AgentIdentity) CertificatePEM() []byte { return a.chainPEM }

// Save persists the private key (0600) and certificate chain to keyPath and
// certPath. The key stays on the host; it is never transmitted.
func (a *AgentIdentity) Save(keyPath, certPath string) error {
	if a == nil || a.key == nil {
		return errors.New("mtls: agent identity is destroyed")
	}
	der, err := x509.MarshalPKCS8PrivateKey(a.key)
	if err != nil {
		return err
	}
	defer wipeBytes(der)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer wipeBytes(keyPEM)
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("mtls: write key: %w", err)
	}
	if err := os.WriteFile(certPath, a.chainPEM, 0o644); err != nil { // #nosec G306 -- certificate chain PEM is public material; the key is written 0600 separately (CWE-276)
		return fmt.Errorf("mtls: write certificate: %w", err)
	}
	return nil
}

// LoadAgentIdentity reloads an identity persisted by Save. It is how an agent
// resumes after a restart without re-bootstrapping.
func LoadAgentIdentity(commonName, keyPath, certPath string) (*AgentIdentity, error) {
	keyPEM, err := os.ReadFile(keyPath) // #nosec G304 -- operator-configured certificate/key path from deployment config (CWE-22)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(keyPEM)
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("mtls: stored key is not PEM")
	}
	defer wipeBytes(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mtls: parse stored key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("mtls: stored key is not an ECDSA key")
	}
	chainPEM, err := os.ReadFile(certPath) // #nosec G304 -- operator-configured certificate/key path from deployment config (CWE-22)
	if err != nil {
		wipeAgentKey(key)
		return nil, err
	}
	a := &AgentIdentity{commonName: commonName, key: key}
	if err := a.UseCertificate(chainPEM); err != nil {
		a.Destroy()
		return nil, err
	}
	return a, nil
}

// Destroy zeroes the client private scalar and releases the certificate copies.
// It is idempotent. Short-lived upstream-CA clients call this after their final
// TLS connection is closed so an mTLS credential is not retained in heap memory.
func (a *AgentIdentity) Destroy() {
	if a == nil {
		return
	}
	wipeAgentKey(a.key)
	a.key = nil
	wipeBytes(a.chainPEM)
	for _, der := range a.chainDER {
		wipeBytes(der)
	}
	a.chainPEM = nil
	a.chainDER = nil
	a.leaf = nil
}

func wipeAgentKey(key *ecdsa.PrivateKey) {
	boundary.WipeECDSAPrivateKey(key)
}

func wipeBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
	runtime.KeepAlive(value)
}

// SignClientCSR signs a PKCS#10 CSR as a short-lived agent client certificate
// (ClientAuth), valid for ttl, and returns the chain (leaf + CA) in PEM. The
// CA never sees the agent's private key — only its CSR.
func (c *CA) SignClientCSR(csrDER []byte, ttl time.Duration) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("mtls: parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("mtls: csr signature: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             boundary.IssuanceNotBefore(now),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("mtls: sign client csr: %w", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	out = append(out, c.BundlePEM()...)
	return out, nil
}

// tenantTrustDomain is the DNS-shaped SPIFFE trust domain under which agent
// identities are stamped with their authorizing tenant. It is a reserved example
// domain so the default URI SAN is RFC 5280-lintable without claiming a public
// production domain.
const tenantTrustDomain = "trstctl.example"

// AgentSPIFFEID is the SPIFFE ID stamped into an agent's client certificate for
// tenant tenantID and the agent's common name cn:
//
//	spiffe://trstctl.example/tenant/<tenantID>/agent/<cn>
//
// The tenant segment is what lets the mTLS consumer derive the tenant from the
// certificate itself rather than trusting a client-supplied header (WIRE-003).
func AgentSPIFFEID(tenantID, cn string) string {
	return (&url.URL{
		Scheme: "spiffe",
		Host:   tenantTrustDomain,
		Path:   "/tenant/" + tenantID + "/agent/" + cn,
	}).String()
}

// SignClientCSRWithTenant signs a PKCS#10 CSR as a short-lived agent client
// certificate (ClientAuth), exactly like SignClientCSR, but ADDITIONALLY stamps
// the authorizing tenant into the certificate as a SPIFFE URI SAN
// (spiffe://trstctl.example/tenant/<tenantID>/agent/<cn>). The SAN is set by the CA from
// the redeemed token's tenant — NOT from the CSR — so a holder of a tenant-A
// token can never obtain a certificate attributed to tenant B even by crafting
// the CSR. The common name still comes from the CSR's subject, but tenant
// attribution does not (WIRE-003 / AN-1). An empty tenantID is rejected — this
// signing path must always carry tenant attribution.
func (c *CA) SignClientCSRWithTenant(
	csrDER []byte,
	tenantID string,
	roles []string,
	ttl time.Duration,
) ([]byte, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, errors.New("mtls: refusing to sign agent CSR without a tenant attribution")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("mtls: parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("mtls: csr signature: %w", err)
	}
	spiffeURI, err := url.Parse(AgentSPIFFEID(tenantID, csr.Subject.CommonName))
	if err != nil {
		return nil, fmt.Errorf("mtls: build tenant SPIFFE ID: %w", err)
	}
	// Capability SANs come from the caller's grant, never the CSR (epic A2). An
	// unknown role is refused rather than stamped: a certificate carrying a role
	// nothing reads is worse than no role at all, because it reads as a grant.
	uris := []*url.URL{spiffeURI}
	for _, role := range NormalizeAgentRoles(roles) {
		roleURI, rerr := url.Parse(AgentRoleSPIFFEID(tenantID, csr.Subject.CommonName, role))
		if rerr != nil {
			return nil, fmt.Errorf("mtls: build agent role SPIFFE ID: %w", rerr)
		}
		uris = append(uris, roleURI)
	}
	for _, role := range roles {
		if strings.TrimSpace(role) != "" && !ValidAgentRole(role) {
			return nil, fmt.Errorf("mtls: refusing to stamp unknown agent role %q", role)
		}
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		URIs:                  uris,
		NotBefore:             boundary.IssuanceNotBefore(now),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("mtls: sign client csr: %w", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	out = append(out, c.BundlePEM()...)
	return out, nil
}

// TenantFromClientCert extracts the authorizing tenant id from an agent client
// certificate's SPIFFE URI SAN (the one SignClientCSRWithTenant stamps). It is how
// a future mTLS consumer derives the tenant from the presented certificate rather
// than a client-supplied header (WIRE-003). It returns an error if no
// spiffe://trstctl.example/tenant/<id>/... SAN is present.
func TenantFromClientCert(certDER []byte) (string, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("mtls: parse client cert: %w", err)
	}
	for _, u := range cert.URIs {
		if u.Scheme != "spiffe" || u.Host != tenantTrustDomain {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
		if len(parts) >= 2 && parts[0] == "tenant" && parts[1] != "" {
			return parts[1], nil
		}
	}
	return "", errors.New("mtls: client certificate carries no tenant SPIFFE SAN")
}

// BundlePEM returns the CA certificate in PEM (the trust anchor an agent pins to
// verify the control plane, and the chain root of issued client certs).
func (c *CA) BundlePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// ServerCredentials issues a server certificate for dnsNames and returns gRPC
// transport credentials that present it and require client certs from this CA —
// so the control plane wires mutual TLS without naming crypto/* itself.
func (c *CA) ServerCredentials(dnsNames []string, ttl time.Duration) (credentials.TransportCredentials, error) {
	serverCert, err := c.IssueServerCertificate(dnsNames, ttl)
	if err != nil {
		return nil, err
	}
	return ServerCredentials(serverCert, c.Pool()), nil
}

// SwappableSource is a ClientCertSource whose backing identity can be replaced
// atomically — so an agent's rotated certificate is presented on the next
// handshake without rebuilding the transport credentials.
type SwappableSource struct {
	mu  sync.Mutex
	cur ClientCertSource
}

// NewSwappableSource wraps an initial source.
func NewSwappableSource(initial ClientCertSource) *SwappableSource {
	return &SwappableSource{cur: initial}
}

// Set replaces the backing source.
func (s *SwappableSource) Set(src ClientCertSource) {
	s.mu.Lock()
	s.cur = src
	s.mu.Unlock()
}

// ClientCertificate returns the current source's certificate.
func (s *SwappableSource) ClientCertificate() (*tls.Certificate, error) {
	s.mu.Lock()
	src := s.cur
	s.mu.Unlock()
	if src == nil {
		return nil, errors.New("mtls: no client certificate source set")
	}
	return src.ClientCertificate()
}

// AgentClientCredentials builds gRPC client credentials for an agent from the
// control-plane CA certificate (PEM) — so the agent trusts the CP without naming
// crypto/* itself.
func AgentClientCredentials(src ClientCertSource, serverCAPEM []byte, serverName string, pin *Pin) (credentials.TransportCredentials, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(serverCAPEM) {
		return nil, errors.New("mtls: no CA certificates in the provided PEM")
	}
	return ClientCredentials(src, pool, serverName, pin), nil
}

// PeerCertInfo is the identity the control plane derives from an agent's VERIFIED
// mTLS client certificate on the served channel: the tenant (from the SPIFFE SAN),
// the agent common name, and the leaf serial — all read from the certificate the
// TLS stack already verified, never from a request field (WIRE-003/AN-1).
type PeerCertInfo struct {
	TenantID          string
	CommonName        string
	Serial            string
	FingerprintSHA256 string
	// LeafDER is the verified leaf certificate (DER), so a caller can sign a renewal
	// CSR for the SAME tenant without re-extracting it.
	LeafDER []byte
	// Roles is the capability grant the presented certificate carries (epic A2).
	// It is what the served channel authorizes work against: an agent's roles are
	// read off the certificate an operator caused to be issued, not off anything
	// the agent says about itself at call time. A certificate with no role SAN
	// reads as host-only.
	Roles []string
}

// PeerCertInfoFromAuthInfo extracts the agent identity from a gRPC peer's AuthInfo
// (peer.Peer.AuthInfo). It asserts the AuthInfo is a TLS connection, reads the
// VERIFIED peer leaf (the server uses RequireAndVerifyClientCert, so the handshake
// already validated the chain), and returns the tenant (from the SPIFFE SAN), the
// agent common name, and the serial. It returns an error when the connection is not
// mTLS, presents no peer certificate, or the certificate carries no tenant SPIFFE
// SAN — so the served handler fails closed on anything that is not a tenant-
// attributed agent identity. It lives here so the agent service never imports
// crypto/tls or crypto/x509 itself (AN-3): the caller passes the opaque
// credentials.AuthInfo and gets back a plain struct.
func PeerCertInfoFromAuthInfo(authInfo credentials.AuthInfo) (PeerCertInfo, error) {
	tlsInfo, ok := authInfo.(credentials.TLSInfo)
	if !ok {
		return PeerCertInfo{}, errors.New("mtls: agent channel peer is not mutual TLS")
	}
	state := tlsInfo.State
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return PeerCertInfo{}, errors.New("mtls: no verified peer certificate on the agent channel")
	}
	leaf := state.PeerCertificates[0]
	tenantID, err := TenantFromClientCert(leaf.Raw)
	if err != nil {
		return PeerCertInfo{}, err
	}
	fingerprint, err := CertFingerprintSHA256(leaf.Raw)
	if err != nil {
		return PeerCertInfo{}, err
	}
	roles, err := AgentRolesFromClientCert(leaf.Raw)
	if err != nil {
		return PeerCertInfo{}, err
	}
	return PeerCertInfo{
		TenantID:          tenantID,
		CommonName:        leaf.Subject.CommonName,
		Serial:            leaf.SerialNumber.Text(16),
		FingerprintSHA256: fingerprint,
		LeafDER:           leaf.Raw,
		Roles:             roles,
	}, nil
}

// VerifiedPeerCertsDERFromTLS extracts the DER chain from a net/http TLS state after
// mutual-TLS verification. It deliberately reads VerifiedChains, not
// PeerCertificates, so a raw client-supplied but untrusted certificate never becomes
// an enrollment credential. A stale/not-yet-valid leaf is rejected defensively even
// though a real TLS verifier would already exclude it from VerifiedChains.
func VerifiedPeerCertsDERFromTLS(state *tls.ConnectionState) ([][]byte, error) {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return nil, errors.New("mtls: no verified peer certificate")
	}
	chain := state.VerifiedChains[0]
	leaf := chain[0]
	if leaf == nil {
		return nil, errors.New("mtls: verified peer certificate is empty")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, errors.New("mtls: verified peer certificate is expired or not yet valid")
	}
	out := make([][]byte, 0, len(chain))
	for _, cert := range chain {
		if cert == nil || len(cert.Raw) == 0 {
			return nil, errors.New("mtls: verified peer chain contains an empty certificate")
		}
		out = append(out, cert.Raw)
	}
	return out, nil
}

// LocalServerKey is a TLS server key the control plane generates locally for its
// agent-channel listener (WIRE-004). The key never leaves the process and is NOT a CA
// key (the agent CA key lives in the signer, AN-4); this is only the channel's
// server-cert key. The control plane generates it, has the AGENT CA sign its CSR (via
// crypto.SignServerCertFromCSR), then builds gRPC server credentials from the signed
// chain with Credentials. It exists so the agent channel's server-cert handling stays
// inside the AN-3 crypto boundary (the server package names no crypto/* symbol).
type LocalServerKey struct {
	key *ecdsa.PrivateKey
}

// NewLocalServerKey generates a fresh ECDSA P-256 server key.
func NewLocalServerKey() (*LocalServerKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &LocalServerKey{key: key}, nil
}

// CSR returns a PKCS#10 certificate request (DER) for this key, with the given common
// name and DNS SANs, for the agent CA to sign into a server certificate.
func (k *LocalServerKey) CSR(commonName string, dnsNames []string) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: dnsNames,
	}, k.key)
}

// Credentials assembles gRPC SERVER transport credentials for the agent channel from
// the agent-CA-signed server chain (serverCertChainPEM, leaf||CA) plus this local key,
// REQUIRING + VERIFYING the agent's client certificate against the agent CA pool
// (agentCAPEM). TLS 1.3, AEAD-only (the package init guard enforces the cipher floor).
// The agent CA PRIVATE key never appears here — only the public CA cert (for the client
// trust pool) and this server's own local key. Fails closed on any malformed input.
func (k *LocalServerKey) Credentials(serverCertChainPEM, agentCAPEM []byte) (credentials.TransportCredentials, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.key)
	if err != nil {
		return nil, fmt.Errorf("mtls: marshal agent-channel server key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	cert, err := tls.X509KeyPair(serverCertChainPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("mtls: load agent-channel server certificate: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(agentCAPEM) {
		return nil, errors.New("mtls: agent CA PEM contains no certificates")
	}
	return ServerCredentials(cert, clientCAs), nil
}

// HTTPServerTLSConfig assembles the HTTPS server TLS config for the embedded-agent
// renewal listener from an agent-CA-signed server chain and the agent CA bundle. It
// is the HTTP analogue of Credentials: TLS 1.3, RequireAndVerifyClientCert, and the
// agent CA as the only accepted client anchor.
func (k *LocalServerKey) HTTPServerTLSConfig(serverCertChainPEM, agentCAPEM []byte) (*tls.Config, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.key)
	if err != nil {
		return nil, fmt.Errorf("mtls: marshal agent HTTP renewal server key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	cert, err := tls.X509KeyPair(serverCertChainPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("mtls: load agent HTTP renewal server certificate: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(agentCAPEM) {
		return nil, errors.New("mtls: agent CA PEM contains no certificates")
	}
	return serverTLSConfig(cert, clientCAs), nil
}

// CertSerialHex returns the serial (lowercase hex) of a DER certificate — a boundary
// helper so a caller can read an issued cert's serial without importing crypto/x509
// (AN-3).
func CertSerialHex(certDER []byte) (string, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("mtls: parse certificate: %w", err)
	}
	return cert.SerialNumber.Text(16), nil
}

// CertFingerprintSHA256 returns the lowercase hex SHA-256 fingerprint of a DER
// certificate — a boundary helper so served callers can key revocation by cert
// fingerprint without importing crypto/* (AN-3).
func CertFingerprintSHA256(certDER []byte) (string, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("mtls: parse certificate: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

// CertNotAfterUnix returns the NotAfter (unix seconds) of the first certificate in a
// PEM chain — a boundary helper so the agent channel can hand the agent its new leaf's
// expiry without importing crypto/x509 (AN-3).
func CertNotAfterUnix(chainPEM []byte) (int64, error) {
	der, err := FirstCertDER(chainPEM)
	if err != nil {
		return 0, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return 0, fmt.Errorf("mtls: parse certificate: %w", err)
	}
	return cert.NotAfter.Unix(), nil
}

// IsCSR reports whether der is a parseable PKCS#10 certificate request — used to
// assert that what an agent transmits during enrollment is a CSR, not a key.
func IsCSR(der []byte) bool {
	_, err := x509.ParseCertificateRequest(der)
	return err == nil
}

// CSRCommonName returns the subject common name of a PKCS#10 CSR (DER) — used by
// enrollment to check a CSR's identity against a token's allowed identity without
// importing crypto/x509 outside the boundary (AN-3).
func CSRCommonName(csrDER []byte) (string, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return "", fmt.Errorf("mtls: parse csr: %w", err)
	}
	return csr.Subject.CommonName, nil
}

// CSRMatchesAllowedIdentity reports whether a PKCS#10 CSR is pinned to exactly
// the allowed identity. The subject common name must match, and every requested
// identity SAN must also match. This lets enrollment reject a stolen bootstrap
// token holder that keeps the right CN but asks for rogue SANs.
func CSRMatchesAllowedIdentity(csrDER []byte, allowedIdentity string) (bool, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return false, fmt.Errorf("mtls: parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return false, fmt.Errorf("mtls: csr signature: %w", err)
	}
	if csr.Subject.CommonName != allowedIdentity {
		return false, nil
	}
	for _, name := range csr.DNSNames {
		if name != allowedIdentity {
			return false, nil
		}
	}
	for _, email := range csr.EmailAddresses {
		if email != allowedIdentity {
			return false, nil
		}
	}
	for _, ip := range csr.IPAddresses {
		if ip.String() != allowedIdentity {
			return false, nil
		}
	}
	for _, uri := range csr.URIs {
		if uri.String() != allowedIdentity {
			return false, nil
		}
	}
	return true, nil
}

// FirstCertDER returns the DER of the first CERTIFICATE block in a PEM chain — the
// leaf the CA issued. It lets callers inspect the issued certificate (e.g. its
// tenant SPIFFE SAN via TenantFromClientCert) without importing encoding/pem or
// crypto/x509 themselves (AN-3).
func FirstCertDER(chainPEM []byte) ([]byte, error) {
	rest := chainPEM
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return block.Bytes, nil
		}
		rest = r
	}
	return nil, errors.New("mtls: no CERTIFICATE block in PEM chain")
}

// LooksLikePrivateKey reports whether der parses as a private key — used to assert
// that a private key is never transmitted.
func LooksLikePrivateKey(der []byte) bool {
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return true
	}
	if _, err := x509.ParseECPrivateKey(der); err == nil {
		return true
	}
	// Also catch a PEM-wrapped key.
	if block, _ := pem.Decode(bytes.TrimSpace(der)); block != nil {
		return block.Type == "PRIVATE KEY" || block.Type == "EC PRIVATE KEY" || block.Type == "RSA PRIVATE KEY"
	}
	return false
}

// Agent roles (epic A2).
//
// An agent's capability has to live in its enrolled identity, not in a flag it
// passes at startup. A flag is something the agent chooses; a certificate is
// something an operator granted. The difference matters most for the network
// role, because a relay holds the credentials that drive appliances — an agent
// that could name itself a relay could name itself into a credential lease.
//
// The role travels as an ADDITIONAL SPIFFE URI SAN alongside the existing
// tenant identity:
//
//	spiffe://trstctl.example/tenant/<tenantID>/agent/<cn>          (identity)
//	spiffe://trstctl.example/tenant/<tenantID>/agent/<cn>/role/... (capability)
//
// Extending the identity SAN's own path would have changed how every already
// enrolled agent's certificate parses. A second SAN is additive: older parsers
// ignore it, and an agent presenting none is read as host-only — the
// conservative default, and the role every agent shipped before A2 actually had.
const (
	// AgentRoleHost executes work on the machine it runs on: deploy a credential
	// to this host's services, verify this host's listeners, restore this host's
	// predecessor bundle.
	AgentRoleHost = "host"
	// AgentRoleNetwork executes work against things in its network segment that
	// cannot run an agent themselves — load balancers, appliances, cloud
	// certificate stores — and probes endpoints from a client's vantage. It holds
	// redeemed appliance credentials, which is why granting it is a deliberate
	// operator act rather than a default.
	AgentRoleNetwork = "network"
)

// AgentRoleSPIFFEID is the capability SAN for one role.
func AgentRoleSPIFFEID(tenantID, cn, role string) string {
	return (&url.URL{
		Scheme: "spiffe",
		Host:   tenantTrustDomain,
		Path:   "/tenant/" + tenantID + "/agent/" + cn + "/role/" + role,
	}).String()
}

// ValidAgentRole reports whether role is one this system grants. Anything else is
// refused at enrollment rather than stamped and puzzled over later.
func ValidAgentRole(role string) bool {
	switch strings.TrimSpace(role) {
	case AgentRoleHost, AgentRoleNetwork:
		return true
	default:
		return false
	}
}

// NormalizeAgentRoles cleans an operator-supplied role list: trimmed, unique,
// known values only, in a stable order. An empty result means host-only, which is
// what an agent with no explicit grant gets.
func NormalizeAgentRoles(roles []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, role := range []string{AgentRoleHost, AgentRoleNetwork} {
		for _, candidate := range roles {
			if strings.TrimSpace(candidate) == role && !seen[role] {
				seen[role] = true
				out = append(out, role)
			}
		}
	}
	return out
}

// AgentRolesFromClientCert reads the capability SANs off a verified agent
// certificate. A certificate carrying none yields host — every agent enrolled
// before roles existed did host work, and reading them as capability-less would
// strand a fleet mid-upgrade.
func AgentRolesFromClientCert(der []byte) ([]string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("mtls: parse agent certificate: %w", err)
	}
	var roles []string
	for _, uri := range cert.URIs {
		if uri == nil || uri.Scheme != "spiffe" || uri.Host != tenantTrustDomain {
			continue
		}
		_, role, found := strings.Cut(uri.Path, "/role/")
		if !found {
			continue
		}
		if ValidAgentRole(role) {
			roles = append(roles, strings.TrimSpace(role))
		}
	}
	if len(roles) == 0 {
		return []string{AgentRoleHost}, nil
	}
	return NormalizeAgentRoles(roles), nil
}
