// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Edge-host local operations (epic B6): the key/CSR the host generates before
// asking for a delegation, and the local leaf issuance it performs while it
// has no path to the brain. Both live inside the crypto boundary (AN-3) — the
// agent binary calls these, it never touches crypto/* itself.
//
// The normal path stores the delegated CA key behind an opaque TPM 2.0 or
// PKCS#11 handle. The compatibility software path is intentionally separate:
// callers must opt into it and accept custody evidence that says EXPORTABLE.
// In either path the certificate itself carries the name constraints, path
// length zero, and short expiry that bound what the disconnected host can mint.

// EdgeCAKeyProvider is the minimum hardware/device contract used by a
// disconnected edge CA. It can create a persistent non-extractable key and sign
// a digest by opaque reference. No method returns private-key bytes.
type EdgeCAKeyProvider interface {
	Name() string
	RemoteKeyLifecycle
	RemoteKeyDigestSigner
}

// EdgeCAKeyHandle is the public, durable half of a device-held edge CA key. It is
// safe to persist beside the agent: KeyID is an opaque TPM persistent handle or
// PKCS#11 object identifier and PublicKeyDER is SPKI public data. Neither field
// can recreate or export the private key.
type EdgeCAKeyHandle struct {
	Version      int       `json:"version"`
	Provider     string    `json:"provider"`
	KeyID        string    `json:"key_id"`
	Algorithm    Algorithm `json:"algorithm"`
	PublicKeyDER []byte    `json:"public_key_der"`
}

const edgeCAKeyHandleVersion = 1

// GenerateEdgeCAKeyHandleAndCSR creates or re-opens the provider key owned by
// operationID, then has that key self-sign a CSR. operationID is durable so a
// retry after a process crash finds the first key instead of silently creating
// an orphaned second CA key.
func GenerateEdgeCAKeyHandleAndCSR(ctx context.Context, operationID, commonName string, algorithm Algorithm, provider EdgeCAKeyProvider) (EdgeCAKeyHandle, []byte, error) {
	if provider == nil {
		return EdgeCAKeyHandle{}, nil, fmt.Errorf("crypto: edge CA key provider is required")
	}
	if strings.TrimSpace(operationID) == "" {
		return EdgeCAKeyHandle{}, nil, fmt.Errorf("crypto: edge CA hardware generation needs a durable operation id")
	}
	if strings.TrimSpace(commonName) == "" {
		return EdgeCAKeyHandle{}, nil, fmt.Errorf("crypto: edge CA CSR needs a common name")
	}
	if strings.TrimSpace(provider.Name()) == "" {
		return EdgeCAKeyHandle{}, nil, fmt.Errorf("crypto: edge CA key provider reports no name")
	}
	lifecycle, ok := provider.(OperationAwareRemoteKeyLifecycle)
	if !ok {
		return EdgeCAKeyHandle{}, nil, fmt.Errorf("crypto: edge CA key provider %q cannot reconcile generation after a crash", provider.Name())
	}
	signer, ref, err := lifecycle.GenerateManagedKeyForOperation(ctx, operationID, algorithm)
	if err != nil {
		return EdgeCAKeyHandle{}, nil, fmt.Errorf("crypto: generate edge CA key in %s: %w", provider.Name(), err)
	}
	if ref.ID == "" || ref.Algorithm != algorithm || signer.Algorithm() != algorithm || len(signer.Public().DER) == 0 {
		return EdgeCAKeyHandle{}, nil, fmt.Errorf("crypto: edge CA key provider %q returned incomplete or inconsistent key metadata", provider.Name())
	}
	if err := validateEdgeHandlePublicAlgorithm(signer.Public().DER, algorithm); err != nil {
		return EdgeCAKeyHandle{}, nil, err
	}
	handle := EdgeCAKeyHandle{
		Version: edgeCAKeyHandleVersion, Provider: provider.Name(), KeyID: ref.ID,
		Algorithm: algorithm, PublicKeyDER: append([]byte(nil), signer.Public().DER...),
	}
	digestSigner := edgeCAHandleDigestSigner{ctx: ctx, provider: provider, handle: handle}
	csrDER, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: strings.TrimSpace(commonName)}, digestSigner)
	if err != nil {
		return EdgeCAKeyHandle{}, nil, fmt.Errorf("crypto: create edge CA CSR with %s key: %w", provider.Name(), err)
	}
	return handle, csrDER, nil
}

type edgeCAHandleDigestSigner struct {
	ctx      context.Context
	provider EdgeCAKeyProvider
	handle   EdgeCAKeyHandle
}

func (s edgeCAHandleDigestSigner) Public() PublicKey {
	return PublicKey{Algorithm: s.handle.Algorithm, DER: append([]byte(nil), s.handle.PublicKeyDER...)}
}

func (s edgeCAHandleDigestSigner) Algorithm() Algorithm { return s.handle.Algorithm }

func (s edgeCAHandleDigestSigner) SignDigest(digest []byte, opts SignOptions) ([]byte, error) {
	return s.provider.SignManagedDigest(s.ctx, KeyRef{ID: s.handle.KeyID, Algorithm: s.handle.Algorithm}, digest, opts)
}

// GenerateEdgeCAKeyAndCSR creates the edge CA's keypair locally and a CSR over
// it. The private key never travels: only the CSR does, and the mint's proof
// of possession is the CSR's self-signature.
func GenerateEdgeCAKeyAndCSR(commonName string) (keyPEM, csrDER []byte, err error) {
	if strings.TrimSpace(commonName) == "" {
		return nil, nil, fmt.Errorf("crypto: edge CA CSR needs a common name")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: generate edge CA key: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: marshal edge CA key: %w", err)
	}
	defer secret.Wipe(keyDER)
	csrDER, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: strings.TrimSpace(commonName)},
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: create edge CA CSR: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return keyPEM, csrDER, nil
}

// EdgeLeafRequest is one local issuance on the edge host.
type EdgeLeafRequest struct {
	CommonName string
	DNSNames   []string
	TTL        time.Duration
}

// EdgeIssuedLeaf is the locally issued certificate and its key. The
// certificate is what the journal records for reconciliation; the KEY goes
// only to the workload's key file and never into the journal — the brain has
// no business holding it.
type EdgeIssuedLeaf struct {
	SerialHex      string
	CertificateDER []byte
	CertificatePEM []byte
	LeafKeyPEM     []byte
	NotAfter       time.Time
}

// IssueEdgeLeaf issues one leaf locally under a delegated edge CA. The
// CONSTRAINTS COME FROM THE CERTIFICATE — the permitted and excluded name
// subtrees and the CA's own expiry are read from the delegation itself, so a
// tampered local config cannot widen what the brain delegated. The same check
// the brain applies at reconciliation applies here first: an out-of-constraint
// request fails closed on the edge host, it does not become a certificate that
// gets flagged later.
func IssueEdgeLeaf(delegationCertPEM, delegationKeyPEM []byte, req EdgeLeafRequest, now time.Time) (EdgeIssuedLeaf, error) {
	keyBlock, _ := pem.Decode(delegationKeyPEM)
	if keyBlock == nil {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: delegated CA key PEM has no block")
	}
	defer secret.Wipe(keyBlock.Bytes)
	caKey, err := NewLockedSignerFromPKCS8(ECDSAP256, keyBlock.Bytes)
	if err != nil {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: parse delegated CA key: %w", err)
	}
	defer caKey.Destroy()
	return issueEdgeLeafWithSigner(delegationCertPEM, caKey, req, now)
}

// IssueEdgeLeafWithKeyHandle issues through a reopened TPM/PKCS#11 session. It
// first binds all three public claims — provider name, handle public key, and
// delegation certificate public key — before asking the device to sign.
func IssueEdgeLeafWithKeyHandle(ctx context.Context, delegationCertPEM []byte, handle EdgeCAKeyHandle, provider EdgeCAKeyProvider, req EdgeLeafRequest, now time.Time) (EdgeIssuedLeaf, error) {
	if provider == nil {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: edge CA key provider is required")
	}
	if handle.Version != edgeCAKeyHandleVersion || handle.KeyID == "" || handle.Algorithm == "" || len(handle.PublicKeyDER) == 0 {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: edge CA public key handle is incomplete or has an unsupported version")
	}
	if handle.Provider != provider.Name() {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: edge CA handle provider %q does not match opened provider %q", handle.Provider, provider.Name())
	}
	if err := validateEdgeHandlePublicAlgorithm(handle.PublicKeyDER, handle.Algorithm); err != nil {
		return EdgeIssuedLeaf{}, err
	}
	return issueEdgeLeafWithSigner(delegationCertPEM, edgeCAHandleDigestSigner{
		ctx: ctx, provider: provider, handle: handle,
	}, req, now)
}

func validateEdgeHandlePublicAlgorithm(der []byte, algorithm Algorithm) error {
	public, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return fmt.Errorf("crypto: parse edge CA public key handle: %w", err)
	}
	valid := false
	switch key := public.(type) {
	case *ecdsa.PublicKey:
		bits := key.Curve.Params().BitSize
		valid = (algorithm == ECDSAP256 && bits == 256) ||
			(algorithm == ECDSAP384 && bits == 384) ||
			(algorithm == ECDSAP521 && bits == 521)
	case *rsa.PublicKey:
		bits := key.N.BitLen()
		valid = (algorithm == RSA2048 && bits == 2048) ||
			(algorithm == RSA3072 && bits == 3072) ||
			(algorithm == RSA4096 && bits == 4096)
	}
	if !valid {
		return fmt.Errorf("crypto: edge CA public key does not match declared algorithm %s", algorithm)
	}
	return nil
}

func issueEdgeLeafWithSigner(delegationCertPEM []byte, caSigner DigestSigner, req EdgeLeafRequest, now time.Time) (EdgeIssuedLeaf, error) {
	block, _ := pem.Decode(delegationCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: delegated CA PEM has no certificate block")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: parse delegated CA certificate: %w", err)
	}
	public, err := x509.MarshalPKIXPublicKey(caCert.PublicKey)
	if err != nil {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: marshal delegated CA public key: %w", err)
	}
	if !bytes.Equal(public, caSigner.Public().DER) {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: delegated CA certificate public key does not match edge CA public key handle")
	}
	adapter, err := newX509Signer(caSigner)
	if err != nil {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: open edge CA signer: %w", err)
	}

	constraints := EdgeConstraints{
		PermittedDNSDomains: append([]string(nil), caCert.PermittedDNSDomains...),
		ExcludedDNSDomains:  append([]string(nil), caCert.ExcludedDNSDomains...),
		NotAfter:            caCert.NotAfter,
	}
	names := req.DNSNames
	if len(names) == 0 && strings.TrimSpace(req.CommonName) != "" {
		names = []string{strings.TrimSpace(req.CommonName)}
	}
	if err := CheckEdgeIssuance(constraints, names, nil, now); err != nil {
		return EdgeIssuedLeaf{}, err
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	notAfter := EdgeLeafNotAfter(constraints, now.Add(ttl))
	serial, err := randomSerial()
	if err != nil {
		return EdgeIssuedLeaf{}, err
	}
	leafKeyless := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: strings.TrimSpace(req.CommonName)},
		DNSNames:     names,
		NotBefore:    IssuanceNotBefore(now),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	// The leaf's key is generated here too: the edge issues complete identity
	// material for the workload beside it.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: generate leaf key: %w", err)
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: marshal leaf key: %w", err)
	}
	defer secret.Wipe(leafKeyDER)
	der, err := x509.CreateCertificate(rand.Reader, leafKeyless, caCert, &leafKey.PublicKey, adapter)
	if err != nil {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: sign edge leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return EdgeIssuedLeaf{}, err
	}
	// PublicKeyDER is persisted outside the device, so it proves what the
	// certificate expects but cannot by itself prove that KeyID still resolves
	// to that same object. Verify the produced signature before returning it.
	// A swapped/stale handle must fail here instead of writing an unusable leaf.
	if err := leaf.CheckSignatureFrom(caCert); err != nil {
		return EdgeIssuedLeaf{}, fmt.Errorf("crypto: edge CA handle signed with a key that does not match the delegation certificate: %w", err)
	}
	return EdgeIssuedLeaf{
		SerialHex:      leaf.SerialNumber.Text(16),
		CertificateDER: der,
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		LeafKeyPEM:     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER}),
		NotAfter:       leaf.NotAfter,
	}, nil
}
