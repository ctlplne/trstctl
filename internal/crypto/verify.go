package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/smallstep/pkcs7"
)

// VerifyMessage verifies a SHA-256 signature over msg by the public key in
// pubDER (PKIX). It supports ECDSA (ASN.1 signatures) and RSA PKCS#1 v1.5 — the
// shapes a TPM attestation key or a signed cloud identity document use. It is a
// boundary helper so attesters never import crypto/ecdsa or crypto/rsa (AN-3).
func VerifyMessage(pubDER, msg, sig []byte) error {
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return fmt.Errorf("crypto: parse public key: %w", err)
	}
	digest := sha256.Sum256(msg)
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig); err != nil {
			return fmt.Errorf("crypto: RSA signature invalid: %w", err)
		}
		return nil
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest[:], sig) {
			return fmt.Errorf("crypto: ECDSA signature invalid")
		}
		return nil
	default:
		return fmt.Errorf("crypto: unsupported public key type %T", pub)
	}
}

// VerifyEd25519 verifies a detached Ed25519 signature over the exact bytes of
// msg against the public key in pubDER (PKIX). Ed25519 signs the message
// directly (no caller pre-hash), which is what a plugin-provenance signature
// over a `.wasm` artifact uses. It is a boundary helper so the plugin host (and
// any other caller) verifies a signed artifact without importing crypto/ed25519
// itself (AN-3). It fails closed: a non-Ed25519 key, a malformed key, or a bad
// signature all return a non-nil error.
func VerifyEd25519(pubDER, msg, sig []byte) error {
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return fmt.Errorf("crypto: parse Ed25519 public key: %w", err)
	}
	pk, ok := pub.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("crypto: not an Ed25519 public key (got %T)", pub)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("crypto: Ed25519 signature has wrong length %d (want %d)", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pk, msg, sig) {
		return fmt.Errorf("crypto: Ed25519 signature verification failed")
	}
	return nil
}

// ParseEd25519PublicKeyPEM decodes a PEM-wrapped PKIX Ed25519 public key and
// returns its DER (the form VerifyEd25519 expects). Operators configure plugin
// trust as PEM public keys; this turns one into the boundary's DER without the
// caller importing crypto/x509 or encoding/pem (AN-3). It rejects anything that
// is not exactly one Ed25519 public key.
func ParseEd25519PublicKeyPEM(pemBytes []byte) (pubDER []byte, err error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, fmt.Errorf("crypto: no PEM block in Ed25519 public key")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse Ed25519 public key: %w", err)
	}
	if _, ok := pub.(ed25519.PublicKey); !ok {
		return nil, fmt.Errorf("crypto: PEM key is not Ed25519 (got %T)", pub)
	}
	return blk.Bytes, nil
}

// GenerateEd25519KeyPair generates an Ed25519 key pair and returns the public
// key as PKIX/DER (the form ParseEd25519PublicKeyPEM/VerifyEd25519 consume once
// PEM-wrapped) and a closure that produces a detached Ed25519 signature over a
// message. It exists so signing tooling — and the plugin-provenance tests —
// produce/verify signed artifacts entirely inside the crypto boundary (AN-3),
// never importing crypto/ed25519 elsewhere. The private key stays captured in
// the closure and is not returned.
func GenerateEd25519KeyPair() (pubDER []byte, sign func(msg []byte) []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: generate Ed25519 key: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: marshal Ed25519 public key: %w", err)
	}
	return der, func(msg []byte) []byte { return ed25519.Sign(priv, msg) }, nil
}

// GenerateEd25519KeyPEM generates a PEM-wrapped Ed25519 private/public keypair
// for offline signing tools. It lives in the crypto boundary so callers such as
// the license issuer never import crypto/ed25519 or crypto/x509 directly (AN-3).
func GenerateEd25519KeyPEM() (privPEM, pubPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: generate Ed25519 key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: marshal Ed25519 private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: marshal Ed25519 public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), nil
}

// SignEd25519 signs msg using a PEM-wrapped PKCS#8 Ed25519 private key. The
// helper exists for offline issuer tooling and tests while keeping private-key
// parsing and Ed25519 imports inside the crypto boundary (AN-3).
func SignEd25519(privPEM, msg []byte) ([]byte, error) {
	blk, _ := pem.Decode(privPEM)
	if blk == nil {
		return nil, fmt.Errorf("crypto: no PEM block in Ed25519 private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse Ed25519 private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("crypto: PEM key is not Ed25519 (got %T)", key)
	}
	return ed25519.Sign(priv, msg), nil
}

// MarshalPublicKeyPEM wraps a PKIX/DER public key in a PEM "PUBLIC KEY" block,
// the textual form operators paste into a trust policy. It keeps encoding/pem
// out of callers (AN-3).
func MarshalPublicKeyPEM(pubDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
}

// SignMessage signs a SHA-256 digest of msg with signer and returns a signature
// in the form VerifyMessage expects (ECDSA ASN.1 or RSA PKCS#1 v1.5). It pairs
// with VerifyMessage so callers (and attester tests) can produce signed quotes /
// documents without importing crypto/sha256 themselves (AN-3).
func SignMessage(signer DigestSigner, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	return signer.SignDigest(digest[:], SignOptions{Hash: SHA256, RSAPadding: RSAPKCS1v15})
}

// PublicKeyDERFromCert returns the PKIX-encoded public key of a DER certificate.
// Attesters use it to recover the key that signed a quote from its (chain-checked)
// certificate without importing crypto/x509 (AN-3).
func PublicKeyDERFromCert(certDER []byte) ([]byte, error) {
	c, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse cert: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(c.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal public key: %w", err)
	}
	return der, nil
}

// VerifyCMSSignature verifies a PKCS#7 / CMS SignedData (the form AWS and Azure
// use for their signed instance-identity documents): it checks the signature and
// that the signer chains to one of the trusted roots, then returns the signed
// content. A document whose signer does not chain to a trusted root is rejected.
func VerifyCMSSignature(p7DER []byte, rootsDER [][]byte) (content []byte, err error) {
	// Untrusted input (the caller-supplied cloud IID document is parsed BEFORE
	// any trust is established): route through safeParsePKCS7 so a malformed
	// document fails closed with an error instead of panicking (FUZZ-001).
	p7, err := safeParsePKCS7(p7DER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse CMS: %w", err)
	}
	if len(rootsDER) == 0 {
		return nil, fmt.Errorf("crypto: no trusted roots for CMS verification")
	}
	pool := x509.NewCertPool()
	for _, r := range rootsDER {
		c, err := x509.ParseCertificate(r)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse CMS root: %w", err)
		}
		pool.AddCert(c)
	}
	if err := p7.VerifyWithChain(pool); err != nil {
		return nil, fmt.Errorf("crypto: CMS verification failed: %w", err)
	}
	return p7.Content, nil
}

// SignCMS builds a PKCS#7 SignedData over content, signed by a freshly generated
// certificate, and returns the message together with that signer certificate
// (DER) to be used as the trust root. It models an external CMS producer (a cloud
// metadata signer) so the AWS/Azure attesters can be tested without importing
// crypto/* outside this boundary (AN-3).
func SignCMS(content []byte) (p7DER, signerCertDER []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: generate CMS key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "trstctl CMS signer"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: create CMS signer cert: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: new CMS: %w", err)
	}
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, nil, fmt.Errorf("crypto: add CMS signer: %w", err)
	}
	der, err := sd.Finish()
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: finish CMS: %w", err)
	}
	return der, certDER, nil
}
