// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// SSH certificate signing lives inside the crypto boundary (AN-3): the SSH CA is
// another implementation behind the one boundary, not a parallel stack. The CA
// private key is a DigestSigner, so it can live in the isolated signer (AN-4) and
// be HSM-backed where configured.

// SSH certificate types (re-exported so callers don't import x/crypto/ssh just for
// the constants).
const (
	SSHUserCert = ssh.UserCert
	SSHHostCert = ssh.HostCert
)

// SSHCertParams configures an OpenSSH certificate to sign.
type SSHCertParams struct {
	SubjectPublicKey []byte // the subject's SSH public key (authorized_keys form)
	KeyID            string
	Principals       []string
	CertType         uint32 // SSHUserCert or SSHHostCert
	ValidAfter       time.Time
	ValidBefore      time.Time
	CriticalOptions  map[string]string
	Extensions       map[string]string
	Serial           uint64
}

// SignSSHCertificate signs an OpenSSH host or user certificate with the CA
// DigestSigner and returns it in authorized_keys (wire) form. The CA key never
// leaves the signer.
func SignSSHCertificate(caSigner DigestSigner, p SSHCertParams) ([]byte, error) {
	if p.CertType != ssh.UserCert && p.CertType != ssh.HostCert {
		return nil, fmt.Errorf("crypto: invalid SSH certificate type %d", p.CertType)
	}
	// The validity window is enforced here, at the boundary, not left to the
	// caller: SignSSHCertificate is exported, and Unix() on a zero or pre-epoch
	// time.Time is negative, which the uint64 conversion below would wrap into a
	// far-future ValidBefore -- an OpenSSH certificate that never expires.
	if p.ValidAfter.IsZero() || p.ValidBefore.IsZero() {
		return nil, fmt.Errorf("crypto: SSH certificate validity window required")
	}
	if p.ValidAfter.Unix() < 0 || p.ValidBefore.Unix() < 0 {
		return nil, fmt.Errorf("crypto: SSH certificate validity window predates the Unix epoch")
	}
	if !p.ValidBefore.After(p.ValidAfter) {
		return nil, fmt.Errorf("crypto: SSH certificate ValidBefore must be after ValidAfter")
	}
	subjectKey, _, _, _, err := ssh.ParseAuthorizedKey(p.SubjectPublicKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse subject SSH key: %w", err)
	}
	cert := &ssh.Certificate{
		Key:             subjectKey,
		Serial:          p.Serial,
		CertType:        p.CertType,
		KeyId:           p.KeyID,
		ValidPrincipals: p.Principals,
		ValidAfter:      uint64(p.ValidAfter.Unix()),  // #nosec G115 -- certificate validity epoch seconds; non-negative by validation (CWE-190)
		ValidBefore:     uint64(p.ValidBefore.Unix()), // #nosec G115 -- certificate validity epoch seconds; non-negative by validation (CWE-190)
		Permissions: ssh.Permissions{
			CriticalOptions: p.CriticalOptions,
			Extensions:      p.Extensions,
		},
	}
	authority, err := sshSignerFromDigestSigner(caSigner)
	if err != nil {
		return nil, err
	}
	if err := cert.SignCert(rand.Reader, authority); err != nil {
		return nil, fmt.Errorf("crypto: sign SSH certificate: %w", err)
	}
	return ssh.MarshalAuthorizedKey(cert), nil
}

// SSHPublicKeyFromSigner converts a signer's public key into SSH authorized_keys
// form (used for the subject key in tests and for the CA trust-anchor line in
// TrustedUserCAKeys / @cert-authority known_hosts).
func SSHPublicKeyFromSigner(s DigestSigner) ([]byte, error) {
	pub, err := x509.ParsePKIXPublicKey(s.Public().DER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse public key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("crypto: ssh public key: %w", err)
	}
	return ssh.MarshalAuthorizedKey(sshPub), nil
}

// SSHSigner adapts a signer to an SSH signer for SSH clients and servers
// inside the crypto boundary (the access gateway's host and session keys,
// A254); the private key stays in the signer's custody.
func SSHSigner(ds DigestSigner) (ssh.Signer, error) { return sshSignerFromDigestSigner(ds) }

func sshSignerFromDigestSigner(ds DigestSigner) (ssh.Signer, error) {
	adapter, err := newX509Signer(ds) // DigestSigner -> crypto.Signer (inside the boundary)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromSigner(adapter)
	if err != nil {
		return nil, fmt.Errorf("crypto: build SSH authority signer: %w", err)
	}
	return signer, nil
}

// GenerateSSHClientKey generates an Ed25519 key pair for an SSH certificate
// lease (A239-L11): the private key in OpenSSH form for the lease's holder,
// and the public key in authorized_keys form for the CA to certify. The caller
// owns the private key bytes and MUST secret.Wipe them once sealed or handed
// off; the generated key is wiped here.
func GenerateSSHClientKey(comment string) (private, public []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: generate SSH key: %w", err)
	}
	defer wipeStdlibKey(priv)
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: marshal SSH key: %w", err)
	}
	private = pem.EncodeToMemory(block)
	secret.Wipe(block.Bytes)
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		secret.Wipe(private)
		return nil, nil, fmt.Errorf("crypto: SSH public key: %w", err)
	}
	return private, ssh.MarshalAuthorizedKey(sshPub), nil
}

// SSHAuthorizedKeyOfPrivateKey returns the authorized_keys form of an OpenSSH
// private key's public half (a prepared SSH lease key, A239-L11). It never
// returns or keeps the private key.
func SSHAuthorizedKeyOfPrivateKey(private []byte) ([]byte, error) {
	signer, err := ssh.ParsePrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse SSH private key: %w", err)
	}
	return ssh.MarshalAuthorizedKey(signer.PublicKey()), nil
}
