package crypto

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
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
		ValidAfter:      uint64(p.ValidAfter.Unix()),
		ValidBefore:     uint64(p.ValidBefore.Unix()),
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
