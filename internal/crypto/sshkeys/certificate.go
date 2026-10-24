// SPDX-License-Identifier: BUSL-1.1

package sshkeys

import (
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
)

// maxCertificateFileBytes bounds one *-cert.pub file. An OpenSSH certificate
// with a 16 KiB RSA key and many principals stays far below it.
const maxCertificateFileBytes = 64 << 10

// CertificateInfo is the inventory metadata of one OpenSSH certificate (A115):
// what it certifies, which CA key signed it, and when it is valid. A host's
// served HostCertificate says whether the host presents an identity an SSH CA
// vouches for; the signing CA's fingerprint says which one.
type CertificateInfo struct {
	// Kind is "host" or "user".
	Kind string
	// KeyType and KeyFingerprintSHA256 identify the certified public key.
	KeyType              string
	KeyFingerprintSHA256 string
	// CAType and CAFingerprintSHA256 identify the CA key the certificate names
	// as its signer.
	CAType              string
	CAFingerprintSHA256 string
	// SignatureVerified is true only when the certificate's signature verifies
	// with that CA key. A certificate that names a CA but does not verify
	// vouches for nothing, whatever it names.
	SignatureVerified bool
	KeyID             string
	Serial            uint64
	Principals        []string
	// ValidAfter and ValidBefore bound the validity window. Forever reports
	// OpenSSH's unbounded end ("forever"); ValidBefore is then zero.
	ValidAfter  time.Time
	ValidBefore time.Time
	Forever     bool
}

// ParseCertificate parses one OpenSSH certificate in authorized_keys form (the
// content of a *-cert.pub file) and verifies its signature with the CA key it
// names. A plain public key is not a certificate and is refused.
func ParseCertificate(data []byte) (CertificateInfo, error) {
	if len(data) > maxCertificateFileBytes {
		return CertificateInfo{}, errors.New("sshkeys: certificate file is too large")
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return CertificateInfo{}, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return CertificateInfo{}, errors.New("sshkeys: not an OpenSSH certificate")
	}
	info := CertificateInfo{
		KeyType: cert.Key.Type(), KeyFingerprintSHA256: ssh.FingerprintSHA256(cert.Key),
		KeyID: cert.KeyId, Serial: cert.Serial, Principals: append([]string(nil), cert.ValidPrincipals...),
	}
	switch cert.CertType {
	case ssh.HostCert:
		info.Kind = "host"
	case ssh.UserCert:
		info.Kind = "user"
	default:
		return CertificateInfo{}, errors.New("sshkeys: certificate is neither a host nor a user certificate")
	}
	if cert.SignatureKey == nil {
		return CertificateInfo{}, errors.New("sshkeys: certificate names no signing CA")
	}
	info.CAType = cert.SignatureKey.Type()
	info.CAFingerprintSHA256 = ssh.FingerprintSHA256(cert.SignatureKey)
	info.SignatureVerified = verifyCertificateSignature(cert) == nil
	info.ValidAfter = certificateTime(cert.ValidAfter)
	if cert.ValidBefore == ssh.CertTimeInfinity {
		info.Forever = true
	} else {
		info.ValidBefore = certificateTime(cert.ValidBefore)
	}
	return info, nil
}

// verifyCertificateSignature checks the CA signature over the certificate's
// signed bytes: the certificate as marshalled without its signature, less the
// empty signature's length prefix (PROTOCOL.certkeys).
func verifyCertificateSignature(cert *ssh.Certificate) error {
	if cert.Signature == nil {
		return errors.New("sshkeys: certificate is unsigned")
	}
	unsigned := *cert
	unsigned.Signature = nil
	signed := unsigned.Marshal()
	if len(signed) < 4 {
		return errors.New("sshkeys: certificate encoding is truncated")
	}
	return cert.SignatureKey.Verify(signed[:len(signed)-4], cert.Signature)
}

// maxCertificateUnix is 9999-12-31T23:59:59Z, the last second RFC 3339 writes.
const maxCertificateUnix = 253402300799

// certificateTime converts an OpenSSH certificate timestamp (unsigned seconds
// since the epoch) without wrapping: a later value is clamped to the last
// second a report can carry.
func certificateTime(seconds uint64) time.Time {
	if seconds > maxCertificateUnix {
		seconds = maxCertificateUnix
	}
	return time.Unix(int64(seconds), 0).UTC() // #nosec G115 -- clamped to maxCertificateUnix above (CWE-190)
}
