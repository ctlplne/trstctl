// Package destination installs an issued credential — a certificate and,
// optionally, its private key — to a place on the host where a workload
// consumes it. The agent generates and holds the key locally (S5.1); a
// destination is where that material lands.
//
// Two destinations ship here: a filesystem destination that writes PEM files
// with correct permissions, and a PKCS#11 destination that stores the key and
// certificate as objects on a hardware (or software) token. Neither parses the
// PEM — credentials are opaque bytes — so this package holds no crypto/*
// imports (AN-3). Key material is carried as []byte, never string (AN-8).
package destination

import "context"

// Credential is the material to install: a PEM certificate chain and,
// optionally, its PEM-encoded private key. When KeyPEM is empty the key is
// expected to already reside in the destination (for example, generated inside
// an HSM), and only the certificate is installed.
type Credential struct {
	// KeyPEM is the PEM-encoded private key, or nil if the destination holds
	// the key itself. It is []byte (not string) so it can be zeroed (AN-8).
	KeyPEM []byte
	// CertPEM is the PEM-encoded certificate chain.
	CertPEM []byte
}

// HasKey reports whether the credential carries a private key to install.
func (c Credential) HasKey() bool { return len(c.KeyPEM) > 0 }

// Destination is a place an issued credential is installed on the host.
type Destination interface {
	// Install writes the credential to the destination. It is idempotent:
	// installing the same credential twice leaves the destination in the same
	// state, with the same access controls, as installing it once.
	Install(ctx context.Context, cred Credential) error
	// Describe returns a short, human-readable identifier for logs and errors.
	Describe() string
}

// KeyAttributes mirrors the PKCS#11 access-control attributes of a private-key
// object. For a key under hardware custody, Sensitive and Token are set,
// Extractable is clear, and Private is set — the key persists on the token,
// requires authentication to use, and cannot be read back out.
type KeyAttributes struct {
	Sensitive   bool // CKA_SENSITIVE: the key value cannot be revealed in plaintext.
	Extractable bool // CKA_EXTRACTABLE: the key can be wrapped/exported off the token.
	Private     bool // CKA_PRIVATE: the object requires authentication to access.
	Token       bool // CKA_TOKEN: the object persists on the token (not session-only).
}

// Token is the subset of a PKCS#11 token the PKCS11 destination drives. The
// production implementation wraps a real PKCS#11 module (for example SoftHSM or
// a hardware HSM via miekg/pkcs11, which needs CGO and the native module);
// tests and CI use the in-process software token in the softtoken subpackage.
type Token interface {
	// ImportKey stores a PEM private key as a token-resident private-key
	// object under (label, id) with hardware-custody attributes (sensitive,
	// non-extractable, private, token).
	ImportKey(label string, id []byte, keyPEM []byte) error
	// ImportCertificate stores a PEM certificate as a token object under
	// (label, id).
	ImportCertificate(label string, id []byte, certPEM []byte) error
	// FindCertificate returns the certificate object stored under label.
	FindCertificate(label string) (certPEM []byte, found bool, err error)
	// KeyAttributes returns the access-control attributes of the private-key
	// object stored under label.
	KeyAttributes(label string) (KeyAttributes, bool, error)
}
