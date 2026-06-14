// Package ssh implements the SSH certificate authority (S13.1, F43): it signs
// short-lived OpenSSH host and user certificates — a first-class credential type
// distinct from X.509 — with principals, validity windows, and critical
// options/extensions, and maintains a key-revocation list (KRL).
//
// The SSH CA is chainless and is another implementation behind the
// internal/crypto boundary (AN-3), not a parallel crypto stack: signing routes
// through crypto.SignSSHCertificate and the CA key is a DigestSigner that can live
// in the isolated signer (AN-4) and be HSM-backed (AN-8). Issuance is
// profile-governed, audited (AN-2), and bulkheaded (AN-7).
package ssh

import (
	"context"
	"fmt"
	"sync"
	"time"

	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/bulkhead"
	"trustctl.io/trustctl/internal/crypto"
)

// Profile governs SSH issuance.
type Profile struct {
	Name              string
	MaxTTL            time.Duration
	AllowUserCerts    bool
	AllowHostCerts    bool
	DefaultExtensions map[string]string // e.g. permit-pty, permit-port-forwarding
}

// IssueRequest is a request to issue an SSH certificate.
type IssueRequest struct {
	SubjectPublicKey []byte // the subject's SSH public key (authorized_keys form)
	KeyID            string
	Principals       []string
	TTL              time.Duration
	CriticalOptions  map[string]string // e.g. force-command, source-address
	Extensions       map[string]string
}

// Issued is the result of an SSH issuance.
type Issued struct {
	Certificate []byte // authorized_keys form
	Serial      uint64
	KeyID       string
	ValidBefore time.Time
}

// Config configures the SSH CA.
type Config struct {
	TenantID string
	Signer   crypto.DigestSigner // the SSH CA key (HSM-backed where configured)
	Pool     *bulkhead.Pool
	Audit    auditsink.Auditor
	KRL      *KRL
	Clock    func() time.Time
}

// CA is the SSH certificate authority.
type CA struct {
	cfg    Config
	mu     sync.Mutex
	serial uint64
}

// New validates configuration and constructs a CA.
func New(cfg Config) (*CA, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("ssh: TenantID required (AN-1)")
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("ssh: CA Signer required")
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &CA{cfg: cfg}, nil
}

// AuthorityKey returns the CA's SSH public key (authorized_keys form), for use in
// sshd's TrustedUserCAKeys and @cert-authority known_hosts lines.
func (ca *CA) AuthorityKey() ([]byte, error) {
	return crypto.SSHPublicKeyFromSigner(ca.cfg.Signer)
}

// IssueUserCert signs an SSH user certificate under the profile.
func (ca *CA) IssueUserCert(ctx context.Context, profile Profile, req IssueRequest) (Issued, error) {
	if !profile.AllowUserCerts {
		return Issued{}, fmt.Errorf("ssh: profile %q does not allow user certificates", profile.Name)
	}
	return ca.issue(ctx, profile, req, crypto.SSHUserCert)
}

// IssueHostCert signs an SSH host certificate under the profile.
func (ca *CA) IssueHostCert(ctx context.Context, profile Profile, req IssueRequest) (Issued, error) {
	if !profile.AllowHostCerts {
		return Issued{}, fmt.Errorf("ssh: profile %q does not allow host certificates", profile.Name)
	}
	return ca.issue(ctx, profile, req, crypto.SSHHostCert)
}

func (ca *CA) issue(ctx context.Context, profile Profile, req IssueRequest, certType uint32) (Issued, error) {
	if len(req.Principals) == 0 {
		return Issued{}, fmt.Errorf("ssh: at least one principal is required")
	}
	ttl := req.TTL
	if ttl <= 0 {
		return Issued{}, fmt.Errorf("ssh: TTL required")
	}
	if profile.MaxTTL > 0 && ttl > profile.MaxTTL {
		return Issued{}, fmt.Errorf("ssh: TTL %s exceeds profile max %s", ttl, profile.MaxTTL)
	}

	var out Issued
	err := ca.run(func() error {
		now := ca.cfg.Clock()
		ca.mu.Lock()
		ca.serial++
		serial := ca.serial
		ca.mu.Unlock()

		ext := map[string]string{}
		for k, v := range profile.DefaultExtensions {
			ext[k] = v
		}
		for k, v := range req.Extensions {
			ext[k] = v
		}
		validBefore := now.Add(ttl)
		certB, err := crypto.SignSSHCertificate(ca.cfg.Signer, crypto.SSHCertParams{
			SubjectPublicKey: req.SubjectPublicKey,
			KeyID:            req.KeyID,
			Principals:       req.Principals,
			CertType:         certType,
			ValidAfter:       now.Add(-time.Minute),
			ValidBefore:      validBefore,
			CriticalOptions:  req.CriticalOptions,
			Extensions:       ext,
			Serial:           serial,
		})
		if err != nil {
			return err
		}
		out = Issued{Certificate: certB, Serial: serial, KeyID: req.KeyID, ValidBefore: validBefore}
		kind := "user"
		if certType == crypto.SSHHostCert {
			kind = "host"
		}
		_ = ca.cfg.Audit.Audit(ctx, "ssh.cert.issued", ca.cfg.TenantID,
			[]byte(fmt.Sprintf(`{"type":%q,"key_id":%q,"serial":%d,"principals":%d,"profile":%q}`,
				kind, req.KeyID, serial, len(req.Principals), profile.Name)))
		return nil
	})
	if err != nil {
		return Issued{}, err
	}
	return out, nil
}

func (ca *CA) run(fn func() error) error {
	if ca.cfg.Pool == nil {
		return fn()
	}
	errc := make(chan error, 1)
	if err := ca.cfg.Pool.Submit(func() { errc <- fn() }); err != nil {
		return err
	}
	return <-errc
}

// KRL is an SSH key-revocation list: a distributable registry of revoked
// certificate serials and key IDs that sshd consults to reject revoked certs.
type KRL struct {
	mu      sync.Mutex
	serials map[uint64]bool
	keyIDs  map[string]bool
}

// NewKRL constructs an empty KRL.
func NewKRL() *KRL {
	return &KRL{serials: map[uint64]bool{}, keyIDs: map[string]bool{}}
}

// RevokeSerial revokes a certificate by serial.
func (k *KRL) RevokeSerial(serial uint64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.serials[serial] = true
}

// RevokeKeyID revokes all certificates with the given key id.
func (k *KRL) RevokeKeyID(keyID string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keyIDs[keyID] = true
}

// IsRevoked reports whether a certificate (by serial or key id) is revoked.
func (k *KRL) IsRevoked(serial uint64, keyID string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.serials[serial] || k.keyIDs[keyID]
}

// Snapshot is the distributable form of a KRL.
type Snapshot struct {
	Serials []uint64 `json:"serials"`
	KeyIDs  []string `json:"key_ids"`
}

// Distribute returns a snapshot of the KRL for distribution to hosts.
func (k *KRL) Distribute() Snapshot {
	k.mu.Lock()
	defer k.mu.Unlock()
	s := Snapshot{}
	for serial := range k.serials {
		s.Serials = append(s.Serials, serial)
	}
	for id := range k.keyIDs {
		s.KeyIDs = append(s.KeyIDs, id)
	}
	return s
}
