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
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto"
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
		_ = auditsink.Emit(ctx, ca.cfg.Audit, nil, "ssh.cert.issued", ca.cfg.TenantID,
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

// OpenSSH KRL binary-format constants (from OpenSSH PROTOCOL.krl). The artifact
// produced by DistributeKRL is exactly what sshd's RevokedKeys directive and
// `ssh-keygen -Q -f` consume (INTEROP-009): a JSON snapshot cannot be loaded by
// stock OpenSSH, so SSH-cert revocation never reaches hosts without this encoding.
const (
	krlMagic         = "SSHKRL\n\x00" // 8-byte file magic
	krlFormatVersion = 1

	krlSectionCertificates = 1 // top-level section: revocations by issuing CA

	krlSectionCertSerialList = 0x20 // cert sub-section: explicit uint64 serial list
	krlSectionCertKeyID      = 3    // cert sub-section: list of revoked key-id strings
)

// DistributeKRL returns the KRL in the OpenSSH binary KRL format (PROTOCOL.krl), the
// artifact sshd's RevokedKeys consumes and `ssh-keygen -Qf <krl>` reads. krlVersion
// is the monotonic KRL version number a host uses to reject an older KRL; pass a
// counter that increases each time the revocation set changes.
//
// The revocations are emitted under the "wildcard" CA (an empty ca_key string), so
// they apply to certificates from any issuing CA — matching this KRL's CA-agnostic
// serial/key-id model. Serials are written as an explicit serial list and key IDs as
// a key-id list; both sub-sections are omitted when empty.
func (k *KRL) DistributeKRL(krlVersion uint64) []byte {
	k.mu.Lock()
	serials := make([]uint64, 0, len(k.serials))
	for s := range k.serials {
		serials = append(serials, s)
	}
	keyIDs := make([]string, 0, len(k.keyIDs))
	for id := range k.keyIDs {
		keyIDs = append(keyIDs, id)
	}
	k.mu.Unlock()
	// Deterministic output (stable across runs) so the artifact is reproducible and
	// testable.
	sort.Slice(serials, func(i, j int) bool { return serials[i] < serials[j] })
	sort.Strings(keyIDs)

	// Build the KRL_SECTION_CERTIFICATES payload: ca_key(empty=wildcard), reserved,
	// then the cert sub-sections.
	var cert bytes.Buffer
	sshWriteString(&cert, nil) // ca_key = "" → applies to any CA (wildcard)
	sshWriteString(&cert, nil) // reserved

	if len(serials) > 0 {
		var serialList bytes.Buffer
		for _, s := range serials {
			sshWriteUint64(&serialList, s)
		}
		cert.WriteByte(krlSectionCertSerialList)
		sshWriteString(&cert, serialList.Bytes())
	}
	if len(keyIDs) > 0 {
		var keyIDList bytes.Buffer
		for _, id := range keyIDs {
			sshWriteString(&keyIDList, []byte(id))
		}
		cert.WriteByte(krlSectionCertKeyID)
		sshWriteString(&cert, keyIDList.Bytes())
	}

	// Assemble the full KRL: magic, header, then the one certificates section.
	var out bytes.Buffer
	out.WriteString(krlMagic)
	sshWriteUint32(&out, krlFormatVersion)
	sshWriteUint64(&out, krlVersion)
	sshWriteUint64(&out, 0)                         // generated_date (0 = unspecified)
	sshWriteUint64(&out, 0)                         // flags
	sshWriteString(&out, nil)                       // reserved
	sshWriteString(&out, []byte("trstctl SSH KRL")) // comment

	out.WriteByte(krlSectionCertificates)
	sshWriteString(&out, cert.Bytes())

	return out.Bytes()
}

// SSH wire-format primitives (RFC 4251 §5): uint32/uint64 are big-endian; a string
// is a uint32 length followed by that many bytes. These encode the KRL framing and
// are pure serialization (no crypto), so they live here beside the KRL, not behind
// the crypto boundary.
func sshWriteUint32(b *bytes.Buffer, v uint32) {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], v)
	b.Write(p[:])
}

func sshWriteUint64(b *bytes.Buffer, v uint64) {
	var p [8]byte
	binary.BigEndian.PutUint64(p[:], v)
	b.Write(p[:])
}

func sshWriteString(b *bytes.Buffer, s []byte) {
	sshWriteUint32(b, uint32(len(s)))
	b.Write(s)
}
