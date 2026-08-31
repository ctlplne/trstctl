// SPDX-License-Identifier: MPL-2.0

package ephemeral

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

const approvalIssuedStatePrefix = "issued:sha256:"

// approvedCertificateRecordDelay is the largest gap allowed between the signer
// creating an approved certificate and the control plane durably recording its
// event. X.509 timestamps lose sub-second precision, so the separate one-second
// allowance below covers encoding while this budget covers bounded SQL/event-log
// work. A larger stall still fails closed while the certificate is unrecorded.
const approvedCertificateRecordDelay = 5 * time.Second

// ErrApprovalCertificateLifetime distinguishes a valid retained target whose
// original event time is required from malformed command/certificate content.
// The command path may perform an outside-transaction history lookup only for
// this recovery case; arbitrary malformed retries must not trigger O(history).
var ErrApprovalCertificateLifetime = errors.New("ephemeral: certificate lifetime is outside approved event window")

// ApprovalBinding is the privacy-stable part of one reviewed ephemeral
// issuance command. It deliberately carries digests instead of raw attestation
// subjects/selectors: retention may erase those values, but it must not make an
// already-consumed authority impossible to verify during a cold rebuild.
type ApprovalBinding struct {
	CAID                       string `json:"ca_id"`
	CACertificateSHA256        string `json:"ca_certificate_sha256"`
	CACertificateDER           []byte `json:"ca_certificate_der"`
	ClientRequestIDSHA256      string `json:"client_request_id_sha256"`
	AttestationMethod          string `json:"attestation_method"`
	AttestationSubjectSHA256   string `json:"attestation_subject_sha256"`
	AttestationSelectorsSHA256 string `json:"attestation_selectors_sha256"`
	PublicKeySHA256            string `json:"public_key_sha256"`
	SPIFFEIDSHA256             string `json:"spiffe_id_sha256"`
	TTLSeconds                 int64  `json:"ttl_seconds"`
	NotBeforeBackdateSeconds   int64  `json:"not_before_backdate_seconds"`
}

// NewApprovalBinding builds the command reviewers authorize. The caller passes
// the effective (already clamped) TTL and the exact SPIFFE ID the signer will
// place in the certificate.
func NewApprovalBinding(caID string, caCertificateDER []byte, clientRequestID, method, subject string, selectors []string, publicKeyDER []byte, spiffeID string, ttl time.Duration) (ApprovalBinding, error) {
	selectors = append([]string(nil), selectors...)
	sort.Strings(selectors)
	selectorsJSON, err := json.Marshal(selectors)
	if err != nil {
		return ApprovalBinding{}, err
	}
	binding := ApprovalBinding{
		CAID:                       strings.TrimSpace(caID),
		CACertificateSHA256:        crypto.SHA256Hex(caCertificateDER),
		CACertificateDER:           append([]byte(nil), caCertificateDER...),
		ClientRequestIDSHA256:      crypto.SHA256Hex([]byte(clientRequestID)),
		AttestationMethod:          strings.TrimSpace(method),
		AttestationSubjectSHA256:   crypto.SHA256Hex([]byte(subject)),
		AttestationSelectorsSHA256: crypto.SHA256Hex(selectorsJSON),
		PublicKeySHA256:            crypto.SHA256Hex(publicKeyDER),
		SPIFFEIDSHA256:             crypto.SHA256Hex([]byte(spiffeID)),
		TTLSeconds:                 int64(ttl / time.Second),
		NotBeforeBackdateSeconds:   int64(crypto.IssuanceBackdateSkew() / time.Second),
	}
	if err := binding.validate(); err != nil {
		return ApprovalBinding{}, err
	}
	return binding, nil
}

// Digest is the single reviewer-visible command identity. It is repeated in
// OperationApprovalUse.ToState, a field retention never clears, so a target
// event cannot swap in a different subject, key, attestation, or lifetime after
// approval evidence has aged out of the read model.
func (b ApprovalBinding) Digest() (string, error) {
	if err := b.validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(append([]byte("trstctl:ephemeral-approval-command:v1\x00"), raw...)), nil
}

// ToState is the immutable approval field that carries the command digest.
func (b ApprovalBinding) ToState() (string, error) {
	digest, err := b.Digest()
	if err != nil {
		return "", err
	}
	return approvalIssuedStatePrefix + digest, nil
}

// EvidenceRefs returns the exact non-secret receipts shown to reviewers. It is
// sorted because operation-approval intents canonicalize evidence before
// hashing and persistence.
func (b ApprovalBinding) EvidenceRefs() ([]string, error) {
	digest, err := b.Digest()
	if err != nil {
		return nil, err
	}
	refs := []string{
		"attestation-method:" + b.AttestationMethod,
		"attestation-selectors-sha256:" + b.AttestationSelectorsSHA256,
		"attestation-subject-sha256:" + b.AttestationSubjectSHA256,
		"client-request-id-sha256:" + b.ClientRequestIDSHA256,
		"ephemeral-ca-id:" + b.CAID,
		"ephemeral-ca-certificate-sha256:" + b.CACertificateSHA256,
		"command-sha256:" + digest,
		"public-key-sha256:" + b.PublicKeySHA256,
		"spiffe-id-sha256:" + b.SPIFFEIDSHA256,
		fmt.Sprintf("not-before-backdate-seconds:%d", b.NotBeforeBackdateSeconds),
		fmt.Sprintf("ttl-seconds:%d", b.TTLSeconds),
	}
	sort.Strings(refs)
	return refs, nil
}

// ValidateCertificate proves that the public certificate carried by a retained
// target event is the command reviewers authorized. Shorter validity is safe;
// the approved TTL is a hard maximum because X.509 has no trusted issuance-time
// field from which an exact elapsed duration can be recovered.
func (b ApprovalBinding) ValidateCertificate(certificateDER []byte, source, tenantID string, eventTime time.Time) (certinfo.Info, error) {
	if err := b.validate(); err != nil {
		return certinfo.Info{}, err
	}
	if source != "ephemeral:"+b.AttestationMethod {
		return certinfo.Info{}, fmt.Errorf("ephemeral: certificate source does not match approved attestation method")
	}
	info, err := certinfo.Inspect(certificateDER)
	if err != nil {
		return certinfo.Info{}, err
	}
	if len(info.URIs) != 1 {
		return certinfo.Info{}, fmt.Errorf("ephemeral: approved certificate must contain exactly one URI SAN")
	}
	if crypto.SHA256Hex(b.CACertificateDER) != b.CACertificateSHA256 {
		return certinfo.Info{}, fmt.Errorf("ephemeral: approved CA certificate digest changed")
	}
	caInfo, err := certinfo.Inspect(b.CACertificateDER)
	if err != nil || !caInfo.IsCA {
		return certinfo.Info{}, fmt.Errorf("ephemeral: approved CA certificate is invalid")
	}
	if err := crypto.VerifyLeafSignedByCA(certificateDER, b.CACertificateDER); err != nil {
		return certinfo.Info{}, fmt.Errorf("ephemeral: certificate is not signed by the approved CA: %w", err)
	}
	if len(info.DNSNames) != 0 || len(info.IPAddresses) != 0 || len(info.EmailAddresses) != 0 ||
		info.IsCA || !info.BasicConstraints || !info.KeyUsageSet || !info.KeyUsageDigitalSig ||
		!info.KeyUsageEncipher || info.KeyUsageCertSign || !svidExtKeyUsages(info.ExtKeyUsages) {
		return certinfo.Info{}, fmt.Errorf("ephemeral: certificate does not match the approved X.509-SVID profile")
	}
	spiffeID := info.URIs[0]
	if crypto.SHA256Hex([]byte(spiffeID)) != b.SPIFFEIDSHA256 {
		return certinfo.Info{}, fmt.Errorf("ephemeral: certificate SPIFFE ID does not match approved command")
	}
	identityTenant, identityMethod, subject, err := ephemeralIdentitySubject(spiffeID)
	if err != nil {
		return certinfo.Info{}, err
	}
	if identityTenant != "" && (identityTenant != tenantID || identityMethod != b.AttestationMethod) {
		return certinfo.Info{}, fmt.Errorf("ephemeral: certificate authority context does not match approved tenant and method")
	}
	if crypto.SHA256Hex([]byte(subject)) != b.AttestationSubjectSHA256 {
		return certinfo.Info{}, fmt.Errorf("ephemeral: certificate subject does not match approved attestation")
	}
	publicKeyDER, err := crypto.PublicKeyDERFromCert(certificateDER)
	if err != nil {
		return certinfo.Info{}, err
	}
	if crypto.SHA256Hex(publicKeyDER) != b.PublicKeySHA256 {
		return certinfo.Info{}, fmt.Errorf("ephemeral: certificate public key does not match approved command")
	}
	approvedTTL := time.Duration(b.TTLSeconds) * time.Second
	approvedBackdate := time.Duration(b.NotBeforeBackdateSeconds) * time.Second
	if !eventTime.Before(info.NotAfter) || info.NotBefore.After(eventTime.Add(time.Second)) ||
		eventTime.Sub(info.NotBefore) > approvedBackdate+approvedCertificateRecordDelay+time.Second ||
		info.NotAfter.Sub(info.NotBefore) > approvedTTL+approvedBackdate+time.Second ||
		info.NotAfter.After(eventTime.Add(approvedTTL+time.Second)) {
		return certinfo.Info{}, ErrApprovalCertificateLifetime
	}
	return info, nil
}

func (b ApprovalBinding) validate() error {
	if b.CAID == "" || strings.TrimSpace(b.CAID) != b.CAID {
		return fmt.Errorf("ephemeral: approval binding has no canonical CA ID")
	}
	if _, err := uuid.Parse(b.CAID); err != nil {
		return fmt.Errorf("ephemeral: approval binding CA ID is not a UUID: %w", err)
	}
	if b.AttestationMethod == "" || strings.TrimSpace(b.AttestationMethod) != b.AttestationMethod {
		return fmt.Errorf("ephemeral: approval binding has no canonical attestation method")
	}
	for name, digest := range map[string]string{
		"CA certificate":    b.CACertificateSHA256,
		"client request ID": b.ClientRequestIDSHA256,
		"subject":           b.AttestationSubjectSHA256,
		"selectors":         b.AttestationSelectorsSHA256,
		"public key":        b.PublicKeySHA256,
		"SPIFFE ID":         b.SPIFFEIDSHA256,
	} {
		if len(digest) != 64 {
			return fmt.Errorf("ephemeral: approval %s digest is not SHA-256 hex", name)
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return fmt.Errorf("ephemeral: approval %s digest is not SHA-256 hex: %w", name, err)
		}
	}
	if len(b.CACertificateDER) == 0 {
		return fmt.Errorf("ephemeral: approval binding has no CA certificate")
	}
	const maxTTLSeconds = int64((1<<63 - 1) / int64(time.Second))
	if b.TTLSeconds <= 0 || b.TTLSeconds > maxTTLSeconds ||
		b.NotBeforeBackdateSeconds <= 0 || b.NotBeforeBackdateSeconds > maxTTLSeconds {
		return fmt.Errorf("ephemeral: approval TTL is invalid")
	}
	return nil
}

func svidExtKeyUsages(usages []string) bool {
	if len(usages) != 2 {
		return false
	}
	seen := map[string]bool{}
	for _, usage := range usages {
		seen[usage] = true
	}
	return seen["serverAuth"] && seen["clientAuth"]
}

// SubjectFromSPIFFEID returns the original attestation subject. Versioned
// automatic identities have a tenant/route/method prefix and reversible segment
// encoding. Historical unreserved identities retain their original decoded path.
// This is a retained-evidence reader, not a validator for new issuance or TLS.
// ValidateCertificate separately binds the exact URI, key, CA, subject and time;
// this decoder never converts an old approval into authority for a new identity.
func SubjectFromSPIFFEID(raw string) (string, error) {
	_, _, subject, err := ephemeralIdentitySubject(raw)
	return subject, err
}

func ephemeralIdentitySubject(raw string) (tenantID, method, subject string, err error) {
	id, err := crypto.ParseSPIFFEID(raw)
	if err != nil {
		legacySubject, legacyErr := retainedLegacySubject(raw)
		if legacyErr != nil {
			return "", "", "", err
		}
		return "", "", legacySubject, nil
	}
	subjectPath := strings.TrimPrefix(id.Path, "/")
	if subjectPath == "" {
		return "", "", "", fmt.Errorf("ephemeral: certificate SPIFFE ID has no subject path")
	}
	if !crypto.IsReservedWorkloadSPIFFEID(raw) {
		return "", "", subjectPath, nil
	}
	parts := strings.Split(subjectPath, "/")
	if len(parts) < 9 || parts[0] != "_trstctl" || parts[1] != "v1" || parts[2] != "tenant" || parts[4] != "ephemeral" || parts[5] != "method" || parts[7] != "subject" {
		return "", "", "", fmt.Errorf("ephemeral: certificate has an unsupported automatic identity shape")
	}
	tenant, err := uuid.Parse(parts[3])
	if err != nil || tenant == uuid.Nil || tenant.String() != parts[3] {
		return "", "", "", fmt.Errorf("ephemeral: certificate has an invalid tenant namespace")
	}
	method, err = crypto.DecodeWorkloadSPIFFESegment(parts[6])
	if err != nil {
		return "", "", "", err
	}
	subjectParts := parts[8:]
	for i, part := range subjectParts {
		subjectParts[i], err = crypto.DecodeWorkloadSPIFFESegment(part)
		if err != nil || strings.Contains(subjectParts[i], "/") {
			return "", "", "", fmt.Errorf("ephemeral: certificate has an invalid mapped subject segment")
		}
	}
	return tenant.String(), method, strings.Join(subjectParts, "/"), nil
}

// retainedLegacySubject recovers punctuation and per-segment URL escaping used
// before canonical workload names. It cannot read the reserved namespace or an
// alias of it. New SignSVID and SPIFFEIDFromCert still use the strict parser.
// The exact signed URI digest remains authoritative: decoding is not permission
// to substitute another spelling or reuse an old approval for a scoped name.
func retainedLegacySubject(raw string) (string, error) {
	if len(raw) > crypto.MaxSPIFFEIDLength || !strings.HasPrefix(raw, "spiffe://") ||
		strings.ContainsAny(raw, "?#") || crypto.IsReservedWorkloadSPIFFEID(raw) {
		return "", errors.New("ephemeral: unsupported retained identity")
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.Host == "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("ephemeral: invalid retained identity URI")
	}
	// Compatibility is limited to the old path spelling. It does not accept
	// noncanonical trust domains, ports, userinfo, queries or fragments.
	if _, err := crypto.ParseSPIFFEID("spiffe://" + u.Host); err != nil {
		return "", errors.New("ephemeral: invalid retained identity trust domain")
	}
	escaped := strings.TrimPrefix(u.EscapedPath(), "/")
	parts := strings.Split(escaped, "/")
	for i, part := range parts {
		parts[i], err = url.PathUnescape(part)
		if err != nil || parts[i] == "" || parts[i] == "." || parts[i] == ".." ||
			strings.Contains(parts[i], "/") {
			return "", errors.New("ephemeral: ambiguous retained identity subject")
		}
	}
	return strings.Join(parts, "/"), nil
}
