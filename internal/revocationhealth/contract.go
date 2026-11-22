// SPDX-License-Identifier: BUSL-1.1

// Package revocationhealth defines the bounded public command/report/event
// contract shared by the control plane and a network relay. It contains no
// transport, store, or X.509 implementation; cryptographic parsing stays behind
// internal/crypto (AN-3).
package revocationhealth

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	JobKind             = "revocation.probe"
	RequiredRoleNetwork = "network"
	ProtocolCRL         = "crl"
	ProtocolOCSP        = "ocsp"
	MaxTargets          = 32
	MaxEndpointBytes    = 4_096
	MaxCertificateBytes = 1 << 20
	MaxCommandDERBytes  = 8 << 20
)

type Intent struct {
	ID                 string   `json:"id"`
	Bucket             string   `json:"bucket"`
	BatchIndex         int      `json:"batch_index"`
	BatchCount         int      `json:"batch_count"`
	Targets            []Target `json:"targets"`
	StaleWithinSeconds int      `json:"stale_within_seconds"`
	RequiredAgentRole  string   `json:"required_agent_role"`
	RequiredAgentID    string   `json:"required_agent_id,omitempty"`
	// LDAPBinding is set on a batch of LDAP distribution points (A107): the
	// directory the relay binds to before it reads them.
	LDAPBinding *LDAPBinding `json:"ldap_binding,omitempty"`

	// Endpoints/IssuerDER are decode-only compatibility fields for pre-R1 unit
	// fixtures. Production producers always emit Targets with exact context.
	Endpoints []string `json:"endpoints,omitempty"`
	IssuerDER []byte   `json:"issuer_der,omitempty"`
}

type Target struct {
	Key                    string `json:"key"`
	Protocol               string `json:"protocol"`
	Endpoint               string `json:"endpoint"`
	IssuerSubject          string `json:"issuer_subject"`
	IssuerFingerprint      string `json:"issuer_fingerprint,omitempty"`
	IssuerDER              []byte `json:"issuer_der,omitempty"`
	CertificateID          string `json:"certificate_id"`
	CertificateSubject     string `json:"certificate_subject"`
	CertificateFingerprint string `json:"certificate_fingerprint"`
	CertificateSerial      string `json:"certificate_serial"`
	CertificateDER         []byte `json:"certificate_der,omitempty"`
	// Scope is ScopeEndpoint (empty) for an endpoint's health checked through a
	// representative certificate, or ScopeCertificate for one certificate known
	// only from a scan, checked for its own serial (A211).
	Scope string `json:"scope,omitempty"`
}

// Target scopes.
const (
	ScopeEndpoint    = "endpoint"
	ScopeCertificate = "certificate"
)

type FindingStatus string

const (
	StatusFresh       FindingStatus = "fresh"
	StatusExpiring    FindingStatus = "expiring"
	StatusStale       FindingStatus = "stale"
	StatusUnreachable FindingStatus = "unreachable"
	StatusUnparseable FindingStatus = "unparseable"
)

type Finding struct {
	TargetKey         string        `json:"target_key"`
	Protocol          string        `json:"protocol"`
	Endpoint          string        `json:"endpoint"`
	Status            FindingStatus `json:"status"`
	DetailCode        string        `json:"detail_code"`
	Detail            string        `json:"detail"`
	LatencyMS         int64         `json:"latency_ms"`
	ThisUpdate        *time.Time    `json:"this_update,omitempty"`
	NextUpdate        *time.Time    `json:"next_update,omitempty"`
	SignatureVerified bool          `json:"signature_verified"`
	RevokedCount      int           `json:"revoked_count,omitempty"`
	ResponseStatus    string        `json:"response_status,omitempty"`
	ResponderSubject  string        `json:"responder_subject,omitempty"`
	// CertificateListed says whether a parsed CRL lists the target's serial.
	CertificateListed *bool `json:"certificate_listed,omitempty"`
}

type Report struct {
	Findings []Finding `json:"findings"`
	Healthy  bool      `json:"healthy"`
}

type Observed struct {
	ProbeID        string    `json:"probe_id"`
	Bucket         string    `json:"bucket"`
	BatchIndex     int       `json:"batch_index"`
	BatchCount     int       `json:"batch_count"`
	AgentID        string    `json:"agent_id"`
	AgentName      string    `json:"agent_name"`
	EvidenceDigest string    `json:"evidence_digest"`
	Targets        []Target  `json:"targets"`
	Findings       []Finding `json:"findings"`
}

// LDAPBinding names the directory an AD CS LDAP CRL distribution point is
// read from (A107): the tenant's AD CS discovery source whose configuration DN
// covers the distribution point's DN. The relay connects to URL, never to a
// host named in a certificate, binds as BindDN with the credential PasswordRef
// names (a secret:// reference it redeems for one attempt), and reads only
// DNs under ConfigurationDN.
type LDAPBinding struct {
	SourceID           string `json:"source_id"`
	URL                string `json:"url"`
	ConfigurationDN    string `json:"configuration_dn"`
	BindDN             string `json:"bind_dn"`
	PasswordRef        string `json:"password_ref"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
}

// IsLDAPEndpoint reports whether a distribution point is an LDAP URL.
func IsLDAPEndpoint(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	return err == nil && (parsed.Scheme == "ldap" || parsed.Scheme == "ldaps")
}

// LDAPEndpointDN is the entry an LDAP distribution point names: its URL path
// without the leading slash, unescaped. AD CS writes
// ldap:///CN=<CA>,CN=<host>,CN=CDP,CN=Public Key Services,CN=Services,
// CN=Configuration,DC=...?certificateRevocationList?base?objectClass=...
func LDAPEndpointDN(endpoint string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "ldap" && parsed.Scheme != "ldaps") {
		return "", errors.New("not an LDAP distribution point")
	}
	dn := strings.TrimSpace(strings.TrimPrefix(parsed.Path, "/"))
	if dn == "" || len(dn) > MaxEndpointBytes {
		return "", errors.New("LDAP distribution point names no entry")
	}
	return dn, nil
}

// LDAPDNWithin reports whether dn lies under base: the last components of dn
// equal base, compared without case or the spaces around separators.
func LDAPDNWithin(dn, base string) bool {
	norm := func(v string) string {
		parts := strings.Split(v, ",")
		for i, part := range parts {
			parts[i] = strings.ToLower(strings.TrimSpace(part))
		}
		return strings.Join(parts, ",")
	}
	d, b := norm(dn), norm(base)
	return b != "" && (d == b || strings.HasSuffix(d, ","+b))
}

func validateLDAPBinding(binding LDAPBinding) error {
	if _, err := uuid.Parse(binding.SourceID); err != nil {
		return errors.New("LDAP binding source_id must be a UUID")
	}
	parsed, err := url.Parse(strings.TrimSpace(binding.URL))
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "ldap" && parsed.Scheme != "ldaps") || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("LDAP binding url must be an ldap:// or ldaps:// directory authority")
	}
	for _, field := range []struct{ name, value string }{
		{"configuration_dn", binding.ConfigurationDN}, {"bind_dn", binding.BindDN}, {"password_ref", binding.PasswordRef},
	} {
		if strings.TrimSpace(field.value) == "" || len(field.value) > MaxEndpointBytes {
			return fmt.Errorf("LDAP binding %s is required and bounded", field.name)
		}
	}
	if !strings.HasPrefix(binding.PasswordRef, "secret://") {
		return errors.New("LDAP binding password_ref must be a secret:// credential reference")
	}
	return nil
}

func ValidateIntent(intent Intent) error {
	if _, err := uuid.Parse(intent.ID); err != nil {
		return errors.New("revocation health: id must be a UUID")
	}
	if strings.TrimSpace(intent.Bucket) == "" || len(intent.Bucket) > 128 {
		return errors.New("revocation health: bucket is required and bounded")
	}
	if intent.BatchIndex < 1 || intent.BatchCount < intent.BatchIndex {
		return errors.New("revocation health: batch index/count are invalid")
	}
	if intent.RequiredAgentRole != RequiredRoleNetwork {
		return errors.New("revocation health: probe must require a network-role relay")
	}
	if intent.RequiredAgentID != "" {
		if _, err := uuid.Parse(intent.RequiredAgentID); err != nil {
			return errors.New("revocation health: required_agent_id must be a UUID")
		}
	}
	if intent.StaleWithinSeconds < 0 || intent.StaleWithinSeconds > int((30*24*time.Hour).Seconds()) {
		return errors.New("revocation health: stale warning window is outside the bound")
	}
	if len(intent.Targets) == 0 || len(intent.Targets) > MaxTargets {
		return fmt.Errorf("revocation health: targets must contain 1..%d entries", MaxTargets)
	}
	if intent.LDAPBinding != nil {
		if err := validateLDAPBinding(*intent.LDAPBinding); err != nil {
			return fmt.Errorf("revocation health: %w", err)
		}
		// A bound batch reads only the directory it names.
		for i, target := range intent.Targets {
			dn, err := LDAPEndpointDN(target.Endpoint)
			if err != nil || target.Protocol != ProtocolCRL || !LDAPDNWithin(dn, intent.LDAPBinding.ConfigurationDN) {
				return fmt.Errorf("revocation health: target %d is not an LDAP CRL under the binding's configuration DN", i)
			}
		}
	}
	previous := ""
	totalDER := 0
	for i, target := range intent.Targets {
		if err := ValidateTarget(target); err != nil {
			return fmt.Errorf("revocation health: target %d: %w", i, err)
		}
		if target.Key <= previous {
			return errors.New("revocation health: targets must be unique and sorted by key")
		}
		previous = target.Key
		totalDER += len(target.IssuerDER) + len(target.CertificateDER)
		if totalDER > MaxCommandDERBytes {
			return errors.New("revocation health: command certificate context exceeds the aggregate bound")
		}
	}
	return nil
}

func ValidateTarget(target Target) error {
	if len(target.Key) != 64 {
		return errors.New("target key must be a SHA-256 hex identifier")
	}
	for _, r := range target.Key {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return errors.New("target key must be lowercase hexadecimal")
		}
	}
	if target.Protocol != ProtocolCRL && target.Protocol != ProtocolOCSP {
		return errors.New("protocol must be crl or ocsp")
	}
	switch target.Scope {
	case "", ScopeEndpoint:
	case ScopeCertificate:
		if len(target.CertificateDER) == 0 || len(target.IssuerDER) == 0 || target.CertificateSerial == "" {
			return errors.New("a certificate-scope target names its certificate, serial and verified issuer")
		}
	default:
		return errors.New("target scope must be endpoint or certificate")
	}
	if len(target.Endpoint) == 0 || len(target.Endpoint) > MaxEndpointBytes {
		return errors.New("endpoint is empty or too large")
	}
	parsed, err := url.Parse(target.Endpoint)
	if err != nil || parsed.Scheme == "" || parsed.User != nil {
		return errors.New("endpoint must be an absolute URL without userinfo")
	}
	// AD CS publishes CRLs at ldap:///<DN>: no host, the client's default
	// directory. Every other endpoint names its host.
	if parsed.Scheme == "ldap" || parsed.Scheme == "ldaps" {
		if _, err := LDAPEndpointDN(target.Endpoint); err != nil {
			return err
		}
	} else if parsed.Host == "" {
		return errors.New("endpoint must be an absolute URL without userinfo")
	}
	if target.Protocol == ProtocolOCSP && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("OCSP endpoint must use HTTP(S)")
	}
	if target.CertificateID == "" || target.CertificateFingerprint == "" || target.CertificateSerial == "" || target.CertificateSubject == "" || target.IssuerSubject == "" {
		return errors.New("certificate and issuer context are required")
	}
	for _, r := range target.CertificateSerial {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return errors.New("certificate serial must be lowercase hexadecimal")
		}
	}
	if len(target.IssuerDER) > MaxCertificateBytes || len(target.CertificateDER) > MaxCertificateBytes {
		return errors.New("certificate context exceeds the per-certificate bound")
	}
	return nil
}

func ValidateReport(intent Intent, report Report) error {
	if err := ValidateIntent(intent); err != nil {
		return err
	}
	if len(report.Findings) != len(intent.Targets) {
		return errors.New("revocation health: report must contain exactly one finding per target")
	}
	byKey := make(map[string]Target, len(intent.Targets))
	for _, target := range intent.Targets {
		byKey[target.Key] = target
	}
	healthy := true
	seen := make(map[string]bool, len(report.Findings))
	for i, finding := range report.Findings {
		target, ok := byKey[finding.TargetKey]
		if !ok || seen[finding.TargetKey] {
			return fmt.Errorf("revocation health: finding %d names an unknown or duplicate target", i)
		}
		seen[finding.TargetKey] = true
		if finding.Protocol != target.Protocol || finding.Endpoint != target.Endpoint {
			return fmt.Errorf("revocation health: finding %d changed immutable target context", i)
		}
		if !knownStatus(finding.Status) || !knownDetailCode(finding.DetailCode) || len(finding.Detail) > 1_024 || finding.LatencyMS < 0 {
			return fmt.Errorf("revocation health: finding %d carries an invalid verdict", i)
		}
		if finding.Status != StatusFresh {
			healthy = false
		}
		if finding.Status == StatusFresh && (!finding.SignatureVerified || finding.NextUpdate == nil) {
			return fmt.Errorf("revocation health: finding %d claims fresh without verified freshness evidence", i)
		}
		if finding.Protocol == ProtocolOCSP && finding.SignatureVerified && finding.ResponseStatus != "good" && finding.ResponseStatus != "revoked" {
			return fmt.Errorf("revocation health: finding %d has an invalid verified OCSP status", i)
		}
	}
	if report.Healthy != healthy {
		return errors.New("revocation health: report healthy flag contradicts its findings")
	}
	return nil
}

// ValidateObserved verifies the authority and exact command/report pairing that
// is retained in an observation event. Recovery calls the same validator as the
// live projector, so a malformed retained payload can never recreate alerts.
func ValidateObserved(observed Observed) error {
	if _, err := uuid.Parse(observed.AgentID); err != nil || strings.TrimSpace(observed.AgentName) == "" || len(observed.AgentName) > 256 {
		return errors.New("revocation health: observation lacks bounded agent authority")
	}
	if len(observed.EvidenceDigest) != 64 {
		return errors.New("revocation health: observation evidence digest is invalid")
	}
	for _, r := range observed.EvidenceDigest {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return errors.New("revocation health: observation evidence digest is invalid")
		}
	}
	healthy := true
	for _, finding := range observed.Findings {
		if finding.Status != StatusFresh {
			healthy = false
		}
	}
	return ValidateReport(Intent{
		ID: observed.ProbeID, Bucket: observed.Bucket,
		BatchIndex: observed.BatchIndex, BatchCount: observed.BatchCount,
		Targets: observed.Targets, RequiredAgentRole: RequiredRoleNetwork,
	}, Report{Findings: observed.Findings, Healthy: healthy})
}

func knownDetailCode(code string) bool {
	switch code {
	case "invalid_endpoint", "unsupported_scheme", "issuer_unavailable",
		"request_build_failed", "transport_failed", "http_status", "body_read_failed", "body_too_large",
		"invalid_crl", "certificate_unavailable", "request_invalid", "invalid_content_type", "invalid_ocsp",
		"serial_mismatch", "this_update_future", "ocsp_unknown", "next_update_missing", "next_update_passed",
		"next_update_near", "fresh",
		// A107: LDAP distribution points read through an AD CS binding.
		"ldap_binding_missing", "ldap_host_not_bound", "ldap_dn_outside_binding", "ldap_bind_failed",
		"ldap_entry_missing", "ldap_crl_missing", "ldap_search_failed",
		// B13-R3: the directory read failed before the bind, or had no credential.
		"ldap_connect_failed", "ldap_tls_failed", "ldap_credential_unavailable":
		return true
	default:
		return false
	}
}

func SortTargets(targets []Target) {
	sort.Slice(targets, func(i, j int) bool { return targets[i].Key < targets[j].Key })
}

func knownStatus(status FindingStatus) bool {
	switch status {
	case StatusFresh, StatusExpiring, StatusStale, StatusUnreachable, StatusUnparseable:
		return true
	default:
		return false
	}
}
