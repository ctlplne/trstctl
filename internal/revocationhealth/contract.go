// SPDX-License-Identifier: MPL-2.0

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
}

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
	if len(target.Endpoint) == 0 || len(target.Endpoint) > MaxEndpointBytes {
		return errors.New("endpoint is empty or too large")
	}
	parsed, err := url.Parse(target.Endpoint)
	if err != nil || parsed.Host == "" || parsed.Scheme == "" || parsed.User != nil {
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
		"next_update_near", "fresh":
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
