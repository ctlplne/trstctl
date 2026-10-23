// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/trust"
)

// TrustRemoveDistrusted removes one trust anchor an agent found in a host trust
// store when this host's own distrust list names it (eMudhra, Part 4). The
// control plane never holds the anchor's bytes, so the host reads the file,
// checks that it holds exactly that one certificate and that the certificate
// is distrusted, and removes exactly the bytes it read.
const TrustRemoveDistrusted = "remove_distrusted"

// The closed outcomes of a distrusted-root removal.
const (
	DistrustRemovalRemoved   = "removed"               // the file is gone and read back absent
	DistrustRemovalAbsent    = "absent"                // nothing at the path; nothing removed
	DistrustRemovalBundle    = "bundle"                // the file holds more than one certificate or other PEM blocks
	DistrustRemovalDifferent = "different_certificate" // the file holds another certificate
	DistrustRemovalNotListed = "not_distrusted"        // this host's distrust list does not name it
	DistrustRemovalRefused   = "outside_profile"       // the host profile does not allow this path
	DistrustRemovalFailed    = "failed"                // the read, the removal or the readback failed
)

// DistrustRemovalReport is the closed evidence of one removal attempt.
// Free-form host output never enters it.
type DistrustRemovalReport struct {
	FindingID     string `json:"finding_id"`
	AnchorPath    string `json:"anchor_path"`
	Fingerprint   string `json:"fingerprint"`
	State         string `json:"state"`
	DistrustEntry string `json:"distrust_entry,omitempty"`
}

// Digest is the evidence digest the agent signs for this report.
func (r DistrustRemovalReport) Digest() string {
	var b []byte
	for _, part := range []string{"trstctl-distrust-removal-report/v1", r.FindingID, r.AnchorPath, r.Fingerprint, r.State, r.DistrustEntry} {
		b = append(b, part...)
		b = append(b, 0)
	}
	return crypto.SHA256Hex(b)
}

// ValidateDistrustRemovalReport checks that a signed report answers exactly the
// queued intent with a known outcome and that the digest the agent signed is
// the report's own.
func ValidateDistrustRemovalReport(intent TrustDistributionIntent, report DistrustRemovalReport, digest string) error {
	if intent.Operation != TrustRemoveDistrusted || report.FindingID != intent.FindingID ||
		report.AnchorPath != intent.AnchorPath ||
		normalizeTrustFingerprint(report.Fingerprint) != normalizeTrustFingerprint(intent.AnchorFingerprint) {
		return errors.New("distrust removal report does not answer the queued intent")
	}
	switch report.State {
	case DistrustRemovalRemoved, DistrustRemovalAbsent, DistrustRemovalBundle, DistrustRemovalDifferent,
		DistrustRemovalNotListed, DistrustRemovalRefused, DistrustRemovalFailed:
	default:
		return errors.New("distrust removal report carries an unknown state")
	}
	if report.State == DistrustRemovalRemoved && report.DistrustEntry == "" {
		return errors.New("a removed distrusted root names no distrust entry")
	}
	if !strings.EqualFold(digest, report.Digest()) {
		return errors.New("distrust removal evidence digest does not match the report")
	}
	return nil
}

// ExecuteDistrustedRootRemoval removes the one anchor the intent names when,
// and only when, the file at the path is a single certificate with that
// fingerprint and this host's distrust list (shipped entries plus any
// --distrust-file) names it. Every other case leaves the file untouched and
// says why. An error means the intent itself is unusable.
func ExecuteDistrustedRootRemoval(profile connector.LocalOpsConfig, intent TrustDistributionIntent) (DistrustRemovalReport, error) {
	intent.FindingID = strings.TrimSpace(intent.FindingID)
	intent.AnchorPath = strings.TrimSpace(intent.AnchorPath)
	fingerprint := normalizeTrustFingerprint(intent.AnchorFingerprint)
	if intent.Operation != TrustRemoveDistrusted || intent.FindingID == "" || len(intent.AnchorPEM) != 0 ||
		!filepath.IsAbs(intent.AnchorPath) || !isSHA256HexFingerprint(fingerprint) {
		return DistrustRemovalReport{}, errors.New("relay: distrust removal needs a finding, an absolute path and an exact SHA-256 fingerprint, and carries no anchor bytes")
	}
	report := DistrustRemovalReport{FindingID: intent.FindingID, AnchorPath: intent.AnchorPath, Fingerprint: fingerprint}
	data, err := connector.ReadLocalFile(profile, intent.AnchorPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		report.State = DistrustRemovalAbsent
		return report, nil
	case errors.Is(err, connector.ErrLocalPathRefused):
		report.State = DistrustRemovalRefused
		return report, nil
	case err != nil:
		report.State = DistrustRemovalFailed
		return report, nil
	}
	der, single := singleCertificate(data)
	if !single {
		report.State = DistrustRemovalBundle
		return report, nil
	}
	info, err := certinfo.Inspect(der)
	if err != nil || normalizeTrustFingerprint(info.SHA256Fingerprint) != fingerprint {
		report.State = DistrustRemovalDifferent
		return report, nil
	}
	entry, listed := trust.Active().MatchHashes(info.SPKISHA256, info.SHA256Fingerprint)
	if !listed {
		report.State = DistrustRemovalNotListed
		return report, nil
	}
	report.DistrustEntry = entry.Name
	// Exactly the bytes just read: a file replaced in between is not removed.
	if err := connector.RemoveLocalFile(profile, intent.AnchorPath, data); err != nil {
		report.State = DistrustRemovalFailed
		if errors.Is(err, connector.ErrLocalPathRefused) {
			report.State = DistrustRemovalRefused
		}
		return report, nil
	}
	if _, err := connector.ReadLocalFile(profile, intent.AnchorPath); !errors.Is(err, os.ErrNotExist) {
		report.State = DistrustRemovalFailed
		return report, nil
	}
	report.State = DistrustRemovalRemoved
	return report, nil
}

// singleCertificate returns the one certificate a file holds. A PEM file must
// hold exactly one CERTIFICATE block and no other PEM block; a file with no
// PEM block is taken as one DER certificate.
func singleCertificate(data []byte) ([]byte, bool) {
	var certs [][]byte
	other := 0
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		} else {
			other++
		}
	}
	if len(certs) == 0 && other == 0 {
		return data, len(data) > 0
	}
	if len(certs) != 1 || other != 0 {
		return nil, false
	}
	return certs[0], true
}

func isSHA256HexFingerprint(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func runDistrustedRootRemoval(ctx context.Context, ch Channel, profile connector.LocalOpsConfig, job Job, intent TrustDistributionIntent) bool {
	result, err := ExecuteDistrustedRootRemoval(profile, intent)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "trust removal intent is invalid")
		return false
	}
	detail, err := json.Marshal(result)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "trust removal evidence could not be encoded")
		return false
	}
	reportWithEvidence(ctx, ch, job, OutcomeExecuted, string(detail), result.Digest())
	return result.State == DistrustRemovalRemoved || result.State == DistrustRemovalAbsent
}
