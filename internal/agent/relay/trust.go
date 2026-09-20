// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

const (
	KindTrustDistribute = "trust.distribute"
	TrustInstall        = "install"
	TrustRemove         = "remove"
	TrustVerified       = "verified"
	maxTrustAnchorBytes = 1 << 20
)

// TrustDistributionIntent is one exact host-local trust mutation. The anchor is
// public certificate material, never a private key or secret reference.
type TrustDistributionIntent struct {
	RunID             string `json:"run_id"`
	WaveID            string `json:"wave_id"`
	IdentityID        string `json:"identity_id"`
	Operation         string `json:"operation"`
	AnchorPath        string `json:"anchor_path"`
	AnchorPEM         []byte `json:"anchor_pem,omitempty"`
	AnchorFingerprint string `json:"anchor_fingerprint"`
	RequiredAgentID   string `json:"required_agent_id,omitempty"`
}

// TrustDistributionReport is closed evidence derived by readback. Free-form
// target output never enters this contract.
type TrustDistributionReport struct {
	RunID               string `json:"run_id"`
	WaveID              string `json:"wave_id"`
	IdentityID          string `json:"identity_id"`
	Operation           string `json:"operation"`
	Verdict             string `json:"verdict"`
	ObservedFingerprint string `json:"observed_fingerprint,omitempty"`
}

// ExecuteTrustDistribution writes or removes one operator-confined anchor and
// independently reads the file back before returning verified.
func ExecuteTrustDistribution(ctx context.Context, profile connector.LocalOpsConfig, intent TrustDistributionIntent) (TrustDistributionReport, error) {
	_ = ctx // filesystem primitives are bounded local operations.
	intent.RunID = strings.TrimSpace(intent.RunID)
	intent.WaveID = strings.TrimSpace(intent.WaveID)
	intent.IdentityID = strings.TrimSpace(intent.IdentityID)
	intent.Operation = strings.TrimSpace(intent.Operation)
	intent.AnchorPath = strings.TrimSpace(intent.AnchorPath)
	intent.AnchorFingerprint = normalizeTrustFingerprint(intent.AnchorFingerprint)
	if intent.RunID == "" || intent.WaveID == "" || intent.IdentityID == "" || intent.AnchorPath == "" || intent.AnchorFingerprint == "" {
		return TrustDistributionReport{}, errors.New("relay: trust intent requires run, wave, identity, path, and fingerprint")
	}
	if len(intent.AnchorPEM) > maxTrustAnchorBytes {
		return TrustDistributionReport{}, errors.New("relay: trust anchor exceeds the bounded size")
	}
	report := TrustDistributionReport{
		RunID: intent.RunID, WaveID: intent.WaveID, IdentityID: intent.IdentityID, Operation: intent.Operation,
	}
	ops, err := connector.NewLocalOps(profile)
	if err != nil {
		return report, err
	}
	reader, ok := ops.(connector.FileReader)
	if !ok {
		return report, errors.New("relay: trust executor has no readback capability")
	}

	switch intent.Operation {
	case TrustInstall:
		info, inspectErr := certinfo.Inspect(intent.AnchorPEM)
		if inspectErr != nil || !info.IsCA || normalizeTrustFingerprint(info.SHA256Fingerprint) != intent.AnchorFingerprint {
			return report, errors.New("relay: trust anchor is not the named CA certificate")
		}
		if current, readErr := reader.ReadFile(intent.AnchorPath); readErr == nil {
			if !bytes.Equal(current, intent.AnchorPEM) {
				return report, errors.New("relay: trust path contains a different anchor")
			}
		} else if err := ops.WriteFile(intent.AnchorPath, intent.AnchorPEM); err != nil {
			return report, fmt.Errorf("relay: install trust anchor: %w", err)
		}
		observed, readErr := reader.ReadFile(intent.AnchorPath)
		if readErr != nil {
			return report, fmt.Errorf("relay: read back trust anchor: %w", readErr)
		}
		observedInfo, inspectErr := certinfo.Inspect(observed)
		if inspectErr != nil || !observedInfo.IsCA || normalizeTrustFingerprint(observedInfo.SHA256Fingerprint) != intent.AnchorFingerprint {
			return report, errors.New("relay: installed trust anchor did not verify on readback")
		}
		report.Verdict = TrustVerified
		report.ObservedFingerprint = intent.AnchorFingerprint
		return report, nil

	case TrustRemove:
		info, inspectErr := certinfo.Inspect(intent.AnchorPEM)
		if inspectErr != nil || !info.IsCA || normalizeTrustFingerprint(info.SHA256Fingerprint) != intent.AnchorFingerprint {
			return report, errors.New("relay: trust removal does not carry the named public CA certificate")
		}
		// RemoveLocalFile accepts only absence or an exact byte match. An
		// unreadable/mutated path therefore cannot be mistaken for absence and
		// deleted as though this run still owned it.
		if err := connector.RemoveLocalFile(profile, intent.AnchorPath, intent.AnchorPEM); err != nil {
			return report, fmt.Errorf("relay: remove trust anchor: %w", err)
		}
		if _, readErr := reader.ReadFile(intent.AnchorPath); readErr == nil {
			return report, errors.New("relay: trust anchor remained after removal")
		}
		report.Verdict = TrustVerified
		report.ObservedFingerprint = intent.AnchorFingerprint
		return report, nil
	default:
		return report, fmt.Errorf("relay: unsupported trust operation %q", intent.Operation)
	}
}

func runTrustDistribution(ctx context.Context, ch Channel, profile connector.LocalOpsConfig, job Job) bool {
	var intent TrustDistributionIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil {
		report(ctx, ch, job, OutcomeFailed, "job payload is not a trust distribution intent")
		return false
	}
	result, err := ExecuteTrustDistribution(ctx, profile, intent)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "trust distribution did not verify")
		return false
	}
	detail, err := json.Marshal(result)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "trust evidence could not be encoded")
		return false
	}
	reportWithEvidence(ctx, ch, job, OutcomeExecuted, string(detail), crypto.SHA256Hex(detail))
	return true
}

func normalizeTrustFingerprint(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "sha256:")
	return strings.ReplaceAll(value, ":", "")
}
