// SPDX-License-Identifier: MPL-2.0

package server

import (
	"errors"
	"strings"
	"trstctl.com/trstctl/internal/crypto/certinfo"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
)

// A valid agent signature identifies the reporter. The immutable job still
// controls the endpoint, connection address, expected leaf, and allowed vantage.
// Validate the complete sweep before any observation changes estate state.
func validateEndpointVerificationReport(jobPayload []byte, reportJSON, evidenceDigest string) (relay.EndpointVerifyReport, error) {
	var intent relay.EndpointVerifyIntent
	var report relay.EndpointVerifyReport
	if len(jobPayload) > maxStructuredSyncReportBytes || len(reportJSON) > maxStructuredSyncReportBytes {
		return report, errors.New("endpoint verification report exceeds the receiver bound")
	}
	if err := decodeStrictJSON(jobPayload, &intent); err != nil {
		return report, errors.New("endpoint verification command cannot be decoded")
	}
	if len(intent.Endpoints) == 0 || len(intent.Endpoints) > endpointVerificationBatch {
		return report, errors.New("endpoint verification command has an invalid endpoint count")
	}
	if err := decodeStrictJSON([]byte(reportJSON), &report); err != nil {
		return report, errors.New("endpoint verification report cannot be decoded")
	}
	if len(report.Results) != len(intent.Endpoints) {
		return report, errors.New("endpoint verification report must cover every claimed endpoint exactly once")
	}
	expected := make(map[string]relay.EndpointExpectation, len(intent.Endpoints))
	for _, want := range intent.Endpoints {
		if strings.TrimSpace(want.EndpointID) == "" || strings.TrimSpace(want.Address) == "" || strings.TrimSpace(want.Fingerprint) == "" {
			return report, errors.New("endpoint verification command has an incomplete endpoint binding")
		}
		if _, duplicate := expected[want.EndpointID]; duplicate {
			return report, errors.New("endpoint verification command repeats an endpoint")
		}
		expected[want.EndpointID] = want
	}
	var canonical []byte
	for _, result := range report.Results {
		want, ok := expected[result.EndpointID]
		if !ok {
			return report, errors.New("endpoint verification report names an unclaimed or repeated endpoint")
		}
		delete(expected, result.EndpointID)
		tr := result.Transcript
		if tr.Address != strings.TrimSpace(want.Address) || tr.ServerName != strings.TrimSpace(want.ServerName) || tr.ExpectedFingerprint != normalizeVerificationFingerprint(want.Fingerprint) || tr.Vantage != transport.VantageRelay || tr.ExpectedSANDigest != transport.SANSetDigest(want.DNSNames) || tr.ExpectedChainDigest != transport.ChainDigest(want.ChainFingerprints) {
			return report, errors.New("endpoint verification report differs from the claimed target, identity, or vantage")
		}
		if tr.ObservedAtUnix <= 0 {
			return report, errors.New("endpoint verification report has no observation time")
		}
		if err := validateReceivedProbe(tr); err != nil {
			return report, errors.New("endpoint verification transcript is invalid")
		}
		canonical = append(canonical, tr.Canonical()...)
		canonical = append(canonical, '\n')
	}
	if transport.SweepDigest(canonical) != evidenceDigest {
		return report, errors.New("endpoint verification digest differs from the signed sweep")
	}
	return report, nil
}

func normalizeVerificationFingerprint(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.ReplaceAll(s, ":", "")))
}

// Canonical syntax alone is insufficient: a signed clean verdict cannot
// contradict the fingerprint, dates or comparison digests in its own evidence.
func validateReceivedProbe(tr transport.ProbeTranscript) error {
	if err := tr.Validate(); err != nil {
		return err
	}
	if tr.ObservedAtUnix <= 0 || tr.HandshakeMillis < 0 || tr.ChainBytes < 0 {
		return errors.New("verification has invalid observation measurements")
	}
	if !tr.Reached {
		if tr.NotBeforeUnix != 0 || tr.NotAfterUnix != 0 || tr.ObservedSANDigest != "" || tr.ObservedChainDigest != "" || tr.ChainBytes != 0 {
			return errors.New("unreachable verification invents served certificate data")
		}
		return nil
	}
	if tr.ObservedFingerprint == "" {
		// The shipping probe distinguishes an unparseable peer from a failed dial.
		if tr.Error != "" && tr.Mismatch == certinfo.MismatchFingerprint && !tr.CheckedSANs && !tr.CheckedChain && tr.NotBeforeUnix == 0 && tr.NotAfterUnix == 0 && tr.ObservedSANDigest == "" && tr.ObservedChainDigest == "" {
			return nil
		}
		return errors.New("reached verification has no observed identity")
	}
	if tr.ExpectedFingerprint != tr.ObservedFingerprint && tr.Mismatch != certinfo.MismatchFingerprint {
		return errors.New("verification verdict contradicts its observed fingerprint")
	}
	if tr.Mismatch == certinfo.MismatchNone {
		// A parsed certificate may start at Unix epoch (0) or earlier.
		// Require the observation to be inside its actual validity window;
		// the fingerprint, not a nonzero date, establishes peer presence.
		if tr.Error != "" || tr.ExpectedFingerprint != tr.ObservedFingerprint || tr.NotAfterUnix < tr.NotBeforeUnix || tr.ObservedAtUnix < tr.NotBeforeUnix || tr.ObservedAtUnix > tr.NotAfterUnix {
			return errors.New("clean verification contradicts its identity or validity window")
		}
		if tr.ExpectedSANDigest != "" && (!tr.CheckedSANs || tr.ExpectedSANDigest != tr.ObservedSANDigest) {
			return errors.New("clean verification did not establish the expected names")
		}
		if tr.ExpectedChainDigest != "" && (!tr.CheckedChain || tr.ExpectedChainDigest != tr.ObservedChainDigest) {
			return errors.New("clean verification did not establish the expected chain")
		}
	}
	return nil
}

func validateDeploymentVerificationReport(intent relay.DeployIntent, expected certinfo.Expectation, reportJSON, evidenceDigest, outcome string) (relay.EndpointVerifyResult, error) {
	var report relay.EndpointVerifyReport
	var empty relay.EndpointVerifyResult
	if strings.TrimSpace(intent.TargetID) == "" || strings.TrimSpace(intent.VerifyAddress) == "" || normalizeVerificationFingerprint(intent.Fingerprint) == "" {
		return empty, errors.New("deployment verification has no complete claimed target binding")
	}
	if len(reportJSON) > maxStructuredSyncReportBytes {
		return empty, errors.New("deployment verification exceeds the receiver bound")
	}
	if err := decodeStrictJSON([]byte(reportJSON), &report); err != nil || len(report.Results) != 1 {
		return empty, errors.New("deployment verification must describe exactly its claimed target")
	}
	result := report.Results[0]
	tr := result.Transcript
	if result.EndpointID != intent.TargetID || tr.Address != strings.TrimSpace(intent.VerifyAddress) || tr.ServerName != strings.TrimSpace(intent.VerifyServerName) || tr.Vantage != transport.VantageLocal || tr.ExpectedFingerprint != normalizeVerificationFingerprint(intent.Fingerprint) || tr.ExpectedSANDigest != transport.SANSetDigest(expected.DNSNames) {
		return empty, errors.New("deployment verification differs from its claimed target or issued identity")
	}
	if err := validateReceivedProbe(tr); err != nil {
		return empty, err
	}
	if tr.Digest() != evidenceDigest {
		return empty, errors.New("deployment verification digest differs from its signed evidence")
	}
	healthy := tr.Reached && tr.Mismatch == certinfo.MismatchNone
	if (outcome == transport.JobOutcomeVerified) != healthy {
		return empty, errors.New("deployment outcome contradicts its verification observation")
	}
	return result, nil
}
