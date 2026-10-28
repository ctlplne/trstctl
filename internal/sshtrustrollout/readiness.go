// SPDX-License-Identifier: BUSL-1.1

package sshtrustrollout

import (
	"errors"
	"regexp"
)

var sshFingerprint = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// Readiness is the public, host-local configuration census carried by an
// authenticated heartbeat. Paths, argv and public-key bytes do not cross here.
// RecordedAt and enrolled host identity come from the receiving control plane.
type Readiness struct {
	Enabled       bool   `json:"enabled"`
	Confirmed     bool   `json:"confirmed"`
	CAFingerprint string `json:"ca_fingerprint,omitempty"`
	PolicyDigest  string `json:"policy_digest,omitempty"`
	IssueCode     string `json:"issue_code,omitempty"`
}

func (r Readiness) Ready() bool {
	return r.Enabled && r.Confirmed && r.IssueCode == "" && sshFingerprint.MatchString(r.CAFingerprint) && digest(r.PolicyDigest)
}

func (r Readiness) State() string {
	if r.IssueCode == "report_state_paused" {
		return "claims_paused"
	}
	if !r.Enabled {
		return "disabled"
	}
	if !r.Confirmed {
		return "unconfirmed"
	}
	if !r.Ready() {
		return "misconfigured"
	}
	return "ready"
}

// Validate keeps the authenticated census a small closed metadata contract.
// A local error is a code, never a path, argv or arbitrary stderr string.
func (r Readiness) Validate() error {
	if !r.Enabled {
		if r.Confirmed || r.CAFingerprint != "" || r.PolicyDigest != "" || (r.IssueCode != "" && r.IssueCode != "report_state_paused") {
			return errors.New("disabled SSH readiness cannot carry local authority")
		}
		return nil
	}
	if r.CAFingerprint != "" && !sshFingerprint.MatchString(r.CAFingerprint) {
		return errors.New("SSH readiness has an invalid public CA fingerprint")
	}
	if r.PolicyDigest != "" && !digest(r.PolicyDigest) {
		return errors.New("SSH readiness has an invalid local policy digest")
	}
	switch r.IssueCode {
	case "", "local_configuration_invalid", "report_state_paused":
	default:
		return errors.New("SSH readiness has an unknown local issue code")
	}
	if r.Confirmed && r.IssueCode == "" && !r.Ready() {
		return errors.New("confirmed SSH readiness needs its staged CA and local policy digest")
	}
	return nil
}
