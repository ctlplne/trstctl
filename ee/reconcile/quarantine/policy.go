// SPDX-License-Identifier: LicenseRef-trstctl-EE

package quarantine

import (
	"strings"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/witness"
)

const defaultStalenessThresholdSec int64 = 7200

type Policy struct {
	IssuingAuthorities       map[string]bool
	StalenessThresholdSec    int64
	AttributeConflictRecords map[string]bool
}

func ReferencePolicy(issuingAuthorities ...string) Policy {
	issuing := map[string]bool{}
	for _, authorityID := range issuingAuthorities {
		if authorityID = strings.TrimSpace(authorityID); authorityID != "" {
			issuing[authorityID] = true
		}
	}
	return Policy{
		IssuingAuthorities:    issuing,
		StalenessThresholdSec: defaultStalenessThresholdSec,
		AttributeConflictRecords: map[string]bool{
			canon.RecordTypeX509Certificate: true,
		},
	}
}

type policyDecision struct {
	quarantine  bool
	authorityID string
	reason      string
}

func (p Policy) evaluate(e witness.Evidence) policyDecision {
	if p.empty() {
		p = ReferencePolicy()
	}
	for _, entry := range e.Body.Entries {
		switch entry.Class {
		case witness.ClassPolicyViolation:
			if entry.Policy == nil {
				continue
			}
			authorityID := strings.TrimSpace(entry.Policy.AuthorityID)
			if authorityID != "" && p.isIssuingAuthority(authorityID) {
				return policyDecision{quarantine: true, authorityID: authorityID, reason: "policy_violation"}
			}
		case witness.ClassAttributeConflict:
			if p.quarantinesAttributeConflict(entry.RecordKey) {
				if authorityID := firstEntryAuthority(entry); authorityID != "" {
					return policyDecision{quarantine: true, authorityID: authorityID, reason: "revocation_state_conflict"}
				}
			}
		case witness.ClassStaleness:
			if entry.Staleness == nil {
				continue
			}
			authorityID := strings.TrimSpace(entry.Staleness.AuthorityID)
			if authorityID != "" && entry.Staleness.LivenessSec > p.stalenessThreshold() {
				return policyDecision{quarantine: true, authorityID: authorityID, reason: "staleness"}
			}
		case witness.ClassPresence:
			continue
		}
	}
	return policyDecision{}
}

func (p Policy) empty() bool {
	return len(p.IssuingAuthorities) == 0 && p.StalenessThresholdSec == 0 && len(p.AttributeConflictRecords) == 0
}

func (p Policy) isIssuingAuthority(authorityID string) bool {
	authorityID = strings.TrimSpace(authorityID)
	if authorityID == "" {
		return false
	}
	if len(p.IssuingAuthorities) == 0 {
		return true
	}
	return p.IssuingAuthorities[authorityID]
}

func (p Policy) quarantinesAttributeConflict(key canon.RecordKey) bool {
	if len(p.AttributeConflictRecords) == 0 {
		return key.RecordType == canon.RecordTypeX509Certificate
	}
	return p.AttributeConflictRecords[strings.TrimSpace(key.RecordType)]
}

func (p Policy) stalenessThreshold() int64 {
	if p.StalenessThresholdSec <= 0 {
		return defaultStalenessThresholdSec
	}
	return p.StalenessThresholdSec
}

func firstEntryAuthority(entry witness.Entry) string {
	for _, disclosed := range entry.DisclosedRecords {
		if authorityID := strings.TrimSpace(disclosed.AuthorityID); authorityID != "" {
			return authorityID
		}
	}
	for _, inclusion := range entry.Inclusions {
		if authorityID := strings.TrimSpace(inclusion.AuthorityID); authorityID != "" {
			return authorityID
		}
	}
	if authorityID := strings.TrimSpace(entry.PresentAuthority); authorityID != "" {
		return authorityID
	}
	return ""
}
