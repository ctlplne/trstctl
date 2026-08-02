// SPDX-License-Identifier: LicenseRef-trstctl-EE

package digest

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/internal/crypto"
)

const policySetDomain = "xrec/policy-set/v1"

var ErrInvalidRule = errors.New("digest: invalid posture rule")

// Rule is one ordered policy predicate in the posture set.
type Rule struct {
	ID         string
	Expression string
	Evaluate   func(canon.CanonicalRecord) bool
}

// RuleCount is the digest-level posture result for one rule.
type RuleCount struct {
	RuleID          string
	SatisfyingCount uint64
	ViolatingCount  uint64
}

// PostureSummary is R-13: a policy-set hash plus per-rule counts.
type PostureSummary struct {
	PolicySetHash []byte
	PerRule       []RuleCount
}

// SummarizePosture evaluates the ordered rule set over records.
// SummarizePosture counts records per policy rule so the signed digest body
// carries a policy-posture summary alongside the observation watermark
// (XREC-claim-11).
func SummarizePosture(rules []Rule, records []canon.CanonicalRecord) (PostureSummary, error) {
	if err := validateRules(rules); err != nil {
		return PostureSummary{}, err
	}
	out := PostureSummary{
		PolicySetHash: PolicySetHash(rules),
		PerRule:       make([]RuleCount, 0, len(rules)),
	}
	for _, rule := range rules {
		count := RuleCount{RuleID: strings.TrimSpace(rule.ID)}
		for _, rec := range records {
			if rule.Evaluate(rec) {
				count.SatisfyingCount++
			} else {
				count.ViolatingCount++
			}
		}
		out.PerRule = append(out.PerRule, count)
	}
	return out, nil
}

// PolicySetHash returns the canonical hash of the ordered rule IDs and
// expression strings. Predicate code is not serialized; Expression is the
// policy-profile identifier the deployment publishes.
func PolicySetHash(rules []Rule) []byte {
	var b bytes.Buffer
	b.WriteString(policySetDomain)
	writeU64(&b, uint64(len(rules)))
	for _, rule := range rules {
		writeField(&b, strings.TrimSpace(rule.ID))
		writeField(&b, strings.TrimSpace(rule.Expression))
	}
	return crypto.SHA256Sum(b.Bytes())
}

func validateRules(rules []Rule) error {
	seen := map[string]struct{}{}
	for _, rule := range rules {
		id := strings.TrimSpace(rule.ID)
		if id == "" || strings.ContainsRune(id, 0) || rule.Evaluate == nil {
			return fmt.Errorf("%w: %q", ErrInvalidRule, rule.ID)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("%w: duplicate %q", ErrInvalidRule, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func (s PostureSummary) normalized() PostureSummary {
	return PostureSummary{
		PolicySetHash: append([]byte(nil), s.PolicySetHash...),
		PerRule:       append([]RuleCount(nil), s.PerRule...),
	}
}

func writeField(b *bytes.Buffer, s string) {
	data := []byte(s)
	writeU64(b, uint64(len(data)))
	b.Write(data)
}
