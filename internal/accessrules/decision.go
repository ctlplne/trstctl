// SPDX-License-Identifier: BUSL-1.1

package accessrules

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	StatusBlocked    = "blocked"
	StatusPending    = "pending"
	StatusAuthorized = "authorized"
	StatusDenied     = "denied"
	StatusExpired    = "expired"
	StatusCanceled   = "canceled"
)

// Observation carries public identifiers and a one-way message digest only.
// Operation names come from the finite public selector vocabulary;
// neither arguments nor authentication material can be represented here.
type Observation struct {
	ConnectionID  string   `json:"connection_id"`
	Ordinal       int64    `json:"ordinal"`
	Phase         string   `json:"phase"`
	RuleIDs       []string `json:"rule_ids"`
	Operations    []string `json:"operations"`
	MessageDigest string   `json:"message_digest"`
}

// Decision binds one occurrence to its exact held session job and policy.
// Status means a gateway decision, not successful execution at the target.
type Decision struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	JobID     int64  `json:"job_id"`
	Attempt   int    `json:"attempt"`
	Protocol  string `json:"protocol"`
	Observation
	PolicyDigest    string     `json:"policy_digest"`
	Status          string     `json:"status"`
	Reason          string     `json:"reason"`
	DecidedAt       time.Time  `json:"decided_at"`
	ObservedAt      time.Time  `json:"observed_at"`
	ReviewExpiresAt *time.Time `json:"review_expires_at,omitempty"`
}

// ActionID is stable for a retried occurrence, distinct for a new connection,
// attempt or ordinal. It is a public correlation ID, never a bearer authority.
func ActionID(session, connection string, jobID int64, attempt int, ordinal int64) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl:pam-command:v1\x00"+session+"\x00"+connection+"\x00"+strconv.FormatInt(jobID, 10)+"\x00"+strconv.Itoa(attempt)+"\x00"+strconv.FormatInt(ordinal, 10))).String()
}

func validUUID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id != uuid.Nil && id.String() == s
}
func ValidDigest(s string) bool { return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == "" }

// ValidateObservation rejects free-form text and unbounded metadata.
func ValidateObservation(o Observation) error {
	if !validUUID(o.ConnectionID) || o.Ordinal < 1 || o.Operations == nil || !ValidDigest(o.MessageDigest) || len(o.RuleIDs) < 1 || len(o.RuleIDs) > MaxRules {
		return errors.New("command rules: invalid action observation")
	}
	switch o.Phase {
	case "query", "bind":
		if len(o.Operations) < 1 || len(o.Operations) > MaxOperations || !slices.IsSorted(o.Operations) {
			return errors.New("command rules: invalid operation facts")
		}
		for i, op := range o.Operations {
			if !knownPostgresRuleOperation(op) || i > 0 && op == o.Operations[i-1] {
				return errors.New("command rules: unknown or duplicate operation fact")
			}
		}
	case "control", "uninspectable":
		if len(o.Operations) != 0 {
			return errors.New("command rules: uninspected traffic has no operation facts")
		}
	default:
		return errors.New("command rules: invalid action phase")
	}
	if !slices.IsSorted(o.RuleIDs) {
		return errors.New("command rules: rule identifiers must be ordered")
	}
	for i, id := range o.RuleIDs {
		if !validUUID(id) || i > 0 && id == o.RuleIDs[i-1] {
			return errors.New("command rules: invalid rule identifiers")
		}
	}
	return nil
}

func ValidateDecision(d Decision) error {
	if err := ValidateObservation(d.Observation); err != nil {
		return err
	}
	if !validUUID(d.SessionID) || d.JobID < 1 || d.Attempt < 1 || d.ID != ActionID(d.SessionID, d.ConnectionID, d.JobID, d.Attempt, d.Ordinal) || d.Protocol != "postgres" || !ValidDigest(d.PolicyDigest) || d.DecidedAt.IsZero() || d.ObservedAt.IsZero() || d.DecidedAt.Before(d.ObservedAt) {
		return errors.New("command rules: invalid bound decision")
	}
	if d.Status == StatusBlocked {
		if d.ReviewExpiresAt != nil || (d.Reason != "matched_rule" && d.Reason != "unsupported_control" && d.Reason != "uninspectable") {
			return errors.New("command rules: invalid blocked decision")
		}
		return nil
	}
	if d.ReviewExpiresAt == nil || !d.ReviewExpiresAt.After(d.ObservedAt) || d.ReviewExpiresAt.Sub(d.ObservedAt) > 45*time.Second {
		return errors.New("command rules: invalid review deadline")
	}
	switch d.Status {
	case StatusPending:
		if d.Reason != "review_required" || !d.DecidedAt.Equal(d.ObservedAt) {
			return errors.New("command rules: invalid held decision")
		}
	case StatusAuthorized:
		if d.Reason != "review_approved" || !d.DecidedAt.Before(*d.ReviewExpiresAt) {
			return errors.New("command rules: invalid authorization")
		}
	case StatusDenied:
		if d.Reason != "review_denied" {
			return errors.New("command rules: invalid denial")
		}
	case StatusExpired:
		if d.Reason != "review_expired" || d.DecidedAt.Before(*d.ReviewExpiresAt) {
			return errors.New("command rules: invalid expiry")
		}
	case StatusCanceled:
		if d.Reason != "client_canceled" && d.Reason != "session_ended" {
			return errors.New("command rules: invalid cancellation")
		}
	default:
		return errors.New("command rules: invalid decision status")
	}
	return nil
}

// ReviewRequirement combines matched facts only. Block has precedence; human
// review uses the largest quorum and shortest lifetime. Control uncertainty is
// always refused and cannot be approved into an uninspected command.
func ReviewRequirement(p *Policy, o Observation) (int, int) {
	if p == nil || (o.Phase != "query" && o.Phase != "bind") {
		return 0, 0
	}
	quorum, ttl := 0, 46
	for _, r := range p.Rules {
		if !slices.Contains(o.RuleIDs, r.ID) {
			continue
		}
		if r.Effect == EffectBlock {
			return 0, 0
		}
		if r.RequiredApprovals > quorum {
			quorum = r.RequiredApprovals
		}
		if r.ReviewTTLSeconds < ttl {
			ttl = r.ReviewTTLSeconds
		}
	}
	return quorum, ttl
}
