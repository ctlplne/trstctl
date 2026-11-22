// SPDX-License-Identifier: BUSL-1.1

// Shared blocking reviewer and policy for gateway command security regressions.
package accessgateway

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/accessrules"
)

// blockingReviewer stands in for the control plane: every matched occurrence is
// durably BLOCKED, exactly as a block rule decides.
type blockingReviewer struct {
	mu        sync.Mutex
	protocol  string
	sessionID string
	digest    string
	seen      [][]string
}

func (r *blockingReviewer) ReviewGatewayAction(_ context.Context, jobID int64, attempt int, key string, o accessrules.Observation, _ bool) (accessrules.Decision, error) {
	r.mu.Lock()
	r.seen = append(r.seen, append([]string{o.Phase}, o.Operations...))
	r.mu.Unlock()
	now := time.Now().UTC()
	reason := "matched_rule"
	switch o.Phase {
	case "control":
		reason = "unsupported_control"
	case "uninspectable":
		reason = "uninspectable"
	}
	return accessrules.Decision{ID: key, SessionID: r.sessionID, JobID: jobID, Attempt: attempt, Protocol: r.protocol, Observation: o,
		PolicyDigest: r.digest, Status: accessrules.StatusBlocked, Reason: reason, DecidedAt: now, ObservedAt: now}, nil
}

func gatewayBlockPolicy(t *testing.T, protocol string, ops []string) (*accessrules.Policy, string) {
	t.Helper()
	ops = slices.Clone(ops)
	slices.Sort(ops)
	policy := &accessrules.Policy{Version: 1, TemplateID: uuid.NewString(), TemplateRevision: 1, Rules: []accessrules.PolicyRule{
		{ID: uuid.NewString(), Protocol: protocol, Operations: ops, Effect: accessrules.EffectBlock}}}
	if err := accessrules.ValidatePolicy(policy, protocol); err != nil {
		t.Fatal(err)
	}
	digest, err := accessrules.PolicyDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	return policy, digest
}
