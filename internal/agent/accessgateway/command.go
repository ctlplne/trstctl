// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
)

const (
	commandProtocolBytes = 8 << 20
	commandTargetBytes   = 4 << 20
	commandProtocolCalls = 8
	commandTargetCalls   = 4
)

var errCommandBusy = errors.New("accessgateway: command capacity is full")

type ActionReviewer interface {
	ReviewGatewayAction(context.Context, int64, int, string, accessrules.Observation, bool) (accessrules.Decision, error)
}

type commandBudget struct {
	mu          sync.Mutex
	bytes       map[string]int
	targetBytes map[[2]string]int
	calls       map[string]int
	targetCalls map[[2]string]int
}

func (b *commandBudget) reserve(protocol, target string, size int, call bool) (func(), bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.bytes == nil {
		b.bytes = map[string]int{}
		b.targetBytes = map[[2]string]int{}
		b.calls = map[string]int{}
		b.targetCalls = map[[2]string]int{}
	}
	key := [2]string{protocol, target}
	if size < 0 || b.bytes[protocol]+size > commandProtocolBytes || b.targetBytes[key]+size > commandTargetBytes || call && (b.calls[protocol] >= commandProtocolCalls || b.targetCalls[key] >= commandTargetCalls) {
		return nil, false
	}
	b.bytes[protocol] += size
	b.targetBytes[key] += size
	if call {
		b.calls[protocol]++
		b.targetCalls[key]++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.bytes[protocol] -= size
			b.targetBytes[key] -= size
			if b.targetBytes[key] == 0 {
				delete(b.targetBytes, key)
			}
			if call {
				b.calls[protocol]--
				b.targetCalls[key]--
				if b.targetCalls[key] == 0 {
					delete(b.targetCalls, key)
				}
			}
		})
	}, true
}

type commandConnection struct {
	gateway                                                 *Gateway
	sessionID, target, protocol, connectionID, policyDigest string
	job                                                     relay.Job
	policy                                                  *accessrules.Policy
	reviewer                                                ActionReviewer
	ordinal                                                 int64
}

type commandCheck struct {
	decision accessrules.Decision
	durable  bool
}

func (g *Gateway) commandConnection(s *session) (*commandConnection, error) {
	if s.intent.CommandPolicy == nil {
		return nil, nil
	}
	reviewer, ok := g.cfg.Channel.(ActionReviewer)
	if !ok {
		return nil, errors.New("accessgateway: command decisions are unavailable on this channel")
	}
	digest, err := accessrules.PolicyDigest(s.intent.CommandPolicy)
	if err != nil {
		return nil, err
	}
	return &commandConnection{gateway: g, sessionID: s.intent.SessionID, target: s.intent.TargetID, protocol: s.intent.TargetType, connectionID: uuid.NewString(), policyDigest: digest, job: s.job, policy: s.intent.CommandPolicy, reviewer: reviewer}, nil
}

func (c *commandConnection) reserveFrame(size int) (func(), bool) {
	return c.gateway.commands.reserve(c.protocol, c.target, size, false)
}

// evaluate sees only known operations from post-authentication client traffic.
// The source request cannot contain arguments, Bind values or sign-in material.
func (c *commandConnection) evaluate(ctx context.Context, phase string, operations []string, message []byte, parentDigest string) (commandCheck, error) {
	ids := accessrules.Match(c.policy, operations)
	if phase == "control" || phase == "uninspectable" {
		ids = nil
		for _, r := range c.policy.Rules {
			ids = append(ids, r.ID)
		}
	}
	if len(ids) == 0 {
		return commandCheck{}, nil
	}
	facts := accessrules.MatchedOperations(c.policy, operations)
	if phase == "control" || phase == "uninspectable" {
		facts = []string{}
	}
	c.ordinal++
	observation := accessrules.Observation{ConnectionID: c.connectionID, Ordinal: c.ordinal, Phase: phase, RuleIDs: ids, Operations: facts,
		MessageDigest: crypto.SHA256Hex([]byte("trstctl:gateway-action:v1\x00" + phase + "\x00" + parentDigest + "\x00" + crypto.SHA256Hex(message)))}
	id := accessrules.ActionID(c.sessionID, c.connectionID, c.job.JobID, c.job.Attempt, c.ordinal)
	result := commandCheck{decision: accessrules.Decision{ID: id, Observation: observation}}
	release, ok := c.gateway.commands.reserve(c.protocol, c.target, 0, true)
	if !ok {
		return result, errCommandBusy
	}
	defer release()
	for {
		work, cancel := context.WithTimeout(ctx, 5*time.Second)
		decision, err := c.reviewer.ReviewGatewayAction(work, c.job.JobID, c.job.Attempt, id, observation, false)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				c.cancelAction(id, observation)
			}
			return result, err
		}
		if accessrules.ValidateDecision(decision) != nil || decision.ID != id || decision.SessionID != c.sessionID || decision.JobID != c.job.JobID || decision.Attempt != c.job.Attempt || decision.Protocol != c.protocol || decision.PolicyDigest != c.policyDigest || !reflect.DeepEqual(decision.Observation, observation) {
			return result, errors.New("accessgateway: command decision differs from the held occurrence")
		}
		result.decision = decision
		result.durable = true
		if ctx.Err() != nil {
			c.cancelAction(id, observation)
			return result, ctx.Err()
		}
		if decision.Status != accessrules.StatusPending {
			if decision.Status == accessrules.StatusAuthorized && (decision.ReviewExpiresAt == nil || !time.Now().Before(*decision.ReviewExpiresAt)) {
				return result, errors.New("accessgateway: command authorization arrived after its deadline")
			}
			return result, nil
		}
		timer := time.NewTimer(300 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			c.cancelAction(id, observation)
			return result, ctx.Err()
		case <-timer.C:
		}
	}
}

func (c *commandConnection) cancelAction(id string, observation accessrules.Observation) {
	work, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = c.reviewer.ReviewGatewayAction(work, c.job.JobID, c.job.Attempt, id, observation, true)
}
