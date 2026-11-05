// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

func (s *pamService) evaluateGatewayCommand(ctx context.Context, tenantID, agentID string, payload []byte, jobID int64, attempt int, key string, observation accessrules.Observation, cancel bool) (accessrules.Decision, error) {
	var intent accessgateway.SessionIntent
	if len(payload) > 256<<10 || json.Unmarshal(payload, &intent) != nil || accessgateway.ValidateSessionIntent(intent) != nil || intent.CommandPolicy == nil || intent.RequiredAgentID != agentID {
		return accessrules.Decision{}, fmt.Errorf("%w: invalid held policy", api.ErrPAMInvalid)
	}
	if err := accessrules.ValidateObservation(observation); err != nil {
		return accessrules.Decision{}, fmt.Errorf("%w: invalid observation", api.ErrPAMInvalid)
	}
	id := accessrules.ActionID(intent.SessionID, observation.ConnectionID, jobID, attempt, observation.Ordinal)
	if key != id {
		return accessrules.Decision{}, fmt.Errorf("%w: action key differs", api.ErrPAMInvalid)
	}
	policyDigest, err := accessrules.PolicyDigest(intent.CommandPolicy)
	if err != nil {
		return accessrules.Decision{}, err
	}
	available := make([]string, 0, len(intent.CommandPolicy.Rules))
	for _, r := range intent.CommandPolicy.Rules {
		available = append(available, r.ID)
	}
	for _, id := range observation.RuleIDs {
		if !slices.Contains(available, id) {
			return accessrules.Decision{}, fmt.Errorf("%w: other-policy rule", api.ErrPAMInvalid)
		}
	}
	if observation.Phase == "query" || observation.Phase == "bind" {
		if !reflect.DeepEqual(accessrules.Match(intent.CommandPolicy, observation.Operations), observation.RuleIDs) || !reflect.DeepEqual(accessrules.MatchedOperations(intent.CommandPolicy, observation.Operations), observation.Operations) {
			return accessrules.Decision{}, fmt.Errorf("%w: operation facts do not match the named rules", api.ErrPAMInvalid)
		}
	} else if !reflect.DeepEqual(observation.RuleIDs, available) {
		return accessrules.Decision{}, fmt.Errorf("%w: refusal must name the complete frozen policy", api.ErrPAMInvalid)
	}
	reason := "matched_rule"
	switch observation.Phase {
	case "control":
		reason = "unsupported_control"
	case "uninspectable":
		reason = "uninspectable"
	}
	expected := accessrules.Decision{ID: id, SessionID: intent.SessionID, JobID: jobID, Attempt: attempt, Protocol: intent.TargetType, Observation: observation, PolicyDigest: policyDigest, Status: accessrules.StatusBlocked, Reason: reason}
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(projections.EventPAMCommandBlocked+"\x00"+tenantID+"\x00"+id)).String()
	if quorum, ttl := accessrules.ReviewRequirement(intent.CommandPolicy, observation); quorum > 0 {
		return s.reviewGatewayCommand(ctx, tenantID, agentID, intent, expected, quorum, ttl, cancel)
	}
	var result accessrules.Decision
	err = s.store.WithTenantResourceCreation(ctx, tenantID, id, func(work context.Context) error {
		canonical, found, err := s.log.EventByID(work, eventID)
		if err != nil {
			return err
		}
		if !found {
			session, err := s.store.GetPAMSession(work, tenantID, intent.SessionID)
			if err != nil {
				return err
			}
			if session.Status != api.PAMSessionStatusActive || session.GatewayAgentID != agentID || session.Delivery != "gateway" || !s.clock().Before(session.ExpiresAt) || !s.clock().Before(intent.ExpiresAt) {
				return api.ErrPAMRejected
			}
			liveDigest, err := accessrules.PolicyDigest(session.CommandPolicy)
			if err != nil {
				return err
			}
			if session.CommandPolicy == nil || liveDigest != policyDigest {
				return fmt.Errorf("%w: policy differs from held job", api.ErrPAMRejected)
			}
			candidate := expected
			candidate.DecidedAt = s.clock().UTC().Truncate(time.Microsecond)
			candidate.ObservedAt = candidate.DecidedAt
			data, err := json.Marshal(candidate)
			if err != nil {
				return err
			}
			event := events.Event{ID: eventID, Type: projections.EventPAMCommandBlocked, TenantID: tenantID, Time: candidate.DecidedAt, Data: data}
			if actor, ok := events.ActorFromContext(work); ok {
				event.Actor = &actor
			}
			canonical, err = s.log.Append(work, event)
			if err != nil {
				return err
			}
		}
		if canonical.Type != projections.EventPAMCommandBlocked || canonical.TenantID != tenantID || canonical.SchemaVersion != events.DefaultSchemaVersion || len(canonical.Data) > 8<<10 {
			return orchestrator.ErrIdempotencyConflict
		}
		var got accessrules.Decision
		decoder := json.NewDecoder(bytes.NewReader(canonical.Data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&got) != nil {
			return errors.New("invalid canonical command decision")
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return errors.New("trailing canonical command decision")
		}
		if accessrules.ValidateDecision(got) != nil || !got.DecidedAt.Equal(canonical.Time) {
			return errors.New("invalid canonical command binding")
		}
		expected.DecidedAt = got.DecidedAt
		expected.ObservedAt = got.ObservedAt
		if !reflect.DeepEqual(expected, got) {
			return orchestrator.ErrIdempotencyConflict
		}
		if err := s.projector.Apply(work, canonical); err != nil {
			return err
		}
		result = got
		return nil
	})
	return result, err
}

func (s *Server) pamEvaluateCommand() func(context.Context, string, string, []byte, int64, int, string, accessrules.Observation, bool) (accessrules.Decision, error) {
	if s.pam == nil {
		return nil
	}
	return s.pam.evaluateGatewayCommand
}
