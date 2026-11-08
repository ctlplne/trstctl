// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A278: gateway pools. The gateways of a pool share sessions: a target bound
// to any member is served by the healthy, undrained member with the fewest
// live sessions when a session starts, and that member owns the session —
// its job is claimable by that gateway alone. A member that has not
// heartbeated within gatewayLostAfter is lost: new sessions go to the
// others, and every live session it owned is revoked by the gateway-health
// actor, so its credential is withdrawn and it reads ended with A255's
// bounded uncertainty (it may still serve until its native deadline).

const (
	pamGatewayPoolMaxMembers = 16
	// defaultPAMGatewayLostAfter is four missed 30-second heartbeats.
	defaultPAMGatewayLostAfter = 2 * time.Minute
	// pamGatewayHealthActor revokes the sessions of a lost gateway.
	pamGatewayHealthActor = "trstctl:gateway-health"
)

var pamGatewayPoolName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func gatewayLostAfterOrDefault(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultPAMGatewayLostAfter
	}
	return d
}

// SavePAMGatewayPool creates a pool (no revision) or replaces one at the
// revision the caller read.
func (s *pamService) SavePAMGatewayPool(ctx context.Context, tenantID, actor string, p api.PAMGatewayPool) (api.PAMGatewayPool, error) {
	var saved api.PAMGatewayPool
	err := s.store.WithPAMCatalogLock(ctx, tenantID, func() error {
		var err error
		saved, err = s.savePAMGatewayPool(ctx, tenantID, actor, p)
		return err
	})
	return saved, err
}

func (s *pamService) savePAMGatewayPool(ctx context.Context, tenantID, actor string, p api.PAMGatewayPool) (api.PAMGatewayPool, error) {
	switch {
	case actor == "":
		return api.PAMGatewayPool{}, fmt.Errorf("%w: an authenticated author is required", api.ErrPAMInvalid)
	case !pamGatewayPoolName.MatchString(p.Name):
		return api.PAMGatewayPool{}, fmt.Errorf("%w: name must be 1-64 lowercase letters, digits, - or _", api.ErrPAMInvalid)
	case len(p.Members) == 0 || len(p.Members) > pamGatewayPoolMaxMembers:
		return api.PAMGatewayPool{}, fmt.Errorf("%w: a pool has 1-%d gateways", api.ErrPAMInvalid, pamGatewayPoolMaxMembers)
	}
	members := make([]projections.PAMGatewayPoolMember, 0, len(p.Members))
	for _, m := range p.Members {
		m.AgentID, m.Address = strings.TrimSpace(m.AgentID), strings.TrimSpace(m.Address)
		if slices.ContainsFunc(members, func(x projections.PAMGatewayPoolMember) bool { return x.AgentID == m.AgentID }) {
			return api.PAMGatewayPool{}, fmt.Errorf("%w: gateway %s is listed twice", api.ErrPAMInvalid, m.AgentID)
		}
		// A member is checked as a target's gateway binding is.
		if err := s.validateGatewayBinding(ctx, tenantID, api.PAMTarget{GatewayAgentID: m.AgentID, GatewayAddress: m.Address}); err != nil {
			return api.PAMGatewayPool{}, err
		}
		if other, found, err := s.store.PAMGatewayPoolFor(ctx, tenantID, m.AgentID); err != nil {
			return api.PAMGatewayPool{}, err
		} else if found && other.Name != p.Name {
			return api.PAMGatewayPool{}, fmt.Errorf("%w: gateway %s is in pool %s", api.ErrPAMTargetConflict, m.AgentID, other.Name)
		}
		members = append(members, projections.PAMGatewayPoolMember{AgentID: m.AgentID, Address: m.Address, Draining: m.Draining})
	}
	revision := int64(1)
	current, err := s.store.GetPAMGatewayPoolAny(ctx, tenantID, p.Name)
	switch {
	case errors.Is(err, store.ErrPAMGatewayPoolNotFound):
		if p.Revision != 0 {
			return api.PAMGatewayPool{}, fmt.Errorf("%w: pool %s does not exist; omit revision to create it", orchestrator.ErrIdempotencyConflict, p.Name)
		}
	case err != nil:
		return api.PAMGatewayPool{}, err
	case current.DeletedAt != nil:
		if p.Revision != 0 {
			return api.PAMGatewayPool{}, fmt.Errorf("%w: pool %s was deleted; omit revision to create it again", orchestrator.ErrIdempotencyConflict, p.Name)
		}
		revision = current.Revision + 1
	default:
		if p.Revision != current.Revision {
			return api.PAMGatewayPool{}, fmt.Errorf("%w: pool %s is at revision %d; read it again", orchestrator.ErrIdempotencyConflict, p.Name, current.Revision)
		}
		revision = current.Revision + 1
	}
	if err := s.appendProject(ctx, tenantID, projections.EventPAMGatewayPoolSaved, projections.PAMGatewayPoolSaved{Name: p.Name, Members: members,
		Revision: revision, Actor: actor, At: s.clock().UTC()}); err != nil {
		return api.PAMGatewayPool{}, err
	}
	saved, err := s.store.GetPAMGatewayPool(ctx, tenantID, p.Name)
	if err != nil {
		return api.PAMGatewayPool{}, err
	}
	return s.gatewayPoolView(ctx, tenantID, saved)
}

// ListPAMGatewayPools returns the tenant's pools with each member's health
// and live sessions.
func (s *pamService) ListPAMGatewayPools(ctx context.Context, tenantID string) ([]api.PAMGatewayPool, error) {
	pools, err := s.store.ListPAMGatewayPools(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]api.PAMGatewayPool, 0, len(pools))
	for _, p := range pools {
		view, err := s.gatewayPoolView(ctx, tenantID, p)
		if err != nil {
			return nil, err
		}
		out = append(out, view)
	}
	return out, nil
}

// DeletePAMGatewayPool deletes a pool at the revision the caller read. Its
// gateways then serve only the targets bound to each; their live sessions
// are unaffected.
func (s *pamService) DeletePAMGatewayPool(ctx context.Context, tenantID, actor, name string, revision int64) error {
	return s.store.WithPAMCatalogLock(ctx, tenantID, func() error {
		current, err := s.store.GetPAMGatewayPool(ctx, tenantID, name)
		if err != nil {
			return err
		}
		if current.Revision != revision {
			return fmt.Errorf("%w: pool %s is at revision %d; read it again", orchestrator.ErrIdempotencyConflict, name, current.Revision)
		}
		return s.appendProject(ctx, tenantID, projections.EventPAMGatewayPoolDeleted, projections.PAMGatewayPoolDeleted{Name: name,
			Revision: current.Revision + 1, Actor: actor, At: s.clock().UTC()})
	})
}

func (s *pamService) gatewayPoolView(ctx context.Context, tenantID string, p store.PAMGatewayPool) (api.PAMGatewayPool, error) {
	now := s.clock().UTC()
	ids := make([]string, 0, len(p.Members))
	for _, m := range p.Members {
		ids = append(ids, m.AgentID)
	}
	live, err := s.store.CountLiveGatewaySessions(ctx, tenantID, ids, now)
	if err != nil {
		return api.PAMGatewayPool{}, err
	}
	view := api.PAMGatewayPool{Name: p.Name, Revision: p.Revision, SavedBy: p.SavedBy, SavedAt: p.SavedAt.UTC(), Members: []api.PAMGatewayMember{}}
	for _, m := range p.Members {
		agent, agentErr := s.store.GetAgent(ctx, tenantID, m.AgentID)
		upgrading := s.gatewayUpgrading(ctx, tenantID, m.AgentID)
		member := api.PAMGatewayMember{AgentID: m.AgentID, Address: m.Address, Draining: m.Draining, UpgradePending: upgrading,
			Health: s.gatewayHealth(agent, agentErr, m, upgrading, now), LiveSessions: live[m.AgentID]}
		if agentErr == nil && agent.LastSeenAt != nil {
			at := agent.LastSeenAt.UTC()
			member.LastSeenAt = &at
		}
		view.Members = append(view.Members, member)
	}
	return view, nil
}

// gatewayHealth is a member's state: offboarded, lost (no heartbeat within
// gatewayLostAfter), draining (by the operator, or for a queued upgrade), or
// healthy.
func (s *pamService) gatewayHealth(agent store.Agent, agentErr error, m store.PAMGatewayMember, upgrading bool, now time.Time) string {
	switch {
	case agentErr != nil || agent.OffboardedAt != nil:
		return "offboarded"
	case agent.LastSeenAt == nil || now.Sub(*agent.LastSeenAt) > gatewayLostAfterOrDefault(s.gatewayLostAfter):
		return "lost"
	case m.Draining || upgrading:
		return "draining"
	default:
		return "healthy"
	}
}

// gatewayUpgrading reports whether a gateway has a self-upgrade queued or in
// flight: it drains first, taking no new sessions (A278 part 2).
func (s *pamService) gatewayUpgrading(ctx context.Context, tenantID, agentID string) bool {
	pending, err := s.store.PendingAgentUpgrade(ctx, tenantID, agentID)
	return err == nil && pending
}

// withholdGatewayUpgrade reports whether a gateway's upgrade must wait: it is
// in a pool and still owns live sessions, which run to their end — and their
// recordings to their seal — before it is handed the upgrade. A gateway in no
// pool upgrades as before.
func (s *pamService) withholdGatewayUpgrade(ctx context.Context, tenantID, agentID string) bool {
	if _, found, err := s.store.PAMGatewayPoolFor(ctx, tenantID, agentID); err != nil || !found {
		return err != nil
	}
	live, err := s.store.CountLiveGatewaySessions(ctx, tenantID, []string{agentID}, s.clock().UTC())
	return err != nil || live[agentID] > 0
}

// gatewayRunsKind reports whether a gateway's executor report says it can
// serve a job kind that needs one (command rules, native desktops).
func gatewayRunsKind(agent store.Agent, kind string) bool {
	var report transport.ExecutorReport
	if agent.ExecutorsReportedAt == nil || json.Unmarshal(agent.Executors, &report) != nil || report.PendingReportError != "" {
		return false
	}
	for _, k := range report.Kinds {
		if k.Kind == kind && len(k.MissingFlags) == 0 {
			return true
		}
	}
	return false
}

// pamSessionNeedsExecutor is the job kind a session's gateway must report it
// can run, or "" when any gateway serves it.
func pamSessionNeedsExecutor(intent accessgateway.SessionIntent) string {
	if intent.CommandPolicy == nil && intent.TargetType != accessgateway.TargetRDP {
		return ""
	}
	return accessgateway.KindForIntent(intent)
}

// chooseGateway picks the gateway a new session starts on. A gateway in no
// pool serves its own targets, as before pools. A pooled one shares them:
// the healthy, undrained member with the fewest live sessions (then the
// lowest agent ID) that can run the session's job owns it.
func (s *pamService) chooseGateway(ctx context.Context, tenantID, agentID, address, needKind string) (string, string, error) {
	pool, found, err := s.store.PAMGatewayPoolFor(ctx, tenantID, agentID)
	if err != nil {
		return "", "", err
	}
	if !found {
		return agentID, address, nil
	}
	now := s.clock().UTC()
	ids := make([]string, 0, len(pool.Members))
	for _, m := range pool.Members {
		ids = append(ids, m.AgentID)
	}
	live, err := s.store.CountLiveGatewaySessions(ctx, tenantID, ids, now)
	if err != nil {
		return "", "", err
	}
	best := -1
	for i, m := range pool.Members {
		agent, agentErr := s.store.GetAgent(ctx, tenantID, m.AgentID)
		if s.gatewayHealth(agent, agentErr, m, s.gatewayUpgrading(ctx, tenantID, m.AgentID), now) != "healthy" ||
			(needKind != "" && !gatewayRunsKind(agent, needKind)) {
			continue
		}
		if best < 0 {
			best = i
			continue
		}
		b := pool.Members[best]
		if live[m.AgentID] < live[b.AgentID] || (live[m.AgentID] == live[b.AgentID] && m.AgentID < b.AgentID) {
			best = i
		}
	}
	if best < 0 {
		return "", "", fmt.Errorf("%w: no gateway of pool %s is reachable and taking sessions", api.ErrPAMRejected, pool.Name)
	}
	return pool.Members[best].AgentID, pool.Members[best].Address, nil
}

// gatewayMemberAddress is the address a pooled gateway is reached at, for a
// session it owns on another member's target.
func (s *pamService) gatewayMemberAddress(ctx context.Context, tenantID, agentID string) (string, bool) {
	pool, found, err := s.store.PAMGatewayPoolFor(ctx, tenantID, agentID)
	if err != nil || !found {
		return "", false
	}
	for _, m := range pool.Members {
		if m.AgentID == agentID {
			return m.Address, true
		}
	}
	return "", false
}

// gatewayServesTarget reports whether a gateway may serve a target bound to
// another: it is that gateway, or a member of the same pool (A278).
func (s *pamService) gatewayServesTarget(ctx context.Context, tenantID, targetGatewayID, agentID string) bool {
	if targetGatewayID == agentID {
		return agentID != ""
	}
	pool, found, err := s.store.PAMGatewayPoolFor(ctx, tenantID, targetGatewayID)
	if err != nil || !found {
		return false
	}
	return slices.ContainsFunc(pool.Members, func(m store.PAMGatewayMember) bool { return m.AgentID == agentID })
}

// markLostGateways revokes every live session a lost pooled gateway owns:
// the gateway-health actor's revocation recalls its job (so a gateway that
// comes back serves it no longer), withdraws its credential, and leaves the
// session ended with uncertainty bounded by its native deadline (A255).
func (s *pamService) markLostGateways(ctx context.Context) {
	sessions, err := s.store.ListActiveGatewayPAMSessions(ctx, s.clock().UTC(), 200)
	if err != nil {
		return
	}
	now := s.clock().UTC()
	type key struct{ tenant, agent string }
	lost := map[key]bool{}
	for _, rec := range sessions {
		k := key{rec.TenantID, rec.GatewayAgentID}
		gone, seen := lost[k]
		if !seen {
			pool, found, err := s.store.PAMGatewayPoolFor(ctx, rec.TenantID, rec.GatewayAgentID)
			if err != nil {
				continue
			}
			if found {
				agent, agentErr := s.store.GetAgent(ctx, rec.TenantID, rec.GatewayAgentID)
				for _, m := range pool.Members {
					if m.AgentID == rec.GatewayAgentID {
						gone = s.gatewayHealth(agent, agentErr, m, false, now) == "lost"
					}
				}
			}
			lost[k] = gone
		}
		if !gone {
			continue
		}
		_, _ = s.RevokePAMSession(ctx, rec.TenantID, rec.ID, pamGatewayHealthActor,
			"gateway lost: "+rec.GatewayAgentID+" stopped reporting", "gateway-lost:"+rec.ID)
	}
}

// SavePAMGatewayPool is the served broker's gateway pool service.
func (s *Server) SavePAMGatewayPool(ctx context.Context, tenantID, actor string, p api.PAMGatewayPool) (api.PAMGatewayPool, error) {
	if s.pam == nil {
		return api.PAMGatewayPool{}, api.ErrPAMUnavailable
	}
	return s.pam.SavePAMGatewayPool(ctx, tenantID, actor, p)
}

// ListPAMGatewayPools lists the tenant's gateway pools.
func (s *Server) ListPAMGatewayPools(ctx context.Context, tenantID string) ([]api.PAMGatewayPool, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.ListPAMGatewayPools(ctx, tenantID)
}

// DeletePAMGatewayPool deletes a gateway pool at its revision.
func (s *Server) DeletePAMGatewayPool(ctx context.Context, tenantID, actor, name string, revision int64) error {
	if s.pam == nil {
		return api.ErrPAMUnavailable
	}
	return s.pam.DeletePAMGatewayPool(ctx, tenantID, actor, name, revision)
}

// pamWithholdGatewayUpgrade is the agent channel's drain-before-upgrade gate
// (A278), or nil when PAM is not served.
func (s *Server) pamWithholdGatewayUpgrade() func(ctx context.Context, tenantID, agentID string) bool {
	if s.pam == nil {
		return nil
	}
	return s.pam.withholdGatewayUpgrade
}
