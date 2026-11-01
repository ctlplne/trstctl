// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Closed-loop verification (X3). A migration run that requires observed
// traffic keeps each wave at its live gate until an observer agent (X1) has
// also seen new connections at every member's endpoint after its successor
// went live: the live receipt proves the served chain, which the wire cannot
// show on TLS 1.3, and the observer proves what real clients now negotiate.
// On the leader each pass records that wire evidence on the run; a member
// still unobserved when its window ends pauses the run, so a wave never
// advances on the probe alone. When a member has both proofs, the observer's
// finding for its predecessor certificate at that endpoint is marked
// remediated with the evidence that closed it, and not before.

const migrationTrafficInterval = 30 * time.Second

// migrationTrafficActor names the gate in the events it appends.
const migrationTrafficActor = "system:migration-traffic-gate"

// maxObservedHandshakes bounds one tenant pass over observer findings.
const maxObservedHandshakes = 5000

// RunMigrationTrafficGate checks runs that require observed traffic on the leader.
func (s *Server) RunMigrationTrafficGate(ctx context.Context) {
	ticker := time.NewTicker(migrationTrafficInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.CheckMigrationTrafficOnce(ctx, time.Now().UTC()); err != nil && s.logger != nil {
				s.logger.Warn("migration traffic gate could not check every run", slog.String("error", err.Error()))
			}
		}
	}
}

// CheckMigrationTrafficOnce visits every running or paused run that requires
// observed traffic.
func (s *Server) CheckMigrationTrafficOnce(ctx context.Context, now time.Time) error {
	if s.store == nil || s.orch == nil {
		return nil
	}
	tenants, err := s.store.TenantsWithMigrationRunsAwaitingTraffic(ctx)
	if err != nil {
		return err
	}
	ctx = events.ContextWithActor(ctx, events.Actor{Subject: migrationTrafficActor})
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, tenantID := range tenants {
		runs, err := s.store.ListMigrationRuns(ctx, tenantID, 200)
		if err != nil {
			note(err)
			continue
		}
		var handshakes []observedHandshake
		loaded := false
		for _, row := range runs {
			run := row.Run
			if !run.RequireObservedTraffic || (run.Status != migration.RunRunning && run.Status != migration.RunPaused) {
				continue
			}
			awaiting := migration.AwaitingObservedTraffic(run)
			if len(awaiting) == 0 {
				continue
			}
			if !loaded {
				if handshakes, err = s.observedHandshakes(ctx, tenantID); err != nil {
					note(err)
					break
				}
				loaded = true
			}
			note(s.checkRunTraffic(ctx, tenantID, run, awaiting, handshakes, now))
		}
	}
	return firstErr
}

func (s *Server) checkRunTraffic(ctx context.Context, tenantID string, run migration.Run, awaiting []migration.RunMemberRef, handshakes []observedHandshake, now time.Time) error {
	window := migration.ObservedTrafficWindow(run)
	var late []string
	for _, ref := range awaiting {
		member := ref.Member
		evidence, ok := trafficEvidence(member, handshakes)
		if ok {
			eventID := orchestrator.MigrationEventID(tenantID, run.ID, "traffic:"+ref.WaveID+":"+member.IdentityID)
			updated, err := s.orch.UpdateMigrationRun(ctx, tenantID, run.ID, eventID,
				func(current migration.Run) (migration.Run, []migration.Action, error) {
					return migration.Observe(current, migration.Observation{
						WaveID: ref.WaveID, IdentityID: member.IdentityID,
						Stage: migration.StageObservedTraffic, Verdict: migration.VerdictVerified, At: now,
					})
				})
			if err != nil {
				return err
			}
			run = updated.Run
			if err := s.closePredecessorFindings(ctx, tenantID, run.ID, member, evidence, handshakes); err != nil {
				return err
			}
			continue
		}
		if member.LiveVerifiedAt != nil && now.Sub(*member.LiveVerifiedAt) >= window {
			late = append(late, member.Binding.VerifyAddress)
		}
	}
	if len(late) == 0 || run.Status != migration.RunRunning {
		return nil
	}
	reason := fmt.Sprintf("no new connections observed at %s within %s of the successor going live", strings.Join(late, ", "), window)
	eventID := orchestrator.MigrationEventID(tenantID, run.ID, "traffic-pause:"+now.Format(time.RFC3339))
	_, err := s.orch.UpdateMigrationRun(ctx, tenantID, run.ID, eventID,
		func(current migration.Run) (migration.Run, []migration.Action, error) {
			if current.Status != migration.RunRunning {
				return current, nil, nil
			}
			paused, err := migration.PauseRun(current, reason)
			return paused, nil, err
		})
	return err
}

// observedHandshake is one observer finding's facts.
type observedHandshake struct {
	FindingID    string
	TriageStatus string
	Server       string
	ServerName   string
	Fingerprint  string
	Visible      bool
	LastSeen     time.Time
}

// observedHandshakes reads the tenant's observer TLS findings in ID order, up
// to maxObservedHandshakes.
func (s *Server) observedHandshakes(ctx context.Context, tenantID string) ([]observedHandshake, error) {
	var out []observedHandshake
	after := store.ZeroUUID
	for len(out) < maxObservedHandshakes {
		page, err := s.store.ListDiscoveryFindingsFiltered(ctx, tenantID, store.DiscoveryFindingFilter{Kind: "tls_handshake"}, after, 500)
		if err != nil {
			return nil, err
		}
		for _, f := range page {
			var meta map[string]string
			if err := json.Unmarshal(f.Metadata, &meta); err != nil {
				continue
			}
			lastSeen, err := time.Parse(time.RFC3339, meta["last_seen"])
			if err != nil {
				continue
			}
			out = append(out, observedHandshake{
				FindingID: f.ID, TriageStatus: f.TriageStatus, Server: meta["server"], ServerName: meta["server_name"],
				Fingerprint: strings.ToLower(f.Fingerprint), Visible: meta["certificate_visible"] == "true", LastSeen: lastSeen,
			})
		}
		if len(page) < 500 {
			break
		}
		after = page[len(page)-1].ID
	}
	return out, nil
}

// at reports whether the handshake was observed at the member's endpoint:
// its verify address, or its server name on the same port.
func (h observedHandshake) at(binding migration.MemberBinding) bool {
	if h.Server == binding.VerifyAddress {
		return true
	}
	_, port, err := net.SplitHostPort(binding.VerifyAddress)
	if err != nil || binding.VerifyServerName == "" || h.ServerName != binding.VerifyServerName {
		return false
	}
	_, observedPort, err := net.SplitHostPort(h.Server)
	return err == nil && observedPort == port
}

// trafficEvidence finds new connections at the member's endpoint after its
// successor went live: on TLS 1.2 they must present the successor; on TLS 1.3
// the certificate is encrypted, so the live receipt already proved the chain.
func trafficEvidence(member migration.RunMember, handshakes []observedHandshake) (observedHandshake, bool) {
	if member.LiveVerifiedAt == nil {
		return observedHandshake{}, false
	}
	successor := strings.ToLower(member.Binding.SuccessorFingerprint)
	for _, h := range handshakes {
		if !h.at(member.Binding) || h.LastSeen.Before(*member.LiveVerifiedAt) {
			continue
		}
		if h.Visible && h.Fingerprint != successor {
			continue
		}
		return h, true
	}
	return observedHandshake{}, false
}

// closePredecessorFindings marks the observer's findings for the predecessor
// certificate at the member's endpoint remediated, naming the evidence.
func (s *Server) closePredecessorFindings(ctx context.Context, tenantID, runID string, member migration.RunMember, evidence observedHandshake, handshakes []observedHandshake) error {
	predecessor := strings.ToLower(member.Binding.PredecessorFingerprint)
	if predecessor == "" {
		return nil
	}
	for _, h := range handshakes {
		if h.Fingerprint != predecessor || !h.at(member.Binding) || h.TriageStatus == string(discovery.TriageRemediated) {
			continue
		}
		_, err := s.orch.ResolveDiscoveryFinding(ctx, tenantID, h.FindingID, orchestrator.DiscoveryFindingResolution{
			Status: discovery.TriageRemediated,
			Reason: "the endpoint serves its successor: live receipt and new connections observed",
			EvidenceRef: fmt.Sprintf("migration run %s member %s: live receipt at %s; observed connections finding %s at %s",
				runID, member.IdentityID, member.LiveVerifiedAt.Format(time.RFC3339), evidence.FindingID, evidence.LastSeen.Format(time.RFC3339)),
		})
		if err != nil {
			return err
		}
	}
	return nil
}
