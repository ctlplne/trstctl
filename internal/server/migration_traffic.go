// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/pqc/compatlab"
	"trstctl.com/trstctl/internal/projections"
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
//
// A replaced endpoint (X3-L1) rides the same pass: a plain renewal's
// deployment or any other replacement that a good verification found waits
// for the same wire evidence, and closes the observer's findings for the
// certificate it replaced (checkEndpointTraffic).
//
// A PQC pilot that requires observed traffic (X3-L5) rides the same pass: a
// wave whose relay probe passed waits until the observer has seen real
// clients connect at every negotiated target after its probe (presenting the
// pilot's leaf on TLS 1.2), and the gate then closes it with that evidence;
// a target still unobserved when the window ends halts the pilot.

const migrationTrafficInterval = 30 * time.Second

// migrationTrafficActor names the gate in the events it appends.
const migrationTrafficActor = "system:migration-traffic-gate"

// observedHandshakePage is how many observer findings one read takes; a pass
// reads them all, keeping only those at the endpoints it watches (X3-L4).
const observedHandshakePage = 500

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
// observed traffic, and every PQC pilot wave awaiting it.
func (s *Server) CheckMigrationTrafficOnce(ctx context.Context, now time.Time) error {
	if s.store == nil || s.orch == nil {
		return nil
	}
	tenants, err := s.store.TenantsWithMigrationRunsAwaitingTraffic(ctx)
	if err != nil {
		return err
	}
	pilotTenants, err := s.store.TenantsWithPQCPilotsAwaitingTraffic(ctx)
	if err != nil {
		return err
	}
	endpointTenants, err := s.store.TenantsWithEndpointsAwaitingTraffic(ctx)
	if err != nil {
		return err
	}
	tenants = unionSorted(unionSorted(tenants, pilotTenants), endpointTenants)
	ctx = events.ContextWithActor(ctx, events.Actor{Subject: migrationTrafficActor})
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, tenantID := range tenants {
		// X3-L4: gather what awaits observed traffic, then read the tenant's
		// observer findings once, keeping only those at the endpoints it
		// watches, so a deciding finding is seen however many others the
		// tenant holds.
		watch := newTrafficWatch()
		type runCheck struct {
			run      migration.Run
			awaiting []migration.RunMemberRef
		}
		var runChecks []runCheck
		runs, err := s.store.ListMigrationRuns(ctx, tenantID, 200)
		if err != nil {
			note(err)
			continue
		}
		for _, row := range runs {
			run := row.Run
			if !run.RequireObservedTraffic || (run.Status != migration.RunRunning && run.Status != migration.RunPaused) {
				continue
			}
			awaiting := migration.AwaitingObservedTraffic(run)
			if len(awaiting) == 0 {
				continue
			}
			runChecks = append(runChecks, runCheck{run: run, awaiting: awaiting})
			for _, ref := range awaiting {
				watch.add(ref.Member.Binding)
			}
		}
		type pilotCheck struct {
			pilot store.PQCPilot
			wave  store.PQCPilotWave
		}
		var pilotChecks []pilotCheck
		if pilots, err := s.store.ListPQCPilotsAwaitingTraffic(ctx, tenantID); err != nil {
			note(err)
		} else {
			for _, pilot := range pilots {
				for _, wave := range pilot.Waves {
					if wave.Status != "awaiting_traffic" {
						continue
					}
					pilotChecks = append(pilotChecks, pilotCheck{pilot: pilot, wave: wave})
					for _, target := range wave.Targets {
						watch.add(pilotTargetBinding(target))
					}
				}
			}
		}
		type endpointCheck struct {
			endpoint store.EndpointVerification
			at       migration.MemberBinding
		}
		var endpointChecks []endpointCheck
		if endpoints, err := s.store.EndpointsAwaitingTraffic(ctx, tenantID); err != nil {
			note(err)
		} else {
			for _, endpoint := range endpoints {
				if endpoint.ReplacedAt == nil {
					continue
				}
				at, err := s.endpointObservedAt(ctx, tenantID, endpoint)
				if err != nil {
					note(err)
					continue
				}
				endpointChecks = append(endpointChecks, endpointCheck{endpoint: endpoint, at: at})
				watch.add(at)
			}
		}
		if len(runChecks) == 0 && len(pilotChecks) == 0 && len(endpointChecks) == 0 {
			continue
		}
		handshakes, err := s.observedHandshakes(ctx, tenantID, watch)
		if err != nil {
			note(err)
			continue
		}
		for _, c := range runChecks {
			note(s.checkRunTraffic(ctx, tenantID, c.run, c.awaiting, handshakes, now))
		}
		for _, c := range pilotChecks {
			note(s.checkPilotTraffic(ctx, tenantID, c.pilot, c.wave, handshakes, now))
		}
		for _, c := range endpointChecks {
			note(s.checkEndpointTraffic(ctx, tenantID, c.endpoint, c.at, handshakes, now))
		}
	}
	return firstErr
}

// checkEndpointTraffic looks for wire evidence at a replaced endpoint (X3-L1):
// a plain renewal's deployment or any other replacement waits, like a
// migration run's member, until an observer has seen new connections at the
// endpoint after the replacement went live — presenting the replacement on
// TLS 1.2; on TLS 1.3 the certificate is encrypted and the verification
// already proved it. The evidence is recorded on the endpoint and the
// observer's findings for the replaced certificate there are marked
// remediated with it. An endpoint still unobserved when its window has
// passed is recorded unobserved; later evidence still closes it.
func (s *Server) checkEndpointTraffic(ctx context.Context, tenantID string, endpoint store.EndpointVerification, at migration.MemberBinding, handshakes []observedHandshake, now time.Time) error {
	if endpoint.ReplacedAt == nil {
		return nil
	}
	replacement := normalizedFingerprint(endpoint.ObservedFingerprint)
	for _, h := range handshakes {
		if !h.at(at) || h.LastSeen.Before(*endpoint.ReplacedAt) {
			continue
		}
		if h.Visible && normalizedFingerprint(h.Fingerprint) != replacement {
			continue
		}
		if err := s.orch.RecordEndpointTrafficObserved(ctx, tenantID, endpoint.EndpointID, endpoint.Vantage,
			endpoint.ObservedFingerprint, h.FindingID, *endpoint.ReplacedAt, h.LastSeen); err != nil {
			return err
		}
		return s.closeReplacedEndpointFindings(ctx, tenantID, endpoint, at, h, handshakes)
	}
	window := migration.ObservedTrafficWindow(migration.Run{})
	if endpoint.TrafficUnobservedSince == nil && now.Sub(*endpoint.ReplacedAt) >= window {
		return s.orch.RecordEndpointTrafficUnobserved(ctx, tenantID, endpoint.EndpointID, endpoint.Vantage,
			endpoint.ObservedFingerprint, *endpoint.ReplacedAt, endpoint.ReplacedAt.Add(window))
	}
	return nil
}

// endpointObservedAt is where an observer sees a replaced endpoint: its
// address, and the observed addresses its deployment target names when NAT or
// a load balancer sits in front of it (X3-L2). The endpoint ID is the target's.
func (s *Server) endpointObservedAt(ctx context.Context, tenantID string, endpoint store.EndpointVerification) (migration.MemberBinding, error) {
	at := migration.MemberBinding{VerifyAddress: endpoint.Address}
	if _, err := uuid.Parse(endpoint.EndpointID); err != nil {
		return at, nil
	}
	target, err := s.store.GetDeploymentTarget(ctx, tenantID, endpoint.EndpointID)
	if errors.Is(err, pgx.ErrNoRows) {
		return at, nil
	}
	if err != nil {
		return at, err
	}
	// The API refuses a malformed list when the target is saved; one that
	// predates that check names no observed address rather than a guess.
	at.ObservedAddresses, _ = migration.ObservedAddresses(target.Config)
	return at, nil
}

// closeReplacedEndpointFindings marks the observer's findings for the replaced
// certificate at the endpoint remediated, naming the evidence.
func (s *Server) closeReplacedEndpointFindings(ctx context.Context, tenantID string, endpoint store.EndpointVerification, at migration.MemberBinding, evidence observedHandshake, handshakes []observedHandshake) error {
	replaced := normalizedFingerprint(endpoint.ReplacedFingerprint)
	if replaced == "" {
		return nil
	}
	for _, h := range handshakes {
		if normalizedFingerprint(h.Fingerprint) != replaced || !h.at(at) || h.TriageStatus == string(discovery.TriageRemediated) {
			continue
		}
		// A migration run in the same pass may have closed it already.
		if current, err := s.store.GetDiscoveryFinding(ctx, tenantID, h.FindingID); err != nil {
			return err
		} else if current.TriageStatus == string(discovery.TriageRemediated) {
			continue
		}
		_, err := s.orch.ResolveDiscoveryFinding(ctx, tenantID, h.FindingID, orchestrator.DiscoveryFindingResolution{
			Status: discovery.TriageRemediated,
			Reason: "the endpoint serves its replacement: verified and new connections observed",
			EvidenceRef: fmt.Sprintf("endpoint %s (%s): serving %s since %s; observed connections finding %s at %s",
				endpoint.EndpointID, endpoint.Vantage, endpoint.ObservedFingerprint, endpoint.ReplacedAt.Format(time.RFC3339),
				evidence.FindingID, evidence.LastSeen.Format(time.RFC3339)),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// normalizedFingerprint compares certificate fingerprints written with or
// without colons, in either case.
func normalizedFingerprint(fp string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fp), ":", ""))
}

// unionSorted merges two sorted tenant lists without duplicates.
func unionSorted(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, id := range list {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}

// checkPilotTraffic closes a pilot wave's observed-traffic gate once every
// negotiated target has new connections after its probe, or once the window
// since the wave's assessment has ended (X3-L5).
func (s *Server) checkPilotTraffic(ctx context.Context, tenantID string, pilot store.PQCPilot, wave store.PQCPilotWave, handshakes []observedHandshake, now time.Time) error {
	targets := make(map[string]store.PQCPilotTarget, len(wave.Targets))
	for _, target := range wave.Targets {
		targets[target.TargetID] = target
	}
	observed := map[string]projections.PQCPilotTraffic{}
	waiting := 0
	for _, result := range wave.Results {
		if result.Outcome != string(compatlab.OutcomeNegotiated) {
			continue
		}
		target, ok := targets[result.TargetID]
		if !ok {
			continue
		}
		h, ok := pilotTrafficEvidence(target, result.ObservedAt, handshakes)
		if !ok {
			waiting++
			continue
		}
		lastSeen := h.LastSeen
		observed[result.TargetID] = projections.PQCPilotTraffic{FindingID: h.FindingID, Server: h.Server,
			TLSVersion: h.TLSVersion, Group: h.Group, PQHybrid: h.PQHybrid, LastSeen: &lastSeen}
	}
	if waiting > 0 && (wave.AssessedAt == nil || now.Sub(*wave.AssessedAt) < orchestrator.PQCPilotTrafficWindow(pilot)) {
		return nil
	}
	return s.orch.RecordPQCPilotTraffic(ctx, tenantID, pilot.ID, wave.Index, observed, now)
}

// pilotTrafficEvidence finds new connections at a pilot target after its
// probe: on TLS 1.2 they must present the pilot's leaf; on TLS 1.3 the
// certificate is encrypted, so the probe already proved the leaf served.
func pilotTrafficEvidence(target store.PQCPilotTarget, probedAt time.Time, handshakes []observedHandshake) (observedHandshake, bool) {
	binding := pilotTargetBinding(target)
	leaf := strings.ToLower(target.Fingerprint)
	for _, h := range handshakes {
		if !h.at(binding) || h.LastSeen.Before(probedAt) {
			continue
		}
		if h.Visible && h.Fingerprint != leaf {
			continue
		}
		return h, true
	}
	return observedHandshake{}, false
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
	// TLSVersion, Group and PQHybrid say what the real clients negotiated
	// (kept as a pilot's traffic evidence, X3-L5).
	TLSVersion string
	Group      string
	PQHybrid   bool
}

// pilotTargetBinding is where an observer sees a pilot target: its address,
// its observed addresses and its server name (X3-L5).
func pilotTargetBinding(target store.PQCPilotTarget) migration.MemberBinding {
	return migration.MemberBinding{VerifyAddress: target.Address, VerifyServerName: target.ServerName,
		ObservedAddresses: target.ObservedAddresses}
}

// trafficWatch is the endpoints one tenant's pass watches (X3-L4): every
// address of every awaiting binding, and each binding's server name on the
// port of each of its addresses.
type trafficWatch struct {
	addresses map[string]bool
	namePorts map[string]bool
}

func newTrafficWatch() *trafficWatch {
	return &trafficWatch{addresses: map[string]bool{}, namePorts: map[string]bool{}}
}

func (w *trafficWatch) add(binding migration.MemberBinding) {
	for _, address := range append([]string{binding.VerifyAddress}, binding.ObservedAddresses...) {
		if address == "" {
			continue
		}
		w.addresses[address] = true
		if _, port, err := net.SplitHostPort(address); err == nil && binding.VerifyServerName != "" {
			w.namePorts[binding.VerifyServerName+"\x00"+port] = true
		}
	}
}

// watches reports whether h was observed at a watched endpoint: exactly when
// h.at holds for one of the bindings the watch was given.
func (w *trafficWatch) watches(h observedHandshake) bool {
	if w.addresses[h.Server] {
		return true
	}
	_, port, err := net.SplitHostPort(h.Server)
	return err == nil && h.ServerName != "" && w.namePorts[h.ServerName+"\x00"+port]
}

// observedHandshakes reads every one of the tenant's observer TLS findings, in
// ID order, a page at a time, and keeps those the watch watches (X3-L4): the
// pass holds the findings at the endpoints it decides, never the tenant's
// whole list, and no count of other findings hides a deciding one.
func (s *Server) observedHandshakes(ctx context.Context, tenantID string, watch *trafficWatch) ([]observedHandshake, error) {
	var out []observedHandshake
	after := store.ZeroUUID
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		page, err := s.store.ListDiscoveryFindingsFiltered(ctx, tenantID, store.DiscoveryFindingFilter{Kind: "tls_handshake"}, after, observedHandshakePage)
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
			h := observedHandshake{
				FindingID: f.ID, TriageStatus: f.TriageStatus, Server: meta["server"], ServerName: meta["server_name"],
				Fingerprint: strings.ToLower(f.Fingerprint), Visible: meta["certificate_visible"] == "true", LastSeen: lastSeen,
				TLSVersion: meta["tls_version"], Group: meta["group"], PQHybrid: meta["pq_hybrid"] == "true",
			}
			if watch.watches(h) {
				out = append(out, h)
			}
		}
		if len(page) < observedHandshakePage {
			return out, nil
		}
		after = page[len(page)-1].ID
	}
}

// at reports whether the handshake was observed at the member's endpoint:
// its verify address or one of its observed addresses (X3-L2: the backends
// behind NAT or a load balancer), or its server name on the port of one of
// them.
func (h observedHandshake) at(binding migration.MemberBinding) bool {
	_, observedPort, observedErr := net.SplitHostPort(h.Server)
	for _, address := range append([]string{binding.VerifyAddress}, binding.ObservedAddresses...) {
		if address == "" {
			continue
		}
		if h.Server == address {
			return true
		}
		_, port, err := net.SplitHostPort(address)
		if err == nil && observedErr == nil && binding.VerifyServerName != "" && h.ServerName == binding.VerifyServerName && observedPort == port {
			return true
		}
	}
	return false
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
