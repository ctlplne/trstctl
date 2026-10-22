// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/pqc/compatlab"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// PQC pilot waves with canary halt (A28/A29, epic M1/H2).
//
// A pilot rolls a post-quantum leaf's handshake proof out in ordered waves: a
// small canary first, then progressively broader waves. Each wave is one
// relay endpoint-verification sweep over that wave's targets, dispatched
// through the durable outbox in the same tenant transaction as the immutable
// event that records it. When the relay's signed report lands, the wave's
// transcripts are classified (negotiated, rejected, unreachable), the
// compat-lab verdict is taken over everything accumulated THROUGH that wave,
// and the pilot halts the instant that verdict says to — later waves are never
// dispatched. A completed or halted pilot's evidence becomes a readiness
// report signed inside the isolated signer, so the report says what it says
// over exactly the evidence that produced it.

// PQCPilotStartRequest is the reviewed plan.
type PQCPilotStartRequest struct {
	ID             string
	Name           string
	AuthorityID    string
	RequestedBy    string
	TimeoutSeconds int
	Waves          []PQCPilotWaveRequest
}

type PQCPilotWaveRequest struct {
	Name    string
	Targets []PQCPilotTargetRequest
}

type PQCPilotTargetRequest struct {
	TargetID    string
	Address     string
	ServerName  string
	Connector   string
	Fingerprint string
}

// PQCPilotReportSigner signs a compat-lab report inside the isolated signer
// and returns the signed report's canonical JSON. nil means pilots complete
// without a signed report and say so.
type PQCPilotReportSigner func(ctx context.Context, report compatlab.Report) (string, error)

// WithPQCPilotReportSigner wires the signer-side readiness-report key.
func WithPQCPilotReportSigner(sign PQCPilotReportSigner) OrchestratorOption {
	return func(o *Orchestrator) { o.pqcPilotReportSigner = sign }
}

var (
	ErrPQCPilotInvalid  = errors.New("orchestrator: pqc pilot request is invalid")
	ErrPQCPilotFinished = errors.New("orchestrator: pqc pilot has already finished")
)

const (
	pqcPilotMaxWaves          = 16
	pqcPilotMaxTargetsPerWave = 64
	pqcPilotMaxTimeoutSeconds = 120
)

func pqcPilotWaveKey(pilotID string, wave int) string {
	return fmt.Sprintf("pqc-pilot:%s:wave:%d", pilotID, wave)
}

func normalizePQCPilot(in PQCPilotStartRequest) (projections.PQCPilotStarted, error) {
	id := strings.TrimSpace(in.ID)
	if id == "" {
		id = uuid.NewString()
	} else if _, err := uuid.Parse(id); err != nil {
		return projections.PQCPilotStarted{}, fmt.Errorf("%w: id must be a UUID", ErrPQCPilotInvalid)
	}
	name := trimBounded(in.Name, 160)
	if name == "" {
		return projections.PQCPilotStarted{}, fmt.Errorf("%w: name is required", ErrPQCPilotInvalid)
	}
	if strings.TrimSpace(in.AuthorityID) == "" {
		// The signed readiness report is a statement about one issuing
		// authority's post-quantum leaf; a pilot without one would report on nothing.
		return projections.PQCPilotStarted{}, fmt.Errorf("%w: authority_id names the issuing authority whose leaf the pilot proves", ErrPQCPilotInvalid)
	}
	if in.TimeoutSeconds < 0 || in.TimeoutSeconds > pqcPilotMaxTimeoutSeconds {
		return projections.PQCPilotStarted{}, fmt.Errorf("%w: timeout_seconds must be between 0 and %d", ErrPQCPilotInvalid, pqcPilotMaxTimeoutSeconds)
	}
	if len(in.Waves) == 0 || len(in.Waves) > pqcPilotMaxWaves {
		return projections.PQCPilotStarted{}, fmt.Errorf("%w: a pilot needs between 1 and %d waves; the first is the canary", ErrPQCPilotInvalid, pqcPilotMaxWaves)
	}
	out := projections.PQCPilotStarted{ID: id, Name: name, AuthorityID: trimBounded(in.AuthorityID, 120),
		RequestedBy: trimBounded(in.RequestedBy, 180), TimeoutSeconds: in.TimeoutSeconds}
	seen := map[string]bool{}
	for i, wave := range in.Waves {
		waveName := trimBounded(wave.Name, 120)
		if waveName == "" {
			return projections.PQCPilotStarted{}, fmt.Errorf("%w: wave %d needs a name", ErrPQCPilotInvalid, i+1)
		}
		if len(wave.Targets) == 0 || len(wave.Targets) > pqcPilotMaxTargetsPerWave {
			return projections.PQCPilotStarted{}, fmt.Errorf("%w: wave %q needs between 1 and %d targets", ErrPQCPilotInvalid, waveName, pqcPilotMaxTargetsPerWave)
		}
		pw := projections.PQCPilotWave{Name: waveName}
		for _, target := range wave.Targets {
			t := projections.PQCPilotTarget{
				TargetID: trimBounded(target.TargetID, 160), Address: trimBounded(target.Address, 260),
				ServerName: trimBounded(target.ServerName, 253), Connector: trimBounded(target.Connector, 40),
				Fingerprint: strings.ToLower(strings.ReplaceAll(strings.TrimSpace(target.Fingerprint), ":", "")),
			}
			if t.TargetID == "" || t.Address == "" || len(t.Fingerprint) != 64 {
				return projections.PQCPilotStarted{}, fmt.Errorf("%w: every target needs target_id, address and the leaf's SHA-256 fingerprint", ErrPQCPilotInvalid)
			}
			if seen[t.TargetID] {
				return projections.PQCPilotStarted{}, fmt.Errorf("%w: target %q appears in more than one wave", ErrPQCPilotInvalid, t.TargetID)
			}
			seen[t.TargetID] = true
			pw.Targets = append(pw.Targets, t)
		}
		out.Waves = append(out.Waves, pw)
	}
	return out, nil
}

func (o *Orchestrator) appendPQCPilotEventTx(ctx context.Context, tx pgx.Tx, tenantID, eventType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ev, err := o.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	return o.proj.ApplyTx(ctx, tx, ev)
}

// StartPQCPilot records the plan and dispatches the canary wave.
func (o *Orchestrator) StartPQCPilot(ctx context.Context, tenantID string, in PQCPilotStartRequest) (store.PQCPilot, error) {
	plan, err := normalizePQCPilot(in)
	if err != nil {
		return store.PQCPilot{}, err
	}
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := o.store.LockPQCPilotTx(ctx, tx, tenantID, plan.ID); err != nil {
			return err
		}
		if _, err := o.store.GetPQCPilotTx(ctx, tx, tenantID, plan.ID); err == nil {
			return store.ErrPQCPilotExists
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := o.appendPQCPilotEventTx(ctx, tx, tenantID, projections.EventPQCPilotStarted, plan); err != nil {
			return err
		}
		return o.dispatchPQCPilotWaveTx(ctx, tx, tenantID, plan.ID, 1, plan.Waves[0].Targets, plan.TimeoutSeconds)
	})
	if err != nil {
		return store.PQCPilot{}, err
	}
	return o.store.GetPQCPilot(ctx, tenantID, plan.ID)
}

func (o *Orchestrator) dispatchPQCPilotWaveTx(ctx context.Context, tx pgx.Tx, tenantID, pilotID string, wave int, targets []projections.PQCPilotTarget, timeoutSeconds int) error {
	intent := relay.EndpointVerifyIntent{TimeoutSeconds: timeoutSeconds, Pilot: &relay.EndpointVerifyPilot{PilotID: pilotID, Wave: wave}}
	for _, target := range targets {
		intent.Endpoints = append(intent.Endpoints, relay.EndpointExpectation{
			EndpointID: target.TargetID, Address: target.Address, ServerName: target.ServerName,
			Connector: target.Connector, Fingerprint: target.Fingerprint,
		})
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	key := pqcPilotWaveKey(pilotID, wave)
	outboxID, err := o.outbox.Enqueue(ctx, tx, Entry{TenantID: tenantID, Destination: relay.KindEndpointVerify, IdempotencyKey: key, Payload: payload})
	if err != nil {
		return err
	}
	return o.appendPQCPilotEventTx(ctx, tx, tenantID, projections.EventPQCPilotWaveDispatched, projections.PQCPilotWaveDispatched{
		PilotID: pilotID, Wave: wave, OutboxID: outboxID, IdempotencyKey: key, DispatchedAt: time.Now().UTC(),
	})
}

// ClassifyPQCPilotTranscript turns one relay transcript into compat-lab
// evidence. Reached with the exact expected leaf is a negotiation; a
// completed TCP connection whose TLS handshake failed, or a listener serving a
// different leaf, is a rejection; a failed dial is unreachable and says
// nothing about the post-quantum leaf.
func ClassifyPQCPilotTranscript(tr transport.ProbeTranscript, expectedFingerprint string) (compatlab.Outcome, string) {
	if tr.Reached {
		if strings.EqualFold(tr.ObservedFingerprint, expectedFingerprint) && tr.Mismatch == "" {
			return compatlab.OutcomeNegotiated, "the client negotiated the post-quantum leaf"
		}
		return compatlab.OutcomeRejected, "the endpoint served a different leaf than the pilot deployed"
	}
	if strings.HasPrefix(tr.Error, "tlsprobe: dial ") || tr.Error == "" {
		return compatlab.OutcomeUnreachable, "the endpoint could not be reached: " + tr.Error
	}
	return compatlab.OutcomeRejected, "the client refused the handshake: " + tr.Error
}

// RecordPQCPilotWave takes a wave's signed relay report, assesses the pilot
// through that wave and either halts it, dispatches the next wave, or
// completes it. A replayed report for an assessed wave changes nothing.
func (o *Orchestrator) RecordPQCPilotWave(ctx context.Context, tenantID, pilotID string, wave int, report relay.EndpointVerifyReport) error {
	var finished *store.PQCPilot
	err := o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := o.store.LockPQCPilotTx(ctx, tx, tenantID, pilotID); err != nil {
			return err
		}
		pilot, err := o.store.GetPQCPilotTx(ctx, tx, tenantID, pilotID)
		if err != nil {
			return err
		}
		if pilot.Status != "running" {
			// A replayed report for a finished pilot changes nothing, except
			// that a report whose signing failed last time is signed now.
			if pilot.SignedReport == "" {
				finished = &pilot
			}
			return nil
		}
		if wave < 1 || wave > len(pilot.Waves) {
			return fmt.Errorf("%w: wave %d is not in the plan", ErrPQCPilotInvalid, wave)
		}
		current := pilot.Waves[wave-1]
		if current.Status == "assessed" {
			return nil
		}
		if current.Status != "probing" {
			return fmt.Errorf("%w: wave %d was never dispatched", ErrPQCPilotInvalid, wave)
		}
		expected := make(map[string]string, len(current.Targets))
		for _, target := range current.Targets {
			expected[target.TargetID] = target.Fingerprint
		}
		now := time.Now().UTC()
		results := make([]projections.PQCPilotResult, 0, len(report.Results))
		for _, res := range report.Results {
			fp, ok := expected[res.EndpointID]
			if !ok {
				continue
			}
			outcome, detail := ClassifyPQCPilotTranscript(res.Transcript, fp)
			observed := time.Unix(res.Transcript.ObservedAtUnix, 0).UTC()
			if res.Transcript.ObservedAtUnix <= 0 {
				observed = now
			}
			results = append(results, projections.PQCPilotResult{
				TargetID: res.EndpointID, Outcome: string(outcome), HandshakeMillis: res.Transcript.HandshakeMillis,
				ChainBytes: res.Transcript.ChainBytes, Detail: detail, EvidenceDigest: res.Transcript.Digest(), ObservedAt: observed,
			})
		}
		cohort := pqcPilotCohort(pilot, wave, results)
		verdict := compatlab.Assess(cohort)
		status := "running"
		haltedAt := ""
		switch {
		case verdict.Halt || (!verdict.Ready && verdict.Rejected == 0 && verdict.NotAttempted == 0 && verdict.Unreachable > 0):
			// A rejection halts outright; an unreachable canary cannot
			// vouch for anything either, and rolling a broader wave on
			// silence is exactly what staging exists to prevent.
			status, haltedAt = "halted", current.Name
		case verdict.Ready && wave == len(pilot.Waves):
			status = "completed"
		case !verdict.Ready:
			status, haltedAt = "halted", current.Name
		}
		if err := o.appendPQCPilotEventTx(ctx, tx, tenantID, projections.EventPQCPilotWaveAssessed, projections.PQCPilotWaveAssessed{
			PilotID: pilotID, Wave: wave, Results: results,
			Verdict: projections.PQCPilotVerdict{Ready: verdict.Ready, Halt: verdict.Halt, Summary: verdict.Summary,
				Negotiated: verdict.Negotiated, Rejected: verdict.Rejected, Unreachable: verdict.Unreachable, NotAttempted: verdict.NotAttempted},
			Status: status, HaltedAtWave: haltedAt, AssessedAt: now,
		}); err != nil {
			return err
		}
		if status == "running" {
			next := pilot.Waves[wave]
			targets := make([]projections.PQCPilotTarget, 0, len(next.Targets))
			for _, t := range next.Targets {
				targets = append(targets, projections.PQCPilotTarget{TargetID: t.TargetID, Address: t.Address,
					ServerName: t.ServerName, Connector: t.Connector, Fingerprint: t.Fingerprint})
			}
			return o.dispatchPQCPilotWaveTx(ctx, tx, tenantID, pilotID, wave+1, targets, pqcPilotTimeout(pilot))
		}
		after, err := o.store.GetPQCPilotTx(ctx, tx, tenantID, pilotID)
		if err != nil {
			return err
		}
		finished = &after
		return nil
	})
	if err != nil || finished == nil {
		return err
	}
	return o.signPQCPilotReport(ctx, tenantID, *finished)
}

// pqcPilotTimeout is not retained on the read model; the plan's timeout only
// bounds the relay handshake, so the package default is used for later waves.
func pqcPilotTimeout(store.PQCPilot) int { return 0 }

// pqcPilotCohort accumulates every wave through the given one: the verdict is
// over everything probed so far, so a canary refusal colors every later wave.
func pqcPilotCohort(pilot store.PQCPilot, through int, latest []projections.PQCPilotResult) compatlab.Cohort {
	cohort := compatlab.Cohort{Name: pilot.Name}
	for i := 0; i < through && i < len(pilot.Waves); i++ {
		w := pilot.Waves[i]
		for _, target := range w.Targets {
			cohort.Targeted = append(cohort.Targeted, target.TargetID)
		}
		if i+1 == through && latest != nil {
			for _, r := range latest {
				cohort.Results = append(cohort.Results, compatlab.Result{ClientID: r.TargetID, Outcome: compatlab.Outcome(r.Outcome),
					HandshakeBytes: r.ChainBytes, LatencyMS: int(r.HandshakeMillis), Detail: r.Detail})
			}
			continue
		}
		for _, r := range w.Results {
			cohort.Results = append(cohort.Results, compatlab.Result{ClientID: r.TargetID, Outcome: compatlab.Outcome(r.Outcome),
				HandshakeBytes: r.ChainBytes, LatencyMS: int(r.HandshakeMillis), Detail: r.Detail})
		}
	}
	return cohort
}

// signPQCPilotReport turns a finished pilot's evidence into the signed
// readiness report (M1). Without a signer the pilot stays finished and the
// read model simply carries no report.
func (o *Orchestrator) signPQCPilotReport(ctx context.Context, tenantID string, pilot store.PQCPilot) error {
	if o.pqcPilotReportSigner == nil || pilot.SignedReport != "" {
		return nil
	}
	cohort := pqcPilotCohort(pilot, len(pilot.Waves), nil)
	// Waves that never ran are absent from the results and therefore counted
	// as not attempted by the verdict, which is what a halt means.
	report, err := compatlab.BuildReport(tenantID, pilot.AuthorityID, cohort, time.Now().UTC().Unix())
	if err != nil {
		return err
	}
	signed, err := o.pqcPilotReportSigner(ctx, report)
	if err != nil {
		return err
	}
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := o.store.LockPQCPilotTx(ctx, tx, tenantID, pilot.ID); err != nil {
			return err
		}
		current, err := o.store.GetPQCPilotTx(ctx, tx, tenantID, pilot.ID)
		if err != nil {
			return err
		}
		if current.SignedReport != "" {
			return nil
		}
		return o.appendPQCPilotEventTx(ctx, tx, tenantID, projections.EventPQCPilotReportSigned, projections.PQCPilotReportSigned{
			PilotID: pilot.ID, SignedReportJSON: signed, SignedAt: time.Now().UTC(),
		})
	})
}
