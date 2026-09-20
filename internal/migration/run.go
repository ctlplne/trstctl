// SPDX-License-Identifier: BUSL-1.1

package migration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	maxExecutableAnchorBytes = 64 << 10
	maxExecutableConfigBytes = 64 << 10
	maxExecutableRunBytes    = 16 << 20
)

// RunStatus is the durable lifecycle of an executable migration plan.
type RunStatus string

const (
	RunPlanned     RunStatus = "planned"
	RunRunning     RunStatus = "running"
	RunPaused      RunStatus = "paused"
	RunHalted      RunStatus = "halted"
	RunRollingBack RunStatus = "rolling_back"
	RunRolledBack  RunStatus = "rolled_back"
	RunComplete    RunStatus = "complete"
)

// Verdict is a signed member observation. Empty means nobody has checked.
type Verdict string

const (
	VerdictVerified Verdict = "verified"
	VerdictFailed   Verdict = "failed"
)

// ObservationStage identifies which safety gate a receipt licenses.
type ObservationStage string

const (
	StageTrust     ObservationStage = "trust"
	StageSuccessor ObservationStage = "successor"
	// StageRevocation is an incident-only control-plane receipt. It proves the
	// exact predecessor certificate was revoked after the signed live listener
	// gate. Ordinary CA migrations do not revoke predecessors and never enter it.
	StageRevocation        ObservationStage = "revocation"
	StageRollbackSuccessor ObservationStage = "rollback_successor"
	StageRollbackTrust     ObservationStage = "rollback_trust"
)

// ActionKind is work the command side must publish through an outbox.
type ActionKind string

const (
	ActionDistributeTrust   ActionKind = "distribute_trust"
	ActionIssueSuccessor    ActionKind = "issue_successor"
	ActionRevokePredecessor ActionKind = "revoke_predecessor"
	ActionRollbackSuccessor ActionKind = "rollback_successor"
	ActionRemoveTrust       ActionKind = "remove_trust"
)

// IncidentMode distinguishes a real compromise response from an isolated
// rehearsal. The engine treats game-day as a safety boundary, not a display
// label: every frozen member binding must name a non-production environment.
type IncidentMode string

const (
	IncidentModeLive    IncidentMode = "live"
	IncidentModeGameDay IncidentMode = "game_day"
)

// IncidentPlan is the immutable H3 authority attached to an H2 run. It records
// the exact compromised and replacement authorities, the authoritative H1
// TRUSTS scope, and the complete affected identity set before any estate intent
// is published. Candidate trust relationships are deliberately absent: they
// are operator guidance, never automation authority.
type IncidentPlan struct {
	Mode                   IncidentMode `json:"mode"`
	CompromisedIssuerID    string       `json:"compromised_issuer_id"`
	ReplacementAuthorityID string       `json:"replacement_authority_id"`
	ExactTrustStoreIDs     []string     `json:"exact_trust_store_ids"`
	ExactTrustHosts        []string     `json:"exact_trust_hosts"`
	AffectedIdentityIDs    []string     `json:"affected_identity_ids"`
}

// Action names one exact member effect. It contains no credential material.
type Action struct {
	Kind       ActionKind `json:"kind"`
	WaveID     string     `json:"wave_id"`
	IdentityID string     `json:"identity_id"`
}

// Observation is the semantic part of a lease-bound signed agent receipt.
// Transport authority is checked before this value reaches the engine.
type Observation struct {
	WaveID               string           `json:"wave_id"`
	IdentityID           string           `json:"identity_id"`
	Stage                ObservationStage `json:"stage"`
	Verdict              Verdict          `json:"verdict"`
	SuccessorFingerprint string           `json:"successor_fingerprint,omitempty"`
}

// RecordSuccessorIssued binds the one idempotently minted successor to its run
// before the CSR response leaves the control plane. It is not a live verdict:
// only the later signed listener receipt may advance the gate. Keeping these
// facts separate lets a failed deploy still name the exact inventory row its
// automatic inverse must supersede.
func RecordSuccessorIssued(in Run, waveID, identityID, fingerprint string) (Run, error) {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return in, errors.New("migration: issued successor fingerprint is required")
	}
	out := cloneRun(in)
	waveIndex, memberIndex := memberIndex(out, waveID, identityID)
	if waveIndex < 0 || !out.Waves[waveIndex].Started || out.Waves[waveIndex].Phase != PhaseVerifyingLive {
		return in, errors.New("migration: issued successor does not name the active published leaf gate")
	}
	if out.Status != RunRunning && out.Status != RunPaused && out.Status != RunRollingBack &&
		(out.Status != RunHalted || out.RollbackWaveID == "") {
		return in, fmt.Errorf("migration: issued successor is not licensed in run %s", out.Status)
	}
	member := &out.Waves[waveIndex].Members[memberIndex]
	if member.Binding.SuccessorFingerprint != "" && member.Binding.SuccessorFingerprint != fingerprint {
		return in, errors.New("migration: issued successor fingerprint conflicts with retained issuance")
	}
	member.Binding.SuccessorFingerprint = fingerprint
	return out, nil
}

// MemberBinding is the immutable authority for every estate effect a run may
// publish. It is captured when the operator starts the run. Recovery therefore
// never re-reads a deployment target that may have been edited after review.
// AnchorPEM and certificate metadata are public; private-key material has no
// field in this contract.
type MemberBinding struct {
	IssuingAuthorityID       string          `json:"issuing_authority_id"`
	TargetID                 string          `json:"target_id"`
	TargetRevision           string          `json:"target_revision"`
	Connector                string          `json:"connector"`
	Target                   string          `json:"target"`
	TargetConfig             json.RawMessage `json:"target_config"`
	RequiredAgentID          string          `json:"required_agent_id"`
	TrustAnchorPath          string          `json:"trust_anchor_path"`
	TrustAnchorPEM           []byte          `json:"trust_anchor_pem"`
	TrustAnchorFingerprint   string          `json:"trust_anchor_fingerprint"`
	VerifyAddress            string          `json:"verify_address"`
	VerifyServerName         string          `json:"verify_server_name,omitempty"`
	SubjectCommonName        string          `json:"subject_common_name"`
	SubjectDNSNames          []string        `json:"subject_dns_names"`
	PredecessorCertificateID string          `json:"predecessor_certificate_id"`
	PredecessorFingerprint   string          `json:"predecessor_fingerprint"`
	// PredecessorCAID is the exact responder/revocation authority. Incident
	// response requires it; a generic migration may leave it empty.
	PredecessorCAID string `json:"predecessor_ca_id,omitempty"`
	// Environment is frozen from the owner and target classification. Game-day
	// validation accepts only an explicit non-production value.
	Environment          string `json:"environment,omitempty"`
	SuccessorFingerprint string `json:"successor_fingerprint,omitempty"`
}

// RunMember carries gate state beside the immutable command authority that
// produced it. Signed receipts remain in the job/event ledgers and are joined
// by run, wave, member, and stage.
type RunMember struct {
	IdentityID               string        `json:"identity_id"`
	Binding                  MemberBinding `json:"binding"`
	TrustVerdict             Verdict       `json:"trust_verdict,omitempty"`
	SuccessorVerdict         Verdict       `json:"successor_verdict,omitempty"`
	RevocationVerdict        Verdict       `json:"revocation_verdict,omitempty"`
	RollbackSuccessorVerdict Verdict       `json:"rollback_successor_verdict,omitempty"`
	RollbackTrustVerdict     Verdict       `json:"rollback_trust_verdict,omitempty"`
}

type RunWave struct {
	ID         string      `json:"id"`
	Ordinal    int         `json:"ordinal"`
	Members    []RunMember `json:"members"`
	Phase      Phase       `json:"phase"`
	Started    bool        `json:"started"`
	HaltReason string      `json:"halt_reason,omitempty"`
}

// Run is the event-projected executable aggregate. RollbackWaveID and
// RollbackStage are durable cursors, so a restart resumes the same newest-first
// inverse rather than recalculating from mutable estate state.
type Run struct {
	ID              string           `json:"id"`
	PlanID          string           `json:"plan_id,omitempty"`
	Incident        *IncidentPlan    `json:"incident,omitempty"`
	Status          RunStatus        `json:"status"`
	Waves           []RunWave        `json:"waves"`
	HaltReason      string           `json:"halt_reason,omitempty"`
	RollbackWaveID  string           `json:"rollback_wave_id,omitempty"`
	RollbackStage   ObservationStage `json:"rollback_stage,omitempty"`
	RollbackAttempt int              `json:"rollback_attempt,omitempty"`
	PauseReason     string           `json:"pause_reason,omitempty"`
}

// StartRun validates and starts only the lowest-ordinal cohort.
func StartRun(in Run) (Run, []Action, error) {
	if err := validateRun(in); err != nil {
		return in, nil, err
	}
	out := cloneRun(in)
	sort.SliceStable(out.Waves, func(i, j int) bool { return out.Waves[i].Ordinal < out.Waves[j].Ordinal })
	out.Status = RunRunning
	out.HaltReason = ""
	out.PauseReason = ""
	out.RollbackWaveID = ""
	out.RollbackStage = ""
	out.RollbackAttempt = 0
	for i := range out.Waves {
		out.Waves[i].Phase = PhasePlanned
		out.Waves[i].Started = false
		out.Waves[i].HaltReason = ""
	}
	out.Waves[0].Phase = PhaseVerifyingTrust
	out.Waves[0].Started = true
	return out, actionsFor(out.Waves[0], ActionDistributeTrust), nil
}

// Observe applies one already-authorized signed fact and returns newly licensed
// work. Exact duplicates are no-ops; semantic drift is refused.
func Observe(in Run, obs Observation) (Run, []Action, error) {
	out := cloneRun(in)
	waveIndex, memberIndex := memberIndex(out, obs.WaveID, obs.IdentityID)
	if waveIndex < 0 {
		return in, nil, errors.New("migration: observation does not name a run member")
	}
	if obs.Verdict != VerdictVerified && obs.Verdict != VerdictFailed {
		return in, nil, fmt.Errorf("migration: unsupported observation verdict %q", obs.Verdict)
	}
	if obs.Stage == StageRevocation && obs.Verdict != VerdictVerified {
		return in, nil, errors.New("migration: incident revocation accepts only a verified control-plane receipt")
	}
	member := &out.Waves[waveIndex].Members[memberIndex]
	verdict := verdictForStage(member, obs.Stage)
	if verdict == nil {
		return in, nil, fmt.Errorf("migration: unsupported observation stage %q", obs.Stage)
	}
	if *verdict != "" {
		if *verdict == obs.Verdict {
			if obs.Stage == StageSuccessor && obs.Verdict == VerdictVerified &&
				strings.TrimSpace(obs.SuccessorFingerprint) != "" &&
				member.Binding.SuccessorFingerprint != "" &&
				member.Binding.SuccessorFingerprint != strings.TrimSpace(obs.SuccessorFingerprint) {
				return in, nil, errors.New("migration: successor fingerprint conflicts with retained evidence")
			}
			return out, nil, nil
		}
		return in, nil, errors.New("migration: observation conflicts with the retained signed verdict")
	}
	// Every member effect in a gate is published together. Another member can
	// fail while this job is still leased. Its later signed receipt must close
	// cleanly so the inverse queued in the same effect lane can run; it must not
	// restart forward progress. Retaining a late successor fingerprint also
	// gives the rollback projection the most exact inventory identity available.
	if (out.Status == RunRollingBack || (out.Status == RunHalted && out.RollbackWaveID != "")) &&
		(obs.Stage == StageTrust || obs.Stage == StageSuccessor) && out.Waves[waveIndex].Started {
		*verdict = obs.Verdict
		if obs.Stage == StageSuccessor && strings.TrimSpace(obs.SuccessorFingerprint) != "" {
			member.Binding.SuccessorFingerprint = strings.TrimSpace(obs.SuccessorFingerprint)
		}
		return out, nil, nil
	}
	if err := requireObservationPhase(out, waveIndex, obs.Stage); err != nil {
		return in, nil, err
	}
	*verdict = obs.Verdict
	if obs.Stage == StageSuccessor && obs.Verdict == VerdictVerified {
		fingerprint := strings.TrimSpace(obs.SuccessorFingerprint)
		if member.Binding.SuccessorFingerprint != "" && fingerprint != "" &&
			member.Binding.SuccessorFingerprint != fingerprint {
			return in, nil, errors.New("migration: successor fingerprint conflicts with retained evidence")
		}
		if fingerprint != "" {
			member.Binding.SuccessorFingerprint = fingerprint
		}
	}
	wave := &out.Waves[waveIndex]
	if obs.Verdict == VerdictFailed {
		reason := fmt.Sprintf("%s verification failed for member %s in wave %s", obs.Stage, obs.IdentityID, obs.WaveID)
		if out.Status == RunRollingBack {
			out.Status = RunHalted
			out.HaltReason = "rollback halted: " + reason
			wave.HaltReason = out.HaltReason
			return out, nil, nil
		}
		out.HaltReason = reason
		wave.HaltReason = reason
		return beginRollback(out, reason)
	}
	if !allVerified(*wave, obs.Stage) {
		return out, nil, nil
	}
	// A pause cannot recall a job already leased to an agent. Retain its signed
	// fact, but publish no next-stage work until ResumeRun explicitly releases
	// this complete gate.
	if out.Status == RunPaused {
		return out, nil, nil
	}

	switch obs.Stage {
	case StageTrust:
		wave.Phase = PhaseVerifyingLive
		return out, actionsFor(*wave, ActionIssueSuccessor), nil
	case StageSuccessor:
		if out.Incident != nil {
			wave.Phase = PhaseRevokingPredecessor
			return out, actionsFor(*wave, ActionRevokePredecessor), nil
		}
		wave.Phase = PhaseComplete
		if next := nextPlannedWave(out, waveIndex); next >= 0 {
			out.Waves[next].Phase = PhaseVerifyingTrust
			out.Waves[next].Started = true
			return out, actionsFor(out.Waves[next], ActionDistributeTrust), nil
		}
		out.Status = RunComplete
		return out, nil, nil
	case StageRevocation:
		wave.Phase = PhaseComplete
		if next := nextPlannedWave(out, waveIndex); next >= 0 {
			out.Waves[next].Phase = PhaseVerifyingTrust
			out.Waves[next].Started = true
			return out, actionsFor(out.Waves[next], ActionDistributeTrust), nil
		}
		out.Status = RunComplete
		return out, nil, nil
	case StageRollbackSuccessor:
		out.RollbackStage = StageRollbackTrust
		return out, missingActions(*wave, StageRollbackTrust, ActionRemoveTrust), nil
	case StageRollbackTrust:
		wave.Phase = PhaseRolledBack
		if next := nextRollbackWave(out, waveIndex); next >= 0 {
			out.RollbackWaveID = out.Waves[next].ID
			out.RollbackStage = StageRollbackSuccessor
			return out, actionsFor(out.Waves[next], ActionRollbackSuccessor), nil
		}
		out.Status = RunRolledBack
		out.RollbackWaveID = ""
		out.RollbackStage = ""
		return out, nil, nil
	default:
		return in, nil, fmt.Errorf("migration: unsupported observation stage %q", obs.Stage)
	}
}

// PauseRun holds advancement after work already leased to an agent. Signed
// receipts may still arrive, but the receiver refuses to advance the aggregate
// until ResumeRun is called; no new cohort or stage is published meanwhile.
func PauseRun(in Run, reason string) (Run, error) {
	if in.Status != RunRunning {
		return in, fmt.Errorf("migration: run in %q cannot be paused", in.Status)
	}
	out := cloneRun(in)
	out.Status = RunPaused
	out.PauseReason = strings.TrimSpace(reason)
	return out, nil
}

// ResumeRun releases an operator pause. Current-stage receipts are retained;
// ReconcileActions returns the exact work still required to complete the gate.
func ResumeRun(in Run) (Run, []Action, error) {
	if in.Status != RunPaused {
		return in, nil, fmt.Errorf("migration: run in %q cannot be resumed", in.Status)
	}
	out := cloneRun(in)
	out.Status = RunRunning
	out.PauseReason = ""
	for waveIndex := range out.Waves {
		wave := &out.Waves[waveIndex]
		switch {
		case wave.Phase == PhaseVerifyingTrust && allVerified(*wave, StageTrust):
			wave.Phase = PhaseVerifyingLive
			return out, actionsFor(*wave, ActionIssueSuccessor), nil
		case wave.Phase == PhaseVerifyingLive && allVerified(*wave, StageSuccessor):
			if out.Incident != nil {
				wave.Phase = PhaseRevokingPredecessor
				return out, actionsFor(*wave, ActionRevokePredecessor), nil
			}
			wave.Phase = PhaseComplete
			if next := nextPlannedWave(out, waveIndex); next >= 0 {
				out.Waves[next].Phase = PhaseVerifyingTrust
				out.Waves[next].Started = true
				return out, actionsFor(out.Waves[next], ActionDistributeTrust), nil
			}
			out.Status = RunComplete
			return out, nil, nil
		}
	}
	return out, ReconcileActions(out), nil
}

// ReconcileActions reconstructs only unfinished work for the aggregate's
// current durable cursor. Outbox idempotency makes republishing safe.
func ReconcileActions(run Run) []Action {
	if run.Status == RunPaused || run.Status == RunHalted || run.Status == RunComplete || run.Status == RunRolledBack {
		return nil
	}
	if run.Status == RunRollingBack {
		for _, wave := range run.Waves {
			if wave.ID != run.RollbackWaveID {
				continue
			}
			kind := ActionRollbackSuccessor
			if run.RollbackStage == StageRollbackTrust {
				kind = ActionRemoveTrust
			}
			return missingActions(wave, run.RollbackStage, kind)
		}
		return nil
	}
	for _, wave := range run.Waves {
		switch wave.Phase {
		case PhaseVerifyingTrust:
			return missingActions(wave, StageTrust, ActionDistributeTrust)
		case PhaseVerifyingLive:
			return missingActions(wave, StageSuccessor, ActionIssueSuccessor)
		case PhaseRevokingPredecessor:
			return missingActions(wave, StageRevocation, ActionRevokePredecessor)
		}
	}
	return nil
}

// StartRollback begins with the highest-ordinal wave whose successor may be
// live. Trust-only or never-started cohorts need no leaf inverse.
func StartRollback(in Run) (Run, []Action, error) {
	if in.Status != RunHalted && in.Status != RunComplete && in.Status != RunRunning && in.Status != RunPaused {
		return in, nil, fmt.Errorf("migration: run in %q cannot start rollback", in.Status)
	}
	out := cloneRun(in)
	if out.Incident != nil {
		for _, wave := range out.Waves {
			if wave.Phase == PhaseRevokingPredecessor || hasVerified(wave, StageRevocation) {
				return in, nil, errors.New("migration: incident predecessor revocation is irreversible; rollback must start before that gate")
			}
		}
	}
	if out.Status == RunHalted && out.RollbackWaveID != "" {
		return retryRollback(out)
	}
	return beginRollback(out, out.HaltReason)
}

func retryRollback(out Run) (Run, []Action, error) {
	for wi := range out.Waves {
		if out.Waves[wi].ID != out.RollbackWaveID {
			continue
		}
		for mi := range out.Waves[wi].Members {
			verdict := verdictForStage(&out.Waves[wi].Members[mi], out.RollbackStage)
			if verdict != nil && *verdict == VerdictFailed {
				*verdict = ""
			}
		}
		out.Status = RunRollingBack
		out.RollbackAttempt++
		return out, ReconcileActions(out), nil
	}
	return out, nil, errors.New("migration: halted rollback cursor names no run wave")
}

func beginRollback(out Run, reason string) (Run, []Action, error) {
	index := newestStartedWave(out)
	if index < 0 {
		out.Status = RunRolledBack
		return out, nil, nil
	}
	out.Status = RunRollingBack
	out.HaltReason = strings.TrimSpace(reason)
	out.PauseReason = ""
	out.RollbackAttempt++
	out.RollbackWaveID = out.Waves[index].ID
	if successorWorkWasPublished(out.Waves[index]) {
		out.RollbackStage = StageRollbackSuccessor
		return out, missingActions(out.Waves[index], StageRollbackSuccessor, ActionRollbackSuccessor), nil
	}
	out.RollbackStage = StageRollbackTrust
	return out, missingActions(out.Waves[index], StageRollbackTrust, ActionRemoveTrust), nil
}

func validateRun(run Run) error {
	if strings.TrimSpace(run.ID) == "" || len(run.Waves) == 0 || len(run.Waves) > 100 {
		return errors.New("migration: run id and at least one wave are required")
	}
	ordinals := map[int]bool{}
	members := map[string]bool{}
	for _, wave := range run.Waves {
		if strings.TrimSpace(wave.ID) == "" || wave.Ordinal <= 0 || len(wave.Members) == 0 {
			return errors.New("migration: every wave needs an id, positive ordinal, and members")
		}
		if ordinals[wave.Ordinal] {
			return errors.New("migration: wave ordinals must be unique")
		}
		ordinals[wave.Ordinal] = true
		for _, member := range wave.Members {
			id := strings.TrimSpace(member.IdentityID)
			if id == "" || members[id] {
				return errors.New("migration: every identity must appear exactly once")
			}
			members[id] = true
			if len(members) > 10000 {
				return errors.New("migration: run exceeds the 10000-member bound")
			}
		}
	}
	if err := validateIncidentPlan(run, members); err != nil {
		return err
	}
	return nil
}

func validateIncidentPlan(run Run, members map[string]bool) error {
	if run.Incident == nil {
		return nil
	}
	p := run.Incident
	if p.Mode != IncidentModeLive && p.Mode != IncidentModeGameDay {
		return fmt.Errorf("migration: incident mode %q is unsupported", p.Mode)
	}
	if strings.TrimSpace(p.CompromisedIssuerID) == "" || strings.TrimSpace(p.ReplacementAuthorityID) == "" ||
		len(p.ExactTrustStoreIDs) == 0 || len(p.ExactTrustHosts) == 0 {
		return errors.New("migration: incident plan requires exact authorities and authoritative H1 trust scope")
	}
	affected := map[string]bool{}
	for _, id := range p.AffectedIdentityIDs {
		id = strings.TrimSpace(id)
		if id == "" || affected[id] {
			return errors.New("migration: incident affected identities must be non-empty and unique")
		}
		affected[id] = true
	}
	if len(affected) != len(members) {
		return errors.New("migration: incident cohorts must exactly cover the frozen affected identity set")
	}
	for id := range members {
		if !affected[id] {
			return errors.New("migration: incident cohort contains an identity outside its frozen scope")
		}
	}
	return nil
}

// ValidateRun checks aggregate shape without advancing it.
func ValidateRun(run Run) error { return validateRun(run) }

// ValidateExecutableRun additionally checks the immutable estate authority
// required to turn every action into one exact-agent outbox command.
func ValidateExecutableRun(run Run) error {
	if err := validateRun(run); err != nil {
		return err
	}
	switch run.Status {
	case RunRunning, RunPaused, RunHalted, RunRollingBack, RunRolledBack, RunComplete:
	default:
		return fmt.Errorf("migration: executable run has unsupported status %q", run.Status)
	}
	targets := map[string]bool{}
	type trustTarget struct{ agentID, path string }
	trustWaves := map[trustTarget]string{}
	started := 0
	var authorityID, anchorFingerprint string
	var anchorPEM []byte
	for _, wave := range run.Waves {
		if _, ok := phaseOrder[wave.Phase]; !ok {
			return fmt.Errorf("migration: wave %s has unsupported phase %q", wave.ID, wave.Phase)
		}
		if wave.Started {
			started++
		} else if wave.Phase != PhasePlanned {
			return fmt.Errorf("migration: unstarted wave %s cannot have phase %q", wave.ID, wave.Phase)
		}
		for _, member := range wave.Members {
			b := member.Binding
			if strings.TrimSpace(b.IssuingAuthorityID) == "" || strings.TrimSpace(b.TargetID) == "" || strings.TrimSpace(b.TargetRevision) == "" ||
				strings.TrimSpace(b.Connector) == "" || strings.TrimSpace(b.Target) == "" ||
				strings.TrimSpace(b.RequiredAgentID) == "" || strings.TrimSpace(b.TrustAnchorPath) == "" ||
				len(b.TrustAnchorPEM) == 0 || strings.TrimSpace(b.TrustAnchorFingerprint) == "" ||
				strings.TrimSpace(b.VerifyAddress) == "" || strings.TrimSpace(b.SubjectCommonName) == "" ||
				len(b.SubjectDNSNames) == 0 || strings.TrimSpace(b.PredecessorCertificateID) == "" ||
				strings.TrimSpace(b.PredecessorFingerprint) == "" || len(b.TargetConfig) == 0 {
				return fmt.Errorf("migration: member %s has incomplete immutable execution authority", member.IdentityID)
			}
			if len(b.TrustAnchorPEM) > maxExecutableAnchorBytes || len(b.TargetConfig) > maxExecutableConfigBytes {
				return fmt.Errorf("migration: member %s exceeds a bounded public anchor or target configuration", member.IdentityID)
			}
			if authorityID == "" {
				authorityID, anchorFingerprint = b.IssuingAuthorityID, b.TrustAnchorFingerprint
				anchorPEM = b.TrustAnchorPEM
			} else if b.IssuingAuthorityID != authorityID || b.TrustAnchorFingerprint != anchorFingerprint ||
				!bytes.Equal(b.TrustAnchorPEM, anchorPEM) {
				return errors.New("migration: every member must retain the same reviewed CA authority and public anchor")
			}
			if run.Incident != nil {
				if strings.TrimSpace(b.PredecessorCAID) == "" {
					return fmt.Errorf("migration: incident member %s has no exact predecessor revocation authority", member.IdentityID)
				}
				if b.IssuingAuthorityID != run.Incident.ReplacementAuthorityID {
					return fmt.Errorf("migration: incident member %s replacement authority drifted from the plan", member.IdentityID)
				}
				if run.Incident.Mode == IncidentModeGameDay && !nonProductionEnvironment(b.Environment) {
					return fmt.Errorf("migration: game-day member %s is not explicitly non-production", member.IdentityID)
				}
			}
			if targets[b.TargetID] {
				return fmt.Errorf("migration: deployment target %s appears more than once", b.TargetID)
			}
			targets[b.TargetID] = true
			trust := trustTarget{agentID: b.RequiredAgentID, path: b.TrustAnchorPath}
			if priorWave, found := trustWaves[trust]; found && priorWave != wave.ID {
				return fmt.Errorf("migration: agent trust path %s cannot be shared across waves", b.TrustAnchorPath)
			}
			trustWaves[trust] = wave.ID
		}
	}
	if started == 0 {
		return errors.New("migration: executable run has no started wave")
	}
	if run.Status == RunRollingBack && (run.RollbackAttempt <= 0 || strings.TrimSpace(run.RollbackWaveID) == "" ||
		(run.RollbackStage != StageRollbackSuccessor && run.RollbackStage != StageRollbackTrust)) {
		return errors.New("migration: rolling back run has no durable rollback attempt cursor")
	}
	encoded, err := json.Marshal(run)
	if err != nil {
		return fmt.Errorf("migration: encode executable run for size check: %w", err)
	}
	if len(encoded) > maxExecutableRunBytes {
		return fmt.Errorf("migration: executable run exceeds the %d-byte event bound", maxExecutableRunBytes)
	}
	return nil
}

// ValidateExecutableRunForStart validates immutable authority before StartRun
// changes the aggregate from planned to running.
func ValidateExecutableRunForStart(run Run) error {
	copy := cloneRun(run)
	copy.Status = RunRunning
	first, ordinal := -1, 0
	for i := range copy.Waves {
		copy.Waves[i].Phase = PhasePlanned
		copy.Waves[i].Started = false
		if first < 0 || copy.Waves[i].Ordinal < ordinal {
			first, ordinal = i, copy.Waves[i].Ordinal
		}
	}
	if first >= 0 {
		copy.Waves[first].Started = true
		copy.Waves[first].Phase = PhaseVerifyingTrust
	}
	return ValidateExecutableRun(copy)
}

// ValidateActions proves that an event cannot smuggle work past the aggregate's
// current durable gate. Empty is valid because many observations only retain a
// partial verdict; every non-empty set must be exactly the unfinished work the
// current cursor licenses.
func ValidateActions(run Run, actions []Action) error {
	if len(actions) == 0 {
		return nil
	}
	want := ReconcileActions(run)
	if len(actions) != len(want) {
		return errors.New("migration: event actions do not match the current safety gate")
	}
	keys := make(map[string]bool, len(want))
	for _, action := range want {
		keys[actionKey(action)] = true
	}
	for _, action := range actions {
		key := actionKey(action)
		if !keys[key] {
			return errors.New("migration: event action is not licensed by the current safety gate")
		}
		delete(keys, key)
	}
	if len(keys) != 0 {
		return errors.New("migration: event actions omit work licensed by the current safety gate")
	}
	return nil
}

func actionKey(action Action) string {
	return string(action.Kind) + "\x00" + action.WaveID + "\x00" + action.IdentityID
}

func cloneRun(in Run) Run {
	out := in
	if in.Incident != nil {
		incident := *in.Incident
		incident.ExactTrustStoreIDs = append([]string(nil), in.Incident.ExactTrustStoreIDs...)
		incident.ExactTrustHosts = append([]string(nil), in.Incident.ExactTrustHosts...)
		incident.AffectedIdentityIDs = append([]string(nil), in.Incident.AffectedIdentityIDs...)
		out.Incident = &incident
	}
	out.Waves = append([]RunWave(nil), in.Waves...)
	for i := range out.Waves {
		out.Waves[i].Members = append([]RunMember(nil), in.Waves[i].Members...)
	}
	return out
}

func memberIndex(run Run, waveID, identityID string) (int, int) {
	for i := range run.Waves {
		if run.Waves[i].ID != waveID {
			continue
		}
		for j := range run.Waves[i].Members {
			if run.Waves[i].Members[j].IdentityID == identityID {
				return i, j
			}
		}
	}
	return -1, -1
}

func verdictForStage(member *RunMember, stage ObservationStage) *Verdict {
	switch stage {
	case StageTrust:
		return &member.TrustVerdict
	case StageSuccessor:
		return &member.SuccessorVerdict
	case StageRevocation:
		return &member.RevocationVerdict
	case StageRollbackSuccessor:
		return &member.RollbackSuccessorVerdict
	case StageRollbackTrust:
		return &member.RollbackTrustVerdict
	default:
		return nil
	}
}

func requireObservationPhase(run Run, waveIndex int, stage ObservationStage) error {
	wave := run.Waves[waveIndex]
	switch stage {
	case StageTrust:
		if (run.Status == RunRunning || run.Status == RunPaused) && wave.Phase == PhaseVerifyingTrust {
			return nil
		}
	case StageSuccessor:
		if (run.Status == RunRunning || run.Status == RunPaused) && wave.Phase == PhaseVerifyingLive {
			return nil
		}
	case StageRevocation:
		if run.Incident != nil && (run.Status == RunRunning || run.Status == RunPaused) && wave.Phase == PhaseRevokingPredecessor {
			return nil
		}
	case StageRollbackSuccessor, StageRollbackTrust:
		if run.Status == RunRollingBack && run.RollbackWaveID == wave.ID && run.RollbackStage == stage {
			return nil
		}
	}
	return fmt.Errorf("migration: %s observation is not licensed in run %s wave phase %s", stage, run.Status, wave.Phase)
}

func allVerified(wave RunWave, stage ObservationStage) bool {
	for i := range wave.Members {
		verdict := verdictForStage(&wave.Members[i], stage)
		if verdict == nil || *verdict != VerdictVerified {
			return false
		}
	}
	return true
}

func hasVerified(wave RunWave, stage ObservationStage) bool {
	for i := range wave.Members {
		verdict := verdictForStage(&wave.Members[i], stage)
		if verdict != nil && *verdict == VerdictVerified {
			return true
		}
	}
	return false
}

func actionsFor(wave RunWave, kind ActionKind) []Action {
	out := make([]Action, 0, len(wave.Members))
	for _, member := range wave.Members {
		out = append(out, Action{Kind: kind, WaveID: wave.ID, IdentityID: member.IdentityID})
	}
	return out
}

func missingActions(wave RunWave, stage ObservationStage, kind ActionKind) []Action {
	out := make([]Action, 0, len(wave.Members))
	for i := range wave.Members {
		verdict := verdictForStage(&wave.Members[i], stage)
		if verdict != nil && *verdict == "" {
			out = append(out, Action{Kind: kind, WaveID: wave.ID, IdentityID: wave.Members[i].IdentityID})
		}
	}
	return out
}

// Member returns a copy of one run member without exposing mutable aggregate
// slices to command construction.
func Member(run Run, waveID, identityID string) (RunMember, bool) {
	wi, mi := memberIndex(run, waveID, identityID)
	if wi < 0 {
		return RunMember{}, false
	}
	return run.Waves[wi].Members[mi], true
}

func nextPlannedWave(run Run, from int) int {
	for i := from + 1; i < len(run.Waves); i++ {
		if run.Waves[i].Phase == PhasePlanned || run.Waves[i].Phase == PhaseHalted {
			return i
		}
	}
	return -1
}

func newestStartedWave(run Run) int {
	best, ordinal := -1, -1
	for i := range run.Waves {
		wave := run.Waves[i]
		if wave.Started && wave.Phase != PhaseRolledBack && wave.Ordinal > ordinal {
			best, ordinal = i, wave.Ordinal
		}
	}
	return best
}

func nextRollbackWave(run Run, from int) int {
	// An incident revokes each completed cohort's predecessor before advancing.
	// Those predecessors cannot be made valid again, so an automatic failure
	// inverse is deliberately bounded to the current cohort.
	if run.Incident != nil {
		return -1
	}
	best, ordinal := -1, -1
	current := run.Waves[from].Ordinal
	for i := range run.Waves {
		wave := run.Waves[i]
		if wave.Ordinal >= current || wave.Phase == PhaseRolledBack || !wave.Started {
			continue
		}
		if wave.Ordinal > ordinal {
			best, ordinal = i, wave.Ordinal
		}
	}
	return best
}

func successorWorkWasPublished(wave RunWave) bool {
	return wave.Phase == PhaseVerifyingLive || wave.Phase == PhaseRevokingPredecessor ||
		wave.Phase == PhaseComplete || hasVerified(wave, StageSuccessor)
}

func nonProductionEnvironment(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "test", "testing", "qa", "quality-assurance", "staging", "stage", "development", "dev", "sandbox", "game-day", "game_day", "non-production", "nonproduction":
		return true
	default:
		return false
	}
}
