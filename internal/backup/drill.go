// SPDX-License-Identifier: BUSL-1.1

package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
)

// Proving a backup restores, by restoring it (epic J2).
//
// A verified backup is one whose bytes still match what was recorded. That is
// necessary and it is not the claim an operator needs before an incident, which
// is that the backup RESTORES — that the artifacts, in the shape they are in,
// reproduce a working deployment.
//
// The gap between those is where disaster recovery actually fails: an intact
// artifact of a format the current binary no longer reads, a manifest missing a
// table added three migrations ago, an event log whose restore stops on a gap.
// Every one of those passes verification and fails a restore, and the usual way
// to find out is during the outage.
//
// So a drill restores into an EPHEMERAL target and throws it away. The
// attestation records what actually happened — including when it failed, which
// is the case worth having an attestation for.

// DrillOutcome is the closed set of results.
//
// Closed because this is signed evidence somebody reads under pressure, and each
// value implies a different response. A free-text status would produce prose
// that reads like a verdict and commits to nothing.
type DrillOutcome string

const (
	// DrillRestored: the backup reproduced state into the ephemeral target.
	DrillRestored DrillOutcome = "restored"
	// DrillFailed: the restore was attempted and did not complete. This is the
	// outcome an attestation exists for — a drill nobody ran and a drill that
	// failed look identical without one.
	DrillFailed DrillOutcome = "failed"
	// DrillSkipped: no drill ran. Recorded rather than left absent, so a
	// deployment that never drills cannot be mistaken for one whose drills pass.
	DrillSkipped DrillOutcome = "skipped"
)

// DrillAlertReason is the closed operational verdict derived from the signed
// measurements and signed recovery objectives.
type DrillAlertReason string

const (
	DrillAlertFailed   DrillAlertReason = "failed"
	DrillAlertSkipped  DrillAlertReason = "skipped"
	DrillAlertOverRPO  DrillAlertReason = "over_rpo"
	DrillAlertOverRTO  DrillAlertReason = "over_rto"
	DrillAlertOverBoth DrillAlertReason = "over_rpo_and_rto"
)

// DrillAttestation is the signed record of one restore drill.
type DrillAttestation struct {
	Outcome DrillOutcome `json:"outcome"`
	// StartedAt and CompletedAt bound the attempt.
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	// BackupCreatedAt is when the backup being drilled was taken.
	BackupCreatedAt time.Time `json:"backup_created_at"`
	// RPOSeconds is how much time the restored state would have lost: the age of
	// the backup at the moment the drill ran.
	//
	// Measured from the backup's own manifest rather than configured. A
	// configured RPO is a target; this is the one that was actually achievable
	// with the artifacts on disk, and the two diverge precisely when a backup
	// job has been quietly failing.
	RPOSeconds int64 `json:"rpo_seconds"`
	// RTOSeconds is how long the restore took, wall clock.
	//
	// From an ephemeral target on the machine running the drill, which is not
	// the production restore time — real recovery includes provisioning,
	// networking and people. It is a floor, and the attestation says so rather
	// than letting it be read as a promise.
	RTOSeconds int64 `json:"rto_seconds"`
	// EventsRestored is how many events the restore replayed. Zero on a
	// successful drill is itself a finding: a backup that restores nothing has
	// verified and proved nothing.
	EventsRestored int `json:"events_restored"`
	// PostgresRecordsRestored is the independent state imported from the paired
	// PostgreSQL artifact. PostgresTablesRestored carries the table-by-table
	// evidence, including explicit zeroes, so a newly added durable table cannot
	// disappear behind a plausible aggregate.
	PostgresRecordsRestored int            `json:"postgres_records_restored"`
	PostgresTablesRestored  map[string]int `json:"postgres_tables_restored"`
	// ArtifactsRestored names the manifest artifacts that were actually copied,
	// decrypted, or replayed into the isolated target. FullSetRestored is true
	// only after every required artifact and both datastore artifacts complete.
	ArtifactsRestored []string `json:"artifacts_restored"`
	FullSetRestored   bool     `json:"full_set_restored"`
	// Health is evidence collected from the recovered target, not the source
	// deployment. A restored verdict requires every check to be true.
	StoreHealthy    bool `json:"store_healthy"`
	EventLogHealthy bool `json:"event_log_healthy"`
	SignerHealthy   bool `json:"signer_healthy"`
	ServerHealthy   bool `json:"server_healthy"`
	// Detail explains the outcome in the terms an operator acts on.
	Detail string `json:"detail"`
	// Limitations states what this drill did NOT prove, carried in the
	// attestation itself so it cannot be separated from the claim.
	Limitations []string `json:"limitations"`
}

// ErrNoEphemeralTarget is returned when a drill is asked for with nowhere to
// restore into.
var ErrNoEphemeralTarget = errors.New("backup: a restore drill needs an ephemeral target to restore into")

// RestoreFunc performs the restore into an ephemeral target and reports how many
// events it replayed.
//
// A function rather than a concrete restorer so the drill exercises the SAME
// restore path production recovery uses. A drill with its own simplified restore
// would prove that the simplified one works.
type RestoreResult struct {
	EventsRestored          int
	PostgresRecordsRestored int
	PostgresTablesRestored  map[string]int
	ArtifactsRestored       []string
	FullSetRestored         bool
	StoreHealthy            bool
	EventLogHealthy         bool
	SignerHealthy           bool
	ServerHealthy           bool
}

// Healthy reports whether the isolated recovery target proved all four runtime
// boundaries needed to serve: PostgreSQL, the AN-2 log, the signer process, and
// the recovered control-plane assembly.
func (r RestoreResult) Healthy() bool {
	return r.StoreHealthy && r.EventLogHealthy && r.SignerHealthy && r.ServerHealthy
}

type RestoreFunc func(ctx context.Context) (RestoreResult, error)

// RunDrill restores a backup into an ephemeral target and attests what happened.
//
// It attests a FAILURE as readily as a success. An attestation that only exists
// when the drill passed makes "no attestation" ambiguous between "nobody ran it"
// and "it failed", and those are the two states most worth telling apart.
func RunDrill(ctx context.Context, backupDir string, restore RestoreFunc, now func() time.Time) (DrillAttestation, error) {
	if now == nil {
		now = time.Now
	}
	att := DrillAttestation{
		StartedAt: now().UTC(),
		Limitations: []string{
			"The restore ran into an ephemeral target on the machine performing the drill, so " +
				"the measured RTO is a floor: real recovery also includes provisioning, " +
				"networking, DNS and the people doing it.",
			"A drill proves the artifacts on disk reproduce state. It does not prove the " +
				"deployment they reproduce is correctly configured for your environment.",
		},
	}
	if restore == nil {
		att.Outcome = DrillSkipped
		att.CompletedAt = now().UTC()
		att.Detail = "No ephemeral restore target is configured, so no drill ran. This is recorded " +
			"rather than left absent: a deployment that never drills must not be mistaken for one " +
			"whose drills pass."
		return att, ErrNoEphemeralTarget
	}

	// Verify first. Restoring a backup already known to be corrupt would produce
	// a failed drill whose cause is buried in a restore error, when the manifest
	// could have said so in a sentence.
	report, verifyErr := VerifyFullBackup(backupDir)
	att.BackupCreatedAt = report.CreatedAt
	if verifyErr != nil || !report.Verified {
		att.Outcome = DrillFailed
		att.CompletedAt = now().UTC()
		att.Detail = "The backup did not verify, so no restore was attempted. Its artifacts no " +
			"longer match what was recorded when it was taken, which means a restore would not " +
			"reproduce the state it claims to hold."
		return att, nil
	}
	if !report.CreatedAt.IsZero() {
		att.RPOSeconds = int64(att.StartedAt.Sub(report.CreatedAt).Seconds())
	}

	result, err := restore(ctx)
	att.CompletedAt = now().UTC()
	att.RTOSeconds = int64(att.CompletedAt.Sub(att.StartedAt).Seconds())
	att.EventsRestored = result.EventsRestored
	att.PostgresRecordsRestored = result.PostgresRecordsRestored
	att.PostgresTablesRestored = result.PostgresTablesRestored
	att.ArtifactsRestored = append([]string(nil), result.ArtifactsRestored...)
	att.FullSetRestored = result.FullSetRestored
	att.StoreHealthy = result.StoreHealthy
	att.EventLogHealthy = result.EventLogHealthy
	att.SignerHealthy = result.SignerHealthy
	att.ServerHealthy = result.ServerHealthy

	switch {
	case err != nil:
		att.Outcome = DrillFailed
		// The restore error can carry paths and internal detail. The attestation
		// is signed evidence that may travel, so it carries a closed sentence
		// and the operator reads the drill's own logs for the rest.
		att.Detail = "The backup verified and the restore did not complete. The artifacts are " +
			"intact and something about restoring them into a fresh deployment fails — which is " +
			"exactly the failure a drill exists to find before an incident does."
	case result.EventsRestored == 0:
		// A restore that replayed nothing "succeeded" and proved nothing. Left
		// as a pass, this is the drill most likely to give false confidence.
		att.Outcome = DrillFailed
		att.Detail = "The restore completed and replayed no events. A backup that restores " +
			"nothing has verified and proved nothing; treat this as a failed drill rather than " +
			"a fast one."
	case !result.FullSetRestored:
		att.Outcome = DrillFailed
		att.Detail = "The event log restored, but the delivered full backup set did not. " +
			"A disaster-recovery verdict requires the paired PostgreSQL state and every required " +
			"key and configuration artifact, so this drill failed closed."
	case !result.Healthy():
		att.Outcome = DrillFailed
		att.Detail = "The full backup set restored, but the isolated target did not pass every " +
			"PostgreSQL, event-log, signer, and recovered-server health check. Restored bytes are " +
			"not a working recovery, so this drill failed closed."
	default:
		att.Outcome = DrillRestored
		att.Detail = fmt.Sprintf("The complete backup set restored into an isolated ephemeral target, replaying %d "+
			"events and importing %d independent PostgreSQL records. PostgreSQL, the event log, "+
			"the signer, and the recovered server all passed health checks. The state it holds is %s old.",
			result.EventsRestored, result.PostgresRecordsRestored, humaniseAge(att.RPOSeconds))
	}
	return att, nil
}

// humaniseAge renders an RPO in words an operator reads rather than seconds.
func humaniseAge(seconds int64) string {
	d := time.Duration(seconds) * time.Second
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

// Signable returns the canonical bytes an attestation is signed over.
//
// Deterministic JSON of the whole attestation, so the signature covers the
// limitations too. A signature over only the outcome would let the caveats be
// edited off a document whose signature still verified — and the caveats are the
// part somebody quoting this in a compliance pack would most like to lose.
func (a DrillAttestation) Signable() ([]byte, error) {
	return json.Marshal(a)
}

const DrillEvidenceSchemaVersion = 1

// DrillEvidenceBody is the complete statement authorized by the isolated
// audit-evidence key. Signer identity and public verification material live
// inside the signed body, so neither can be swapped beside a still-valid JWS.
type DrillEvidenceBody struct {
	SchemaVersion           int              `json:"schema_version"`
	DrillID                 string           `json:"drill_id"`
	Scope                   string           `json:"scope"`
	Attestation             DrillAttestation `json:"attestation"`
	RPOObjectiveNanoseconds int64            `json:"rpo_objective_nanoseconds"`
	RTOObjectiveNanoseconds int64            `json:"rto_objective_nanoseconds"`
	AlertReason             DrillAlertReason `json:"alert_reason,omitempty"`
	SignerKeyID             string           `json:"signer_key_id"`
	SignerAlgorithm         string           `json:"signer_algorithm"`
	VerificationJWKS        json.RawMessage  `json:"verification_jwks"`
}

// SignedDrillEvidence is one portable restore-drill proof. Verification accepts
// a deployment-trusted key set separately; VerificationJWKS is carried so an
// exported record is self-describing, never so the record can choose its trust
// root.
type SignedDrillEvidence struct {
	DrillEvidenceBody
	Signature string `json:"signature"`
}

// SignDrillEvidence signs one deployment-scoped drill through the supplied
// SigningKey. In production that key is a public wrapper around the narrow
// trstctl-signer artifact RPC, so the control plane never sees private material.
func SignDrillEvidence(
	ctx context.Context,
	key *jose.SigningKey,
	drillID string,
	att DrillAttestation,
	rpoObjective time.Duration,
	rtoObjective time.Duration,
) (SignedDrillEvidence, error) {
	if err := ctx.Err(); err != nil {
		return SignedDrillEvidence{}, err
	}
	if key == nil || drillID == "" {
		return SignedDrillEvidence{}, errors.New("backup: restore-drill signing key and drill id are required")
	}
	if err := validateDrillAttestation(att); err != nil {
		return SignedDrillEvidence{}, err
	}
	if rpoObjective < 0 || rtoObjective < 0 {
		return SignedDrillEvidence{}, errors.New("backup: restore-drill recovery objectives must not be negative")
	}
	jwks, err := key.PublicJWKS()
	if err != nil {
		return SignedDrillEvidence{}, fmt.Errorf("backup: render restore-drill verification key: %w", err)
	}
	body := DrillEvidenceBody{
		SchemaVersion:           DrillEvidenceSchemaVersion,
		DrillID:                 drillID,
		Scope:                   "deployment",
		Attestation:             att,
		RPOObjectiveNanoseconds: int64(rpoObjective),
		RTOObjectiveNanoseconds: int64(rtoObjective),
		AlertReason:             DrillAlertReasonFor(att, rpoObjective, rtoObjective),
		SignerKeyID:             key.KeyID(),
		SignerAlgorithm:         "RS256",
		VerificationJWKS:        append(json.RawMessage(nil), jwks...),
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return SignedDrillEvidence{}, fmt.Errorf("backup: encode restore-drill evidence: %w", err)
	}
	signature, err := key.SignArtifact(jose.ArtifactRestoreDrill, payload)
	if err != nil {
		return SignedDrillEvidence{}, fmt.Errorf("backup: sign restore-drill evidence: %w", err)
	}
	return SignedDrillEvidence{DrillEvidenceBody: body, Signature: signature}, nil
}

// VerifyDrillEvidence verifies both cryptographic authority and canonical body.
// trusted is configured by the deployment; the JWKS carried in evidence is
// checked for portability but cannot grant itself authority.
func VerifyDrillEvidence(evidence SignedDrillEvidence, trusted *jose.JWKSet) error {
	if trusted == nil {
		return errors.New("backup: trusted restore-drill verification keys are required")
	}
	if evidence.SchemaVersion != DrillEvidenceSchemaVersion || evidence.DrillID == "" ||
		evidence.Scope != "deployment" || evidence.SignerKeyID == "" ||
		evidence.SignerAlgorithm != "RS256" || len(evidence.VerificationJWKS) == 0 ||
		evidence.Signature == "" {
		return errors.New("backup: restore-drill evidence is incomplete or has an unsupported schema")
	}
	if err := validateDrillAttestation(evidence.Attestation); err != nil {
		return err
	}
	if evidence.RPOObjectiveNanoseconds < 0 || evidence.RTOObjectiveNanoseconds < 0 {
		return errors.New("backup: restore-drill evidence has negative recovery objectives")
	}
	wantReason := DrillAlertReasonFor(evidence.Attestation,
		time.Duration(evidence.RPOObjectiveNanoseconds), time.Duration(evidence.RTOObjectiveNanoseconds))
	if evidence.AlertReason != wantReason {
		return fmt.Errorf("backup: restore-drill alert reason %q does not match signed outcome, measurements, and objectives", evidence.AlertReason)
	}
	payload, err := json.Marshal(evidence.DrillEvidenceBody)
	if err != nil {
		return fmt.Errorf("backup: encode restore-drill evidence body: %w", err)
	}
	verified, keyID, err := trusted.VerifyArtifactWithKeyID(evidence.Signature, jose.ArtifactRestoreDrill)
	if err != nil {
		return fmt.Errorf("backup: verify trusted restore-drill signature: %w", err)
	}
	if !sameJSONValue(verified, payload) {
		return errors.New("backup: restore-drill signature payload does not match evidence body")
	}
	if keyID != evidence.SignerKeyID {
		return fmt.Errorf("backup: restore-drill signer identity %q does not match protected JWS kid %q", evidence.SignerKeyID, keyID)
	}
	embedded, err := jose.ParseJWKSet(evidence.VerificationJWKS)
	if err != nil {
		return fmt.Errorf("backup: parse embedded restore-drill verification material: %w", err)
	}
	if _, err := embedded.VerifyArtifact(evidence.Signature, jose.ArtifactRestoreDrill); err != nil {
		return fmt.Errorf("backup: embedded restore-drill verification material does not match signer: %w", err)
	}
	return nil
}

// DrillAlertReasonFor deterministically maps the measured result and configured
// objectives to the alert that must be emitted. Because all inputs and the result
// are signed together, event tampering cannot silence or manufacture the alert.
func DrillAlertReasonFor(att DrillAttestation, rpo, rto time.Duration) DrillAlertReason {
	switch att.Outcome {
	case DrillFailed:
		return DrillAlertFailed
	case DrillSkipped:
		return DrillAlertSkipped
	}
	overRPO := time.Duration(att.RPOSeconds)*time.Second > rpo
	overRTO := time.Duration(att.RTOSeconds)*time.Second > rto
	switch {
	case overRPO && overRTO:
		return DrillAlertOverBoth
	case overRPO:
		return DrillAlertOverRPO
	case overRTO:
		return DrillAlertOverRTO
	default:
		return ""
	}
}

func sameJSONValue(a, b []byte) bool {
	var left, right any
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return false
	}
	return reflect.DeepEqual(left, right)
}

func validateDrillAttestation(att DrillAttestation) error {
	switch att.Outcome {
	case DrillRestored, DrillFailed, DrillSkipped:
	default:
		return fmt.Errorf("backup: unsupported restore-drill outcome %q", att.Outcome)
	}
	if att.StartedAt.IsZero() || att.CompletedAt.IsZero() || att.CompletedAt.Before(att.StartedAt) {
		return errors.New("backup: restore-drill evidence has invalid attempt times")
	}
	if att.RPOSeconds < 0 || att.RTOSeconds < 0 {
		return errors.New("backup: restore-drill evidence has negative recovery measurements")
	}
	return nil
}
