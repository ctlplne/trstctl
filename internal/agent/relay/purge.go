// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Removing compromised material from a host (A49).
//
// Containment stops a listener; it leaves the compromised private key on disk
// and in the agent's rollback ledger, where a later rollback or a curious
// process can still reach it. A purge is the second half: the exact enrolled
// host agent proves the installed leaf is the compromised one, overwrites and
// removes the certificate and key files the target's file layout names, wipes
// every ledger snapshot carrying that fingerprint so no rollback can restore
// it, and, when the host profile binds a stop action to the target, runs that
// action so the key is not kept alive in a running process either.
//
// It is host-only and reference-only like containment: the control plane
// selects the agent and the exact fingerprint; the host profile's allowed
// roots bound which files may be touched; nothing in the job can name a path
// outside the target's own configuration.

// KindEndpointPurge is the host-only material-removal command.
const KindEndpointPurge = "endpoint.purge"

// PurgeIntent names the exact target, leaf and agent. TargetConfig is the
// target's own configuration, from which the file layout is derived.
type PurgeIntent struct {
	TargetID            string          `json:"target_id"`
	TargetRevision      string          `json:"target_revision"`
	IdentityID          string          `json:"identity_id"`
	ExpectedFingerprint string          `json:"expected_fingerprint"`
	RequiredAgentID     string          `json:"required_agent_id"`
	Connector           string          `json:"connector"`
	TargetConfig        json.RawMessage `json:"target_config,omitempty"`
}

const (
	// PurgeRemoved: the installed leaf matched, its files were overwritten and
	// removed, and every ledger snapshot with that fingerprint was wiped.
	PurgeRemoved = "removed"
	// PurgeDifferentLeaf: the files hold another certificate; nothing was
	// touched. The compromised material is not at this target's paths.
	PurgeDifferentLeaf = "different_leaf"
	// PurgeAbsent: the target's files do not exist; only the ledger was wiped.
	PurgeAbsent = "absent"
	// PurgeFailed: the leaf matched but removal or the ledger wipe failed; the
	// report says which. Material may remain.
	PurgeFailed = "failed"

	// Listener dispositions after a removal.
	PurgeListenerNotBound  = "not_bound"
	PurgeListenerStopped   = "stopped"
	PurgeListenerStopError = "stop_failed"
)

// PurgeReport is the public, signed account of one purge. It carries file
// paths (tenant configuration) and fingerprints, never bytes.
type PurgeReport struct {
	TargetID            string   `json:"target_id"`
	TargetRevision      string   `json:"target_revision"`
	IdentityID          string   `json:"identity_id"`
	ExpectedFingerprint string   `json:"expected_fingerprint"`
	Connector           string   `json:"connector"`
	State               string   `json:"state"`
	ObservedFingerprint string   `json:"observed_fingerprint,omitempty"`
	RemovedFiles        []string `json:"removed_files"`
	LedgerWiped         bool     `json:"ledger_wiped"`
	Listener            string   `json:"listener"`
	Failure             string   `json:"failure,omitempty"`
}

// Digest binds the whole decision to the signed job receipt. The server
// re-derives it from the structured report.
func (r PurgeReport) Digest() string {
	var bytes []byte
	for _, part := range []string{"trstctl-purge-report/v1", r.TargetID, r.TargetRevision, r.IdentityID,
		r.ExpectedFingerprint, r.Connector, r.State, r.ObservedFingerprint, r.Listener, r.Failure} {
		bytes = append(bytes, part...)
		bytes = append(bytes, 0)
	}
	for _, path := range r.RemovedFiles {
		bytes = append(bytes, path...)
		bytes = append(bytes, 0)
	}
	if r.LedgerWiped {
		bytes = append(bytes, 1)
	} else {
		bytes = append(bytes, 0)
	}
	return crypto.SHA256Hex(bytes)
}

// ValidatePurgeReport checks that a signed report answers exactly the queued
// intent and that the evidence digest the agent signed is the report's own.
func ValidatePurgeReport(intent PurgeIntent, report PurgeReport, digest string) error {
	if report.TargetID != intent.TargetID || report.TargetRevision != intent.TargetRevision ||
		report.IdentityID != intent.IdentityID || report.Connector != intent.Connector ||
		!strings.EqualFold(report.ExpectedFingerprint, intent.ExpectedFingerprint) {
		return errors.New("purge report does not answer the queued intent")
	}
	switch report.State {
	case PurgeRemoved, PurgeDifferentLeaf, PurgeAbsent, PurgeFailed:
	default:
		return errors.New("purge report carries an unknown state")
	}
	switch report.Listener {
	case PurgeListenerNotBound, PurgeListenerStopped, PurgeListenerStopError:
	default:
		return errors.New("purge report carries an unknown listener disposition")
	}
	if report.State == PurgeRemoved && len(report.RemovedFiles) == 0 {
		return errors.New("a removed purge report names no files")
	}
	if report.State != PurgeRemoved && report.State != PurgeFailed && len(report.RemovedFiles) != 0 {
		return errors.New("a non-removal purge report must not name removed files")
	}
	if report.Failure != "" && report.State != PurgeFailed {
		return errors.New("only a failed purge report carries a failure")
	}
	if digest == "" || digest != report.Digest() {
		return errors.New("purge report digest does not match the signed evidence")
	}
	return nil
}

func validPurgeIntent(intent PurgeIntent) bool {
	for _, value := range []string{intent.TargetID, intent.TargetRevision, intent.IdentityID,
		intent.RequiredAgentID, intent.Connector} {
		if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n") {
			return false
		}
	}
	fp, err := hex.DecodeString(strings.TrimSpace(intent.ExpectedFingerprint))
	return err == nil && len(fp) == 32 && len(intent.TargetConfig) > 0
}

func runPurge(ctx context.Context, ch Channel, profile connector.LocalOpsConfig, hostRollback *HostRollbackStore, job Job) bool {
	var intent PurgeIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil || !validPurgeIntent(intent) {
		report(ctx, ch, job, OutcomeFailed, "endpoint purge intent is invalid")
		return false
	}
	if hostRollback == nil {
		report(ctx, ch, job, OutcomeFailed, "host rollback ledger is unavailable for purge")
		return false
	}
	var stop func() error
	if binding, found := containmentForTarget(profile, intent.TargetID); found {
		ops, err := connector.NewLocalOps(profile)
		if err != nil {
			report(ctx, ch, job, OutcomeFailed, "host purge profile is unusable")
			return false
		}
		executor, ok := ops.(connector.ContextExecutor)
		if !ok {
			report(ctx, ch, job, OutcomeFailed, "host purge executor is unavailable")
			return false
		}
		stop = func() error { return executor.ExecContext(ctx, binding.Action, []string{}) }
	}
	result := executePurge(profile, intent, hostRollback, stop)
	encoded, err := json.Marshal(result)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "host purge report could not be encoded")
		return false
	}
	reportWithEvidence(ctx, ch, job, OutcomeExecuted, string(encoded), result.Digest())
	return result.State == PurgeRemoved
}

// executePurge is the whole decision, separated from the channel so the file,
// ledger and listener behavior is testable against a temporary root. stop is
// nil when the host profile binds no stop action to this target.
func executePurge(profile connector.LocalOpsConfig, intent PurgeIntent, ledger *HostRollbackStore, stop func() error) PurgeReport {
	report := PurgeReport{TargetID: intent.TargetID, TargetRevision: intent.TargetRevision,
		IdentityID: intent.IdentityID, ExpectedFingerprint: strings.ToLower(intent.ExpectedFingerprint),
		Connector: intent.Connector, RemovedFiles: []string{}, Listener: PurgeListenerNotBound}
	var target HostTargetConfig
	if err := json.Unmarshal(intent.TargetConfig, &target); err != nil {
		report.State, report.Failure = PurgeFailed, "target configuration is not readable"
		return report
	}
	layout, err := hostPredecessorLayout(intent.Connector, target)
	if err != nil {
		report.State, report.Failure = PurgeFailed, "no exact file layout for this connector family: "+err.Error()
		return report
	}
	certPEM, keyPEM, err := readInstalledHostPredecessor(profile, intent.Connector, target)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		report.State = PurgeAbsent
		report.LedgerWiped = wipeLedgerFingerprint(ledger, intent, &report)
		return report
	case err != nil:
		report.State, report.Failure = PurgeFailed, "installed material could not be read: "+err.Error()
		return report
	}
	defer secret.Wipe(keyPEM)
	info, err := certinfo.Inspect(certPEM)
	if err != nil {
		report.State, report.Failure = PurgeFailed, "installed certificate could not be parsed"
		return report
	}
	report.ObservedFingerprint = strings.ToLower(info.SHA256Fingerprint)
	if !sameHostRollbackFingerprint(info.SHA256Fingerprint, intent.ExpectedFingerprint) {
		report.State = PurgeDifferentLeaf
		return report
	}
	// The leaf is the compromised one. Overwrite every file the layout names
	// before unlinking it, so the key bytes do not survive in the freed blocks
	// of a filesystem that would otherwise leave them in place.
	for _, path := range layout.paths() {
		if path == "" {
			continue
		}
		if err := scrubAndRemoveLocalFile(profile, path); err != nil {
			report.State, report.Failure = PurgeFailed, "could not remove "+path+": "+err.Error()
			return report
		}
		report.RemovedFiles = append(report.RemovedFiles, path)
	}
	report.LedgerWiped = wipeLedgerFingerprint(ledger, intent, &report)
	if report.State == PurgeFailed {
		return report
	}
	report.State = PurgeRemoved
	if stop != nil {
		if err := stop(); err != nil {
			report.Listener = PurgeListenerStopError
		} else {
			report.Listener = PurgeListenerStopped
		}
	}
	return report
}

// paths lists every file the layout names, in removal order (keys first).
func (f hostPredecessorFiles) paths() []string {
	return []string{f.keyPath, f.mirrorKeyPath, f.bundlePath, f.certPath, f.mirrorCertPath}
}

func wipeLedgerFingerprint(ledger *HostRollbackStore, intent PurgeIntent, report *PurgeReport) bool {
	wiped, err := ledger.PurgeFingerprint(intent.Connector, intent.TargetID, intent.ExpectedFingerprint)
	if err != nil {
		report.State, report.Failure = PurgeFailed, "host rollback ledger could not be wiped: "+err.Error()
		return false
	}
	return wiped
}

// scrubAndRemoveLocalFile overwrites a regular file inside the operator's
// allowed roots with zeros of the same length, syncs it, then removes it. A
// missing file is not an error: the material is already gone.
func scrubAndRemoveLocalFile(profile connector.LocalOpsConfig, path string) error {
	current, err := connector.ReadLocalFile(profile, path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer secret.Wipe(current)
	ops, err := connector.NewLocalOps(profile)
	if err != nil {
		return err
	}
	zeros := make([]byte, len(current))
	if err := ops.WriteFile(path, zeros); err != nil {
		return err
	}
	return connector.RemoveLocalFile(profile, path, zeros)
}
