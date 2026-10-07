// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/agent/verify"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// KindEndpointContain is a host-only, reference-only command. The control
// plane selects the exact enrolled agent; the host profile selects the only
// listener and executable the agent may use for this target.
const KindEndpointContain = "endpoint.contain"

type ContainmentIntent struct {
	TargetID            string `json:"target_id"`
	TargetRevision      string `json:"target_revision"`
	IdentityID          string `json:"identity_id"`
	ExpectedFingerprint string `json:"expected_fingerprint"`
	RequiredAgentID     string `json:"required_agent_id"`
}

const (
	ContainmentStopped           = "stopped"
	ContainmentDifferentLeaf     = "different_leaf"
	ContainmentUnverified        = "unverified"
	ContainmentFailed            = "failed"
	containmentMaxPostStopProbes = 40
	containmentPostStopInterval  = 250 * time.Millisecond
)

// ContainmentReport is the public, signed before/after account of one host
// action. It contains no credential and no command output.
type ContainmentReport struct {
	TargetID            string                      `json:"target_id"`
	TargetRevision      string                      `json:"target_revision"`
	IdentityID          string                      `json:"identity_id"`
	ExpectedFingerprint string                      `json:"expected_fingerprint"`
	Action              string                      `json:"action"`
	State               string                      `json:"state"`
	Before              transport.ProbeTranscript   `json:"before"`
	After               []transport.ProbeTranscript `json:"after"`
}

// Digest binds the complete decision and both probe phases to the signed job
// receipt. The server re-derives it from the structured report.
func (r ContainmentReport) Digest() string {
	var bytes []byte
	for _, part := range []string{"trstctl-containment-report/v1", r.TargetID, r.TargetRevision,
		r.IdentityID, r.ExpectedFingerprint, r.Action, r.State} {
		bytes = append(bytes, part...)
		bytes = append(bytes, '\n')
	}
	bytes = append(bytes, r.Before.Canonical()...)
	for _, probe := range r.After {
		bytes = append(bytes, probe.Canonical()...)
	}
	return transport.SweepDigest(bytes)
}

// ValidateContainmentReport is also used by the receiver. A signed statement
// alone proves who sent bytes; these checks prove the bytes describe the queued
// exact target and a logically possible before/after decision.
func ValidateContainmentReport(intent ContainmentIntent, report ContainmentReport, digest string) error {
	if !validContainmentIntent(intent) || report.TargetID != intent.TargetID ||
		report.TargetRevision != intent.TargetRevision || report.IdentityID != intent.IdentityID ||
		!strings.EqualFold(report.ExpectedFingerprint, intent.ExpectedFingerprint) ||
		strings.TrimSpace(report.Action) == "" || strings.ContainsAny(report.Action, "\r\n") {
		return errors.New("containment report does not match the queued target and certificate")
	}
	if err := report.Before.Validate(); err != nil {
		return err
	}
	if report.Before.Vantage != transport.VantageLocal ||
		!strings.EqualFold(report.Before.ExpectedFingerprint, intent.ExpectedFingerprint) {
		return errors.New("containment before probe is not local or exact")
	}
	lastObservedAt := report.Before.ObservedAtUnix
	for _, after := range report.After {
		if err := after.Validate(); err != nil {
			return err
		}
		if after.Vantage != transport.VantageLocal || after.Address != report.Before.Address ||
			after.ServerName != report.Before.ServerName ||
			!strings.EqualFold(after.ExpectedFingerprint, intent.ExpectedFingerprint) ||
			after.ObservedAtUnix < lastObservedAt {
			return errors.New("containment after probe does not follow the same local listener")
		}
		lastObservedAt = after.ObservedAtUnix
	}
	beforeExact := report.Before.Reached && strings.EqualFold(report.Before.ObservedFingerprint, intent.ExpectedFingerprint)
	switch report.State {
	case ContainmentUnverified:
		if (report.Before.Reached && report.Before.ObservedFingerprint != "") || len(report.After) != 0 {
			return errors.New("unverified containment claims a reached listener or a stop")
		}
	case ContainmentDifferentLeaf:
		if !report.Before.Reached || report.Before.ObservedFingerprint == "" || beforeExact || len(report.After) != 0 {
			return errors.New("different-leaf containment did not observe a different leaf before any action")
		}
	case ContainmentStopped, ContainmentFailed:
		if !beforeExact || len(report.After) < 2 || len(report.After) > containmentMaxPostStopProbes {
			return errors.New("containment stop lacks exact before and bounded after probes")
		}
		if report.State == ContainmentStopped {
			for _, after := range report.After {
				if after.Reached && !strings.EqualFold(after.ObservedFingerprint, intent.ExpectedFingerprint) {
					return errors.New("stopped target presented a different TLS leaf")
				}
			}
			last := len(report.After) - 1
			if report.After[last-1].Reached || report.After[last].Reached {
				return errors.New("stopped target lacks two final TLS refusals")
			}
		}
	default:
		return errors.New("containment report has unknown state")
	}
	if report.Digest() != digest {
		return errors.New("containment report digest does not match signed receipt")
	}
	return nil
}

func runContainment(ctx context.Context, ch Channel, profile connector.LocalOpsConfig, job Job) bool {
	var intent ContainmentIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil || !validContainmentIntent(intent) {
		report(ctx, ch, job, OutcomeFailed, "endpoint containment intent is invalid")
		return false
	}
	binding, found := containmentForTarget(profile, intent.TargetID)
	if !found {
		report(ctx, ch, job, OutcomeFailed, "host profile has no containment binding for this exact target")
		return false
	}
	ops, err := connector.NewLocalOps(profile)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "host containment profile is unusable")
		return false
	}
	executor, ok := ops.(connector.ContextExecutor)
	if !ok {
		report(ctx, ch, job, OutcomeFailed, "host containment executor is unavailable")
		return false
	}
	probe := func() (transport.ProbeTranscript, error) {
		observed, probeErr := verify.Endpoint(ctx, verify.Request{
			Address: binding.Address, ServerName: binding.ServerName,
			Vantage: transport.VantageLocal, Timeout: verify.DefaultTimeout,
			NativeProbeExecutable: profile.TLSProbeOpenSSL,
			Expect:                certinfo.Expectation{SHA256Fingerprint: intent.ExpectedFingerprint},
		})
		return observed.Transcript, probeErr
	}
	result, err := executeContainment(ctx, intent, binding, probe, func() error {
		return executor.ExecContext(ctx, binding.Action, []string{})
	})
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "host containment probe could not run")
		return false
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "host containment report could not be encoded")
		return false
	}
	reportWithEvidence(ctx, ch, job, OutcomeExecuted, string(encoded), result.Digest())
	return result.State == ContainmentStopped || result.State == ContainmentDifferentLeaf
}

func validContainmentIntent(intent ContainmentIntent) bool {
	if strings.TrimSpace(intent.TargetID) == "" || strings.TrimSpace(intent.TargetRevision) == "" ||
		strings.TrimSpace(intent.IdentityID) == "" || strings.TrimSpace(intent.RequiredAgentID) == "" {
		return false
	}
	for _, value := range []string{intent.TargetID, intent.TargetRevision, intent.IdentityID, intent.RequiredAgentID} {
		if strings.ContainsAny(value, "\r\n") {
			return false
		}
	}
	fp, err := hex.DecodeString(strings.TrimSpace(intent.ExpectedFingerprint))
	return err == nil && len(fp) == 32
}

func containmentForTarget(profile connector.LocalOpsConfig, targetID string) (connector.LocalContainment, bool) {
	for _, binding := range profile.Containments {
		if binding.TargetID == targetID {
			return binding, true
		}
	}
	return connector.LocalContainment{}, false
}

// executeContainment checks the live fingerprint immediately before the
// operator-pinned stop command. If another certificate is already serving, it
// never stops that healthy successor. Two post-action observations prevent a
// transient refusal from being mistaken for a durable stop. A graceful reload
// may leave an old worker serving briefly; preserve every bounded observation
// in the signed report while waiting for two consecutive refusals.
func executeContainment(ctx context.Context, intent ContainmentIntent, binding connector.LocalContainment,
	probe func() (transport.ProbeTranscript, error), stop func() error) (ContainmentReport, error) {
	return executeContainmentWithPolicy(ctx, intent, binding, probe, stop,
		containmentMaxPostStopProbes, containmentPostStopInterval)
}

func executeContainmentWithPolicy(ctx context.Context, intent ContainmentIntent, binding connector.LocalContainment,
	probe func() (transport.ProbeTranscript, error), stop func() error,
	maxProbes int, interval time.Duration) (ContainmentReport, error) {
	report := ContainmentReport{TargetID: intent.TargetID, TargetRevision: intent.TargetRevision,
		IdentityID: intent.IdentityID, ExpectedFingerprint: strings.ToLower(intent.ExpectedFingerprint),
		Action: binding.Action, After: []transport.ProbeTranscript{}}
	before, err := probe()
	if err != nil {
		return ContainmentReport{}, err
	}
	report.Before = before
	switch {
	case !before.Reached || before.ObservedFingerprint == "":
		report.State = ContainmentUnverified
		return report, nil
	case !strings.EqualFold(before.ObservedFingerprint, intent.ExpectedFingerprint):
		report.State = ContainmentDifferentLeaf
		return report, nil
	}
	stopErr := stop()
	consecutiveAbsence := 0
	differentLeaf := false
	for i := 0; i < maxProbes; i++ {
		if i != 0 {
			timer := time.NewTimer(interval)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ContainmentReport{}, ctx.Err()
			}
		}
		after, err := probe()
		if err != nil {
			return ContainmentReport{}, err
		}
		report.After = append(report.After, after)
		if after.Reached {
			consecutiveAbsence = 0
			if !strings.EqualFold(after.ObservedFingerprint, intent.ExpectedFingerprint) {
				differentLeaf = true
			}
		} else {
			consecutiveAbsence++
		}
		if consecutiveAbsence == 2 {
			break
		}
	}
	report.State = ContainmentFailed
	if stopErr == nil && consecutiveAbsence == 2 && !differentLeaf {
		report.State = ContainmentStopped
	}
	return report, nil
}
