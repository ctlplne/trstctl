// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/agent/verify"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// KindEndpointRecoveryCheck is the read-only question a replacement preview
// cannot answer from the control plane (A210): after containment stopped a
// listener, does this host's operator-owned profile pin an action that brings
// it back, and what is the listener doing now? The agent reports digests of
// the pinned action, never its path or content, and one local TLS probe.
const KindEndpointRecoveryCheck = "endpoint.recovery_check"

// RecoveryCheckIntent names the exact target and the leaves the listener must
// not serve again. CheckID ties the signed answer to the request that asked.
type RecoveryCheckIntent struct {
	CheckID             string   `json:"check_id"`
	TargetID            string   `json:"target_id"`
	TargetRevision      string   `json:"target_revision"`
	RequiredAgentID     string   `json:"required_agent_id"`
	RevokedFingerprints []string `json:"revoked_fingerprints,omitempty"`
}

// What the host's profile says about the target's recovery.
const (
	RecoveryCheckNoBinding        = "no_binding"
	RecoveryCheckNoRecoveryAction = "no_recovery_action"
	RecoveryCheckPinned           = "pinned"
)

// What the local listener is doing.
const (
	RecoveryListenerNone          = "none"
	RecoveryListenerStopped       = "stopped"
	RecoveryListenerServing       = "serving"
	RecoveryListenerServingRevoke = "serving_revoked"
	RecoveryListenerUnverified    = "unverified"
)

// maxRecoveryExecutableBytes bounds the executable the check hashes.
const maxRecoveryExecutableBytes = 256 << 20

// RecoveryCheckReport is the agent's signed answer. It carries digests of the
// pinned recovery action, never its path, arguments or content.
type RecoveryCheckReport struct {
	TargetID         string                     `json:"target_id"`
	TargetRevision   string                     `json:"target_revision"`
	Recovery         string                     `json:"recovery"`
	RecoveryAction   string                     `json:"recovery_action,omitempty"`
	ExecutableSHA256 string                     `json:"executable_sha256,omitempty"`
	ArgvSHA256       string                     `json:"argv_sha256,omitempty"`
	Listener         string                     `json:"listener"`
	Probe            *transport.ProbeTranscript `json:"probe,omitempty"`
}

// Ready reports whether the host can bring the listener back without serving
// a revoked leaf: a pinned recovery action exists and the listener is either
// stopped or serving a leaf that was not revoked.
func (r RecoveryCheckReport) Ready() bool {
	return r.Recovery == RecoveryCheckPinned &&
		(r.Listener == RecoveryListenerStopped || r.Listener == RecoveryListenerServing)
}

// Digest binds the report to the signed job receipt.
func (r RecoveryCheckReport) Digest() string {
	var raw []byte
	for _, part := range []string{"trstctl-recovery-check/v1", r.TargetID, r.TargetRevision, r.Recovery, r.RecoveryAction,
		r.ExecutableSHA256, r.ArgvSHA256, r.Listener} {
		raw = append(raw, part...)
		raw = append(raw, '\n')
	}
	if r.Probe != nil {
		raw = append(raw, r.Probe.Canonical()...)
	}
	return transport.SweepDigest(raw)
}

// ValidateRecoveryCheckReport is also used by the receiver: the report must
// describe the queued target and a consistent state.
func ValidateRecoveryCheckReport(intent RecoveryCheckIntent, report RecoveryCheckReport, digest string) error {
	if !validRecoveryCheckIntent(intent) || report.TargetID != intent.TargetID || report.TargetRevision != intent.TargetRevision {
		return errors.New("recovery check report does not match the queued target")
	}
	switch report.Recovery {
	case RecoveryCheckNoBinding:
		if report.Listener != RecoveryListenerNone || report.Probe != nil || report.RecoveryAction != "" {
			return errors.New("a recovery check without a binding claims a listener or action")
		}
	case RecoveryCheckNoRecoveryAction, RecoveryCheckPinned:
		if report.Probe == nil {
			return errors.New("a recovery check of a bound target has no listener probe")
		}
		if err := report.Probe.Validate(); err != nil {
			return err
		}
		if report.Probe.Vantage != transport.VantageLocal {
			return errors.New("a recovery check probe is not local")
		}
		if report.Recovery == RecoveryCheckPinned && (report.RecoveryAction == "" || !sha256Hex(report.ExecutableSHA256) || !sha256Hex(report.ArgvSHA256)) {
			return errors.New("a pinned recovery action lacks its name or digests")
		}
		if report.Recovery == RecoveryCheckNoRecoveryAction && (report.RecoveryAction != "" || report.ExecutableSHA256 != "") {
			return errors.New("a missing recovery action carries digests")
		}
		want := recoveryListener(*report.Probe, intent.RevokedFingerprints)
		if report.Listener != want {
			return errors.New("the recovery check's listener state does not follow its probe")
		}
	default:
		return errors.New("recovery check report has unknown state")
	}
	if report.Digest() != digest {
		return errors.New("recovery check report digest does not match the signed receipt")
	}
	return nil
}

func runRecoveryCheck(ctx context.Context, ch Channel, profile connector.LocalOpsConfig, job Job) bool {
	var intent RecoveryCheckIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil || !validRecoveryCheckIntent(intent) {
		report(ctx, ch, job, OutcomeFailed, "recovery check intent is invalid")
		return false
	}
	out, failure := checkRecovery(intent, profile, func(binding connector.LocalContainment) (transport.ProbeTranscript, error) {
		observed, err := verify.Endpoint(ctx, verify.Request{
			Address: binding.Address, ServerName: binding.ServerName, Vantage: transport.VantageLocal,
			Timeout: verify.DefaultTimeout, NativeProbeExecutable: profile.TLSProbeOpenSSL,
			Expect: certinfo.Expectation{},
		})
		return observed.Transcript, err
	})
	if failure != "" {
		report(ctx, ch, job, OutcomeFailed, failure)
		return false
	}
	return reportRecoveryCheck(ctx, ch, job, out)
}

// checkRecovery answers a recovery check from the host profile and one probe
// of the bound listener. A non-empty failure is the closed reason the host
// reports instead of an answer.
func checkRecovery(intent RecoveryCheckIntent, profile connector.LocalOpsConfig,
	probe func(connector.LocalContainment) (transport.ProbeTranscript, error)) (RecoveryCheckReport, string) {
	out := RecoveryCheckReport{TargetID: intent.TargetID, TargetRevision: intent.TargetRevision}
	binding, found := containmentForTarget(profile, intent.TargetID)
	if !found {
		out.Recovery, out.Listener = RecoveryCheckNoBinding, RecoveryListenerNone
		return out, ""
	}
	out.Recovery = RecoveryCheckNoRecoveryAction
	if name := strings.TrimSpace(binding.RecoveryAction); name != "" {
		action, ok := profileAction(profile, name)
		if !ok {
			return RecoveryCheckReport{}, "host profile's recovery action is not one of its actions"
		}
		executable, err := hashExecutable(filepath.Clean(strings.TrimSpace(action.Command)))
		if err != nil {
			return RecoveryCheckReport{}, "host profile's recovery executable could not be read"
		}
		out.Recovery, out.RecoveryAction = RecoveryCheckPinned, name
		out.ExecutableSHA256, out.ArgvSHA256 = executable, pinnedCommandDigest(action)
	}
	observed, err := probe(binding)
	if err != nil {
		return RecoveryCheckReport{}, "recovery check probe could not run"
	}
	out.Probe = &observed
	out.Listener = recoveryListener(observed, intent.RevokedFingerprints)
	return out, ""
}

func reportRecoveryCheck(ctx context.Context, ch Channel, job Job, out RecoveryCheckReport) bool {
	encoded, err := json.Marshal(out)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "recovery check report could not be encoded")
		return false
	}
	reportWithEvidence(ctx, ch, job, OutcomeExecuted, string(encoded), out.Digest())
	return true
}

// recoveryListener classifies one local probe: no TLS listener answering is
// stopped; a leaf is serving, or serving_revoked when it is one of the
// revoked leaves; a probe that reached nothing it could read is unverified.
func recoveryListener(probe transport.ProbeTranscript, revoked []string) string {
	switch {
	case !probe.Reached:
		return RecoveryListenerStopped
	case probe.ObservedFingerprint == "":
		return RecoveryListenerUnverified
	}
	for _, fp := range revoked {
		if strings.EqualFold(strings.TrimSpace(fp), probe.ObservedFingerprint) {
			return RecoveryListenerServingRevoke
		}
	}
	return RecoveryListenerServing
}

// pinnedCommandDigest commits to everything the profile pins about how the
// action runs: its executable path, its fixed arguments, the connector
// arguments it accepts and whether it passes them on.
func pinnedCommandDigest(action connector.LocalAction) string {
	logical := "*"
	if action.LogicalArgs != nil {
		logical = strings.Join(action.LogicalArgs, "\x1f")
	}
	return crypto.SHA256Hex([]byte(strings.Join([]string{
		"trstctl-pinned-command/v1", action.Command, strings.Join(action.Args, "\x1f"),
		logical, strconv.FormatBool(action.PassArgs),
	}, "\x00")))
}

// HostDeployActionNames lists the logical actions a host connector runs while
// it deploys to a target with this configuration. A recovery action outside
// the list is pinned but never run by a replacement deploy.
func HostDeployActionNames(connectorName string, targetConfig json.RawMessage) ([]string, error) {
	var target HostTargetConfig
	if len(targetConfig) > 0 {
		if err := json.Unmarshal(targetConfig, &target); err != nil {
			return nil, err
		}
	}
	actions, err := hostPreflightActions(connectorName, target)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(actions))
	for _, action := range actions {
		if !slices.Contains(names, action.LogicalName) {
			names = append(names, action.LogicalName)
		}
	}
	return names, nil
}

func profileAction(profile connector.LocalOpsConfig, name string) (connector.LocalAction, bool) {
	for _, action := range profile.Actions {
		if strings.TrimSpace(action.LogicalName) == name {
			return action, true
		}
	}
	return connector.LocalAction{}, false
}

// hashExecutable is the SHA-256 of the regular, non-symlink file the action
// runs, the same file checks LocalOps applies before it runs a command.
func hashExecutable(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("relay: recovery executable is not a regular file")
	}
	file, err := os.Open(path) // #nosec G304 -- the host operator's own pinned executable from the host profile (CWE-22)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	digest, _, err := crypto.SHA256ReaderHex(io.LimitReader(file, maxRecoveryExecutableBytes))
	return digest, err
}

func validRecoveryCheckIntent(intent RecoveryCheckIntent) bool {
	for _, value := range []string{intent.CheckID, intent.TargetID, intent.TargetRevision, intent.RequiredAgentID} {
		if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n") {
			return false
		}
	}
	for _, fp := range intent.RevokedFingerprints {
		if !sha256Hex(fp) {
			return false
		}
	}
	return len(intent.RevokedFingerprints) <= 16
}

func sha256Hex(value string) bool {
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	return err == nil && len(decoded) == 32
}
