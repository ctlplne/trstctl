// SPDX-License-Identifier: BUSL-1.1

// Package rehearsal holds the rules of a failure-scenario rehearsal (A247):
// the scenario kinds and their default steps, the four modes a run replays in,
// how a run is labeled, what keeps a replay away from production, and how
// observations are compared with expected effects. It is pure: the server
// gathers observations and the store keeps the record.
package rehearsal

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// Kind is the failure a scenario rehearses.
type Kind string

const (
	KindApprovalResumption Kind = "approval_resumption"
	KindTargetOutage       Kind = "target_outage"
	KindRenewalFailure     Kind = "renewal_failure"
	KindRevokedCredential  Kind = "revoked_credential" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	KindStalePolicy        Kind = "stale_policy"
	KindRestore            Kind = "restore"
	KindRetry              Kind = "retry"
)

// Kinds lists every kind, in a fixed order.
func Kinds() []Kind {
	return []Kind{KindApprovalResumption, KindTargetOutage, KindRenewalFailure, KindRevokedCredential,
		KindStalePolicy, KindRestore, KindRetry}
}

// Mode is how a run replays a scenario. The four are kept apart: what a
// preview or a mock shows is never presented as what production did.
type Mode string

const (
	// ModeStaticPreview evaluates the scenario against the configuration
	// without running anything.
	ModeStaticPreview Mode = "static_preview"
	// ModeMockedRehearsal runs the steps against the product's documented
	// behavior with nothing real behind them.
	ModeMockedRehearsal Mode = "mocked_rehearsal"
	// ModeSandboxExecution runs the steps for real against non-production
	// targets with generated credentials.
	ModeSandboxExecution Mode = "sandbox_execution"
	// ModeLiveObservation runs nothing: it reads what production recorded.
	ModeLiveObservation Mode = "live_observation"
)

// Source is where one observation came from.
type Source string

const (
	SourcePreview        Source = "preview"
	SourceMock           Source = "mock"
	SourceSandboxReceipt Source = "sandbox_receipt"
	SourceLiveReceipt    Source = "live_receipt"
)

// sourceFor is the one source each mode may record.
var sourceFor = map[Mode]Source{
	ModeStaticPreview:    SourcePreview,
	ModeMockedRehearsal:  SourceMock,
	ModeSandboxExecution: SourceSandboxReceipt,
	ModeLiveObservation:  SourceLiveReceipt,
}

// Candidate is what a scenario tests: a profile, connector, policy, issuer,
// identity or binary, at a revision.
type Candidate struct {
	Kind     string `json:"kind"`
	Ref      string `json:"ref"`
	Revision string `json:"revision,omitempty"`
}

// DataSet is what a scenario replays over: named identities, or a scrubbed
// failure. SecretRefs are the secret-store names it would read; a sandbox
// replay refuses any.
type DataSet struct {
	Kind        string           `json:"kind"`
	IdentityIDs []string         `json:"identity_ids,omitempty"`
	Failure     *ScrubbedFailure `json:"failure,omitempty"`
	SecretRefs  []string         `json:"secret_refs,omitempty"`
}

// ScrubbedFailure is a recorded failure reduced to what a replay needs: where
// it was recorded, the record's identifier, the step that failed and its
// classified code. Values — secrets, subjects, request bodies — have no field
// to travel in.
type ScrubbedFailure struct {
	Source string `json:"source"`
	Ref    string `json:"ref"`
	Step   string `json:"step,omitempty"`
	Code   string `json:"code,omitempty"`
}

// Step is one action, the deployment target it acts on (if any) and the effect
// it should have.
type Step struct {
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Expect string `json:"expect"`
}

// Observation is what one step was seen to do.
type Observation struct {
	Step    int    `json:"step"`
	Effect  string `json:"effect"`
	Source  Source `json:"source"`
	Receipt string `json:"receipt,omitempty"`
}

// Verdict is a run's comparison of observations with expectations.
type Verdict string

const (
	VerdictMatched  Verdict = "matched"
	VerdictDiverged Verdict = "diverged"
	VerdictBlocked  Verdict = "blocked"
)

// Templates are each kind's default steps, written as the product behaves.
var templates = map[Kind][]Step{
	KindApprovalResumption: {
		{Action: "request_issuance", Expect: "awaiting_approval"},
		{Action: "approve", Expect: "issued"},
	},
	KindTargetOutage: {
		{Action: "deliver_to_unreachable_target", Expect: "retried_with_backoff"},
		{Action: "exhaust_retries", Expect: "dead_lettered_and_alerted"},
	},
	KindRenewalFailure: {
		{Action: "renew_with_failing_issuer", Expect: "renewal_failed_and_alerted"},
		{Action: "retry_renewal", Expect: "renewed_before_expiry"},
	},
	KindRevokedCredential: {
		{Action: "revoke", Expect: "revocation_published"},
		{Action: "present_revoked_credential", Expect: "refused"},
	},
	KindStalePolicy: {
		{Action: "issue_under_superseded_policy", Expect: "refused_by_policy"},
	},
	KindRestore: {
		{Action: "restore_backup_into_isolated_target", Expect: "restored_and_read_back"},
	},
	KindRetry: {
		{Action: "repeat_request_with_same_key", Expect: "one_effect"},
	},
}

// Template returns a kind's default steps.
func Template(kind Kind) ([]Step, bool) {
	steps, ok := templates[kind]
	return append([]Step(nil), steps...), ok
}

// Label is a run's public label. It is the mode's own word; "live" is
// reserved for a live observation whose every observation is a live receipt.
// A mocked success reads "mocked: matched", never "live".
func Label(mode Mode, verdict Verdict, observations []Observation) string {
	word := map[Mode]string{
		ModeStaticPreview: "preview", ModeMockedRehearsal: "mocked",
		ModeSandboxExecution: "sandbox", ModeLiveObservation: "live",
	}[mode]
	if word == "" {
		return "unknown: " + string(verdict)
	}
	if mode == ModeLiveObservation {
		for _, o := range observations {
			if o.Source != SourceLiveReceipt {
				return "unverified: " + string(verdict)
			}
		}
	}
	return word + ": " + string(verdict)
}

// ErrUnsafeReplay is a sandbox replay that could reach production or reuse
// a production secret.
var ErrUnsafeReplay = errors.New("rehearsal: a sandbox replay cannot reach production or reuse production secrets")

// nonProduction mirrors the game-day allowlist of environment names
// (migration.nonProductionEnvironment).
func nonProduction(environment string) bool {
	switch strings.ToLower(strings.TrimSpace(environment)) {
	case "test", "testing", "qa", "quality-assurance", "staging", "stage", "development", "dev", "sandbox",
		"game-day", "game_day", "non-production", "non_production", "nonproduction":
		return true
	}
	return false
}

// Environments resolves the recorded environment of a deployment target and
// of an identity, from the product's own records (the target's configuration,
// the identity owner's application model) — never from the scenario.
type Environments struct {
	Target   func(id string) (string, error)
	Identity func(id string) (string, error)
}

// Guard refuses a sandbox replay that would act on a target or identity whose
// recorded environment is not on the non-production allowlist (an unknown
// environment is refused too), or whose data set would read stored secrets.
// The other modes run nothing real and pass.
func Guard(mode Mode, steps []Step, data DataSet, env Environments) error {
	if mode != ModeSandboxExecution {
		return nil
	}
	if len(data.SecretRefs) > 0 {
		return fmt.Errorf("%w: the data set names %d stored secret(s); a sandbox replay uses generated credentials", ErrUnsafeReplay, len(data.SecretRefs))
	}
	for i, s := range steps {
		if s.Target == "" {
			continue
		}
		environment, err := env.Target(s.Target)
		if err != nil {
			return fmt.Errorf("%w: step %d targets %s, whose environment cannot be read: %v", ErrUnsafeReplay, i+1, s.Target, err)
		}
		if !nonProduction(environment) {
			return fmt.Errorf("%w: step %d targets %s, whose environment %q is not non-production", ErrUnsafeReplay, i+1, s.Target, environment)
		}
	}
	for _, id := range data.IdentityIDs {
		environment, err := env.Identity(id)
		if err != nil {
			return fmt.Errorf("%w: identity %s's environment cannot be read: %v", ErrUnsafeReplay, id, err)
		}
		if !nonProduction(environment) {
			return fmt.Errorf("%w: identity %s's environment %q is not non-production", ErrUnsafeReplay, id, environment)
		}
	}
	return nil
}

// Compare checks observations against the steps' expected effects. A step
// with no observation, or an observation from a source its mode may not
// record, is a divergence.
func Compare(mode Mode, steps []Step, observations []Observation) (Verdict, string) {
	want := sourceFor[mode]
	seen := map[int]Observation{}
	for _, o := range observations {
		seen[o.Step] = o
	}
	var diverged []string
	for i, s := range steps {
		o, ok := seen[i+1]
		switch {
		case !ok:
			diverged = append(diverged, fmt.Sprintf("step %d (%s) was not observed", i+1, s.Action))
		case o.Source != want:
			diverged = append(diverged, fmt.Sprintf("step %d was observed from %s, which a %s run does not record", i+1, o.Source, mode))
		case o.Effect != s.Expect:
			diverged = append(diverged, fmt.Sprintf("step %d (%s) expected %s, observed %s", i+1, s.Action, s.Expect, o.Effect))
		}
	}
	if len(diverged) > 0 {
		return VerdictDiverged, strings.Join(diverged, "; ")
	}
	return VerdictMatched, fmt.Sprintf("every one of %d steps had its expected effect", len(steps))
}

// DataSetDigest identifies a data set by the SHA-256 of its canonical JSON.
func DataSetDigest(data DataSet) (string, error) {
	ids := append([]string(nil), data.IdentityIDs...)
	sort.Strings(ids)
	refs := append([]string(nil), data.SecretRefs...)
	sort.Strings(refs)
	data.IdentityIDs, data.SecretRefs = ids, refs
	raw, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return "sha256:" + crypto.SHA256Hex(raw), nil
}

// Mock observes what the product is documented to do for each step: the
// effect its kind's template gives the action. A step whose action no
// template knows is not observed, and an expectation that differs from the
// documented effect diverges — a mocked rehearsal checks the scenario, not
// production.
func Mock(steps []Step) []Observation {
	documented := documentedEffects()
	out := []Observation{}
	for i, s := range steps {
		if effect, ok := documented[s.Action]; ok {
			out = append(out, Observation{Step: i + 1, Effect: effect, Source: SourceMock})
		}
	}
	return out
}

// Preview evaluates steps against the configuration without running them:
// a step whose references resolve is observed to have its documented effect,
// and one whose references do not is observed as unresolved.
func Preview(steps []Step, resolve func(Step) error) []Observation {
	documented := documentedEffects()
	out := []Observation{}
	for i, s := range steps {
		effect, known := documented[s.Action]
		if err := resolve(s); err != nil {
			effect = "unresolved: " + err.Error()
		} else if !known {
			continue
		}
		out = append(out, Observation{Step: i + 1, Effect: effect, Source: SourcePreview})
	}
	return out
}

// documentedEffects maps each template action to the effect the product is
// documented to have.
func documentedEffects() map[string]string {
	documented := map[string]string{}
	for _, kind := range Kinds() {
		for _, s := range templates[kind] {
			documented[s.Action] = s.Expect
		}
	}
	return documented
}
