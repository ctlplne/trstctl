// SPDX-License-Identifier: LicenseRef-trstctl-EE

package revoke

import (
	"context"
	"encoding/json"
	"fmt"

	agidstore "trstctl.com/trstctl/ee/agentid/delegation/store"
	"trstctl.com/trstctl/internal/eventspec"
)

// interval.go is the AGID-11 interval monitor (claim 23): the subject is expected to
// transition to the terminal revoked-with-evidence state within a POLICY-DEFINED INTERVAL
// of the directive being recorded; an EXCEEDANCE — the interval elapses without the
// terminal transition, or the transition landed later than the interval allows — is
// recorded as a DISTINCT ledger event (a projector can alert on it; it is not folded into
// the terminal state). The monitor uses an INJECTED clock so a test advances time
// deterministically past the interval to force an exceedance.
//
// The interval is measured from the directive's recorded start (created_at) to either the
// terminal_at timestamp (if terminal) or the current clock (if still draining). It is NOT
// a claim about credential usability (HARNESS.md §1.5 note (b)): it times the LEDGER fact
// of terminal completion, so an exceedance says "the kill has not been fully evidenced
// within the SLA," not "a credential is still usable." Cascade covers future
// issuance/renewal (refused in-signer); expiry covers the outstanding credential.

// TypeRevocationIntervalExceeded is the AN-2 event appended when a directive's terminal
// transition exceeds the policy-defined completion interval (claim 23). It is a DISTINCT
// event type (not the terminal event, not the effect event), so the exceedance is an
// independent ledger fact. A projector that does not know it skips it (forward-compatible).
const TypeRevocationIntervalExceeded = "agent.revocation.interval-exceeded"

// RevocationIntervalExceededSchemaV1 is the baseline payload-shape version for the event.
const RevocationIntervalExceededSchemaV1 = 1

// IntervalMonitor records interval exceedances for revocation directives (claim 23). It
// holds the AGID-02 repo (the directive timing read), the AN-2 log (the distinct
// exceedance event), the policy interval (seconds), and an injected clock (deterministic
// tests). It performs no key op and no mutation of the directive; it only appends the
// distinct exceedance event.
type IntervalMonitor struct {
	repo     *agidstore.Repo
	log      EventLog
	interval int64 // policy-defined completion interval, seconds
	clock    Clock
}

// NewIntervalMonitor builds the interval monitor over the AGID-02 repo, the AN-2 log, the
// policy interval (seconds, > 0), and an optional clock (defaults to Unix-0 for
// determinism; production injects a real clock). repo, log are required and interval must
// be positive (a non-positive interval would make every directive instantly exceed, which
// is a policy bug, not a monitor default).
func NewIntervalMonitor(repo *agidstore.Repo, log EventLog, intervalSeconds int64, opts ...IntervalOption) (*IntervalMonitor, error) {
	if repo == nil || log == nil {
		return nil, fmt.Errorf("revoke: NewIntervalMonitor requires repo and log")
	}
	if intervalSeconds <= 0 {
		return nil, fmt.Errorf("revoke: NewIntervalMonitor requires a positive interval (got %d)", intervalSeconds)
	}
	m := &IntervalMonitor{repo: repo, log: log, interval: intervalSeconds, clock: func() int64 { return 0 }}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

// IntervalOption configures an IntervalMonitor.
type IntervalOption func(*IntervalMonitor)

// WithIntervalClock injects the clock used to measure elapsed time for a still-draining
// directive (deterministic tests advance it past the interval).
func WithIntervalClock(clock Clock) IntervalOption {
	return func(m *IntervalMonitor) {
		if clock != nil {
			m.clock = clock
		}
	}
}

// IntervalExceededPayload is the distinct exceedance event body: the directive, the
// policy interval, the observed elapsed time, and whether the directive had reached
// terminal by the time the exceedance was recorded (a terminal-but-late transition vs. a
// still-draining overrun are both exceedances, distinguished here).
type IntervalExceededPayload struct {
	DirectiveID  string `json:"directive_id"`
	SubjectID    string `json:"subject_id"`
	IntervalSecs int64  `json:"interval_secs"`
	ElapsedSecs  int64  `json:"elapsed_secs"`
	TerminalWhen int64  `json:"terminal_when,omitempty"` // terminal_at if terminal, else 0
	WasTerminal  bool   `json:"was_terminal"`
}

// CheckResult reports the outcome of a Check: whether the directive exceeded its interval,
// the observed elapsed seconds, and whether THIS call recorded the distinct exceedance
// event (Recorded=false if it did not exceed, or if an exceedance was already recorded).
type CheckResult struct {
	DirectiveID string
	Exceeded    bool
	ElapsedSecs int64
	Recorded    bool
}

// Check evaluates one directive against the policy interval and, if the observed
// completion interval exceeds it, appends the DISTINCT exceedance event (claim 23),
// exactly once. Elapsed time is (terminal_at - created_at) when the directive is terminal,
// else (clock - created_at) while it is still draining. It appends the exceedance event
// only on a fresh exceedance: it first checks whether one already exists in the ledger for
// this directive (a prior Check recorded it), so repeated monitor passes do not duplicate
// the event. tenantID scopes every read/write by RLS.
func (m *IntervalMonitor) Check(ctx context.Context, tenantID, directiveID string) (CheckResult, error) {
	dir, found, err := m.repo.FetchRevocationDirective(ctx, tenantID, directiveID)
	if err != nil {
		return CheckResult{}, err
	}
	if !found {
		return CheckResult{}, fmt.Errorf("revoke: directive %q not found for interval check", directiveID)
	}
	timing, found, err := m.repo.FetchDirectiveTiming(ctx, tenantID, directiveID)
	if err != nil {
		return CheckResult{}, err
	}
	if !found {
		return CheckResult{}, fmt.Errorf("revoke: directive %q has no timing row", directiveID)
	}

	var elapsed int64
	if timing.Terminal && timing.TerminalAt > 0 {
		elapsed = timing.TerminalAt - timing.CreatedAt
	} else {
		elapsed = m.clock() - timing.CreatedAt
	}
	res := CheckResult{DirectiveID: directiveID, ElapsedSecs: elapsed}
	if elapsed <= m.interval {
		// Within the policy interval: no exceedance.
		return res, nil
	}
	res.Exceeded = true

	// Fresh-exceedance guard: append the distinct event only if one is not already in the
	// ledger for this directive (idempotent monitor passes).
	already, err := m.exceedanceRecorded(ctx, tenantID, directiveID)
	if err != nil {
		return CheckResult{}, err
	}
	if already {
		return res, nil
	}

	payload := IntervalExceededPayload{
		DirectiveID:  directiveID,
		SubjectID:    dir.SubjectID,
		IntervalSecs: m.interval,
		ElapsedSecs:  elapsed,
		TerminalWhen: timing.TerminalAt,
		WasTerminal:  timing.Terminal,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return CheckResult{}, fmt.Errorf("revoke: marshal interval-exceeded event: %w", err)
	}
	if _, err := m.log.Append(ctx, eventspec.Event{
		Type:          TypeRevocationIntervalExceeded,
		TenantID:      tenantID,
		SchemaVersion: RevocationIntervalExceededSchemaV1,
		Data:          data,
	}); err != nil {
		return CheckResult{}, fmt.Errorf("revoke: append interval-exceeded event: %w", err)
	}
	res.Recorded = true
	return res, nil
}

// exceedanceRecorded reports whether a distinct interval-exceeded event already exists in
// the ledger for (tenantID, directiveID). It replays the ledger and matches on the event
// type + directive id in the payload. This keeps the exceedance a single ledger fact per
// directive under repeated monitor passes (the event is the durable de-dup key, mirroring
// how the terminal flag guards the terminal event).
func (m *IntervalMonitor) exceedanceRecorded(ctx context.Context, tenantID, directiveID string) (bool, error) {
	found := false
	if err := m.log.Replay(ctx, 1, func(e eventspec.Event) error {
		if e.Type != TypeRevocationIntervalExceeded || e.TenantID != tenantID {
			return nil
		}
		var pl IntervalExceededPayload
		if err := json.Unmarshal(e.Data, &pl); err != nil {
			// A malformed prior event of this type is ignored for the de-dup decision
			// (it does not name a directive we can match); we do not fail the monitor on
			// someone else's bad payload.
			return nil
		}
		if pl.DirectiveID == directiveID {
			found = true
		}
		return nil
	}); err != nil {
		return false, fmt.Errorf("revoke: scan for prior interval exceedance: %w", err)
	}
	return found, nil
}
