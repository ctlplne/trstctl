// SPDX-License-Identifier: MPL-2.0

package doctor

import (
	"context"
	"fmt"
	"os"
	"time"

	"trstctl.com/trstctl/internal/store"
)

const (
	groupSigner     = "signer-isolation (AN-4)"
	groupEvents     = "event-integrity (AN-2)"
	groupDurability = "durability-backpressure (AN-5/6/7)"
	groupPosture    = "deployment-posture"
)

// stalledLaneThreshold is how old the oldest undelivered outbox row in a lane
// may be before DUR-2 warns. Delivery is at-least-once with retry/backoff, so
// age — not depth — is the stall signal.
const stalledLaneThreshold = 15 * time.Minute

func runOpsProbes(ctx context.Context, s *store.Store, opts options) []Probe {
	var out []Probe

	// DUR-2: per-lane oldest-undelivered age over the outbox.
	//trstctl:system-query — cross-tenant by design: the outbox stall sweep aggregates min(created_at) per delivery lane across all tenants, the same whole-system view the dispatcher itself has; it reads lane ages, never payloads, and reports no tenant_id.
	rows, err := s.SystemPool().Query(ctx, `
		SELECT COALESCE(NULLIF(effect_lane, ''), destination) AS lane, min(created_at)
		FROM outbox
		WHERE status <> 'delivered'
		GROUP BY 1
		ORDER BY 2`)
	if err != nil {
		out = append(out, Probe{ID: "DUR-2", Group: groupDurability, Status: StatusFail,
			Detail: "could not sweep outbox lanes: " + err.Error()})
	} else {
		defer rows.Close()
		now := opts.now().UTC()
		stalled := map[string]string{}
		lanes := 0
		for rows.Next() {
			var lane string
			var oldest time.Time
			if err := rows.Scan(&lane, &oldest); err != nil {
				out = append(out, Probe{ID: "DUR-2", Group: groupDurability, Status: StatusFail, Detail: "scan outbox lanes: " + err.Error()})
				stalled = nil
				lanes = -1
				break
			}
			lanes++
			if age := now.Sub(oldest); age > stalledLaneThreshold {
				stalled[lane] = age.Truncate(time.Second).String()
			}
		}
		switch {
		case lanes < 0:
			// scan error already reported
		case len(stalled) > 0:
			out = append(out, Probe{ID: "DUR-2", Group: groupDurability, Status: StatusWarn,
				Detail:   fmt.Sprintf("%d outbox lane(s) have undelivered work older than %s: %v", len(stalled), stalledLaneThreshold, stalled),
				Evidence: map[string]any{"lanes_with_backlog": lanes}})
		default:
			out = append(out, Probe{ID: "DUR-2", Group: groupDurability, Status: StatusPass,
				Detail:   fmt.Sprintf("no outbox lane holds undelivered work older than %s (%d lane(s) with any backlog)", stalledLaneThreshold, lanes),
				Limits:   "an age sweep at one instant; sustained delivery health is the outbox dead-letter runbook's concern",
				Evidence: map[string]any{"lanes_with_backlog": lanes}})
		}
	}

	// POSTURE-1: RLS-relevant server settings.
	var rowSecurity, version string
	//trstctl:system-query — cross-tenant by design: reads only the server's row_security setting and version string to report deployment posture; no tenant rows and no tenant_id are involved in a SHOW-style catalog read.
	if err := s.SystemPool().QueryRow(ctx, `SELECT current_setting('row_security'), version()`).Scan(&rowSecurity, &version); err != nil {
		out = append(out, Probe{ID: "POSTURE-1", Group: groupPosture, Status: StatusFail,
			Detail: "could not read server posture: " + err.Error()})
	} else if rowSecurity != "on" {
		out = append(out, Probe{ID: "POSTURE-1", Group: groupPosture, Status: StatusFail,
			Detail: fmt.Sprintf("row_security is %q; the deployment must run with row_security=on", rowSecurity)})
	} else {
		out = append(out, Probe{ID: "POSTURE-1", Group: groupPosture, Status: StatusPass,
			Detail:   "row_security=on",
			Evidence: map[string]any{"server_version": version}})
	}

	// SIG-2: signer socket posture, when the operator points doctor at it.
	if opts.signerSocket == "" {
		out = append(out, Probe{ID: "SIG-2", Group: groupSigner, Status: StatusSkip,
			Detail: "no --signer-socket given; socket posture not probed"})
	} else if st, err := os.Stat(opts.signerSocket); err != nil {
		out = append(out, Probe{ID: "SIG-2", Group: groupSigner, Status: StatusFail,
			Detail: "signer socket not reachable: " + err.Error()})
	} else if st.Mode()&os.ModeSocket == 0 {
		out = append(out, Probe{ID: "SIG-2", Group: groupSigner, Status: StatusFail,
			Detail: fmt.Sprintf("%s exists but is not a Unix domain socket (mode %v)", opts.signerSocket, st.Mode())})
	} else if perm := st.Mode().Perm(); perm&0o077 != 0 {
		out = append(out, Probe{ID: "SIG-2", Group: groupSigner, Status: StatusFail,
			Detail: fmt.Sprintf("signer socket %s is group/world-accessible (%#o); only the owner may reach the signer", opts.signerSocket, perm)})
	} else {
		out = append(out, Probe{ID: "SIG-2", Group: groupSigner, Status: StatusPass,
			Detail: fmt.Sprintf("signer reached over a Unix domain socket with owner-only mode %#o", st.Mode().Perm()),
			Limits: "proves the transport posture, not the signer's dependency closure"})
	}

	// The remaining probes need surfaces this seat cannot honestly reach; a
	// skipped proof must never look like a passed one, so each says why.
	skips := []Probe{
		{ID: "SIG-1", Group: groupSigner, Status: StatusSkip,
			Detail: "the signer health RPC intentionally reports only serving status, not a PID; separate-process proof stays with the AN-4 dependency-closure gate in CI"},
		{ID: "SIG-3", Group: groupSigner, Status: StatusSkip,
			Detail: "no dependency-closure fingerprint is compiled into the signer binary yet; until one exists, AN-4's closure proof is CI-only (cmd/trstctl-signer/core_boundary_test.go)"},
		{ID: "SIG-4", Group: groupSigner, Status: StatusSkip,
			Detail: "key-custody proof requires the signer API surface, which this datastore-side probe does not hold credentials for"},
		{ID: "EVT-1", Group: groupEvents, Status: StatusSkip,
			Detail: "audit hash-chain verification replays the event log over NATS; doctor's datastore seat has no log credentials — run the served audit export verification instead"},
		{ID: "EVT-2", Group: groupEvents, Status: StatusSkip,
			Detail: "projection-lag comparison needs the event stream head from NATS, which this seat does not hold"},
		{ID: "EVT-3", Group: groupEvents, Status: StatusSkip,
			Detail: "read-model row sampling against source events needs the event stream, which this seat does not hold"},
		{ID: "DUR-1", Group: groupDurability, Status: StatusSkip,
			Detail: "idempotency replay is exercised end-to-end against the HTTP API; doctor's datastore seat holds no API token"},
		{ID: "DUR-3", Group: groupDurability, Status: StatusSkip,
			Detail: "bulkhead capacities live in the serving process; query GET /api/v1/operations/bulkheads on the running control plane"},
		{ID: "DUR-4", Group: groupDurability, Status: StatusSkip,
			Detail: "dispatcher-family inventory lives in the serving process, not the datastore"},
	}
	return append(out, skips...)
}
