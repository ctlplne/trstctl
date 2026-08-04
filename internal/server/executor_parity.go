// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/custody"
)

// The per-target parity gate: once a target is agent-executed, key bytes may
// never be sent to it (epic B2).
//
// B2's value is a negative property — private key bytes stop travelling from
// the control plane to the host — and a negative property is only worth
// anything if it cannot be silently violated. A migration that "prefers" the
// host-generated path but falls back to shipping a key when something is
// missing gives an estate that believes it moved and did not; the receipts, the
// custody column and the documentation would all say the key never left, and on
// some targets it would still be leaving.
//
// So the gate REFUSES rather than degrades. An operator marks a target
// agent-executed; from that moment a deploy for it that would carry key bytes
// is an error, loudly, rather than a quiet fallback to the legacy path.
//
// It is per target on purpose. A real estate migrates a few targets at a time,
// and a global switch would force an all-or-nothing cutover on exactly the
// systems least able to take one. Targets not marked keep working precisely as
// before — this adds no behaviour to them at all.

// The marker itself lives in internal/custody, imported by both this package and
// internal/api. It used to be defined in each, with a comment promising a guard
// test kept them aligned — a promise nothing kept. One definition cannot drift,
// which is a stronger guarantee than any test of two definitions.

// ErrCredentialBearingPathRefused is returned when a deploy would send key
// bytes to a target whose executor is an agent.
//
// A distinct error rather than a generic failure: an operator seeing this has
// mid-migration work to finish — the identity still has no CSR on record — and
// the message has to say that rather than reading as a transient fault they
// should retry.
var ErrCredentialBearingPathRefused = errors.New(
	"server: this deployment target is marked executor=agent, so the control plane will not " +
		"send private key material to it. The identity has no subject CSR on record, which means " +
		"its key is still control-plane generated; re-enroll the identity with a host-generated " +
		"CSR, or unset executor=agent on the target to return it to the legacy path")

// targetExecutorIsAgent reports whether an operator has marked this target's
// executor as an agent.
//
// Absent means no. A target whose config predates this feature must never
// change behaviour because a new version shipped, and the failure direction
// matters: defaulting to "agent" would refuse deploys across an entire estate
// on upgrade.
func targetExecutorIsAgent(cfg json.RawMessage) bool {
	return custody.TargetExecutorIsAgent(cfg)
}

// enforceExecutorParity refuses a credential-bearing deploy to an agent-executed
// target.
//
// Called at the one place the control plane still holds the unsealed payload
// and knows both the target and whether key bytes are present. Checking later —
// at seal time, or at redemption — would be too late in the useful sense: the
// bytes would already have been written into an outbox row and an append-only
// event, and the event log is permanent.
func enforceExecutorParity(targetConfig json.RawMessage, keyPEM []byte) error {
	if len(keyPEM) == 0 {
		// Nothing to leak. A certificate-only deploy is exactly what an
		// agent-executed target should receive.
		return nil
	}
	if !targetExecutorIsAgent(targetConfig) {
		return nil
	}
	return ErrCredentialBearingPathRefused
}
