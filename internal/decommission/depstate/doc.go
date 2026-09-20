// SPDX-License-Identifier: BUSL-1.1

// Package depstate defines the VDEC dependency-state event vocabulary and the
// deterministic replay projection used as the set-difference substrate for later
// decommissioning gates.
//
// Unknown event types and newer payload versions decode to Unknown and are skipped
// by the projection. Callers that need full-fidelity forwarding can carry Unknown.Raw
// alongside the folded state; malformed payloads for known versions fail closed.
package depstate
