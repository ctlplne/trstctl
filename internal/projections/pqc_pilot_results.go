// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/store"

// storePQCPilotResults maps a pilot wave's event results to the read model,
// with each target's observed-traffic evidence when the gate has closed
// (X3-L5).
func storePQCPilotResults(in []PQCPilotResult) []store.PQCPilotResult {
	out := make([]store.PQCPilotResult, 0, len(in))
	for _, r := range in {
		res := store.PQCPilotResult{TargetID: r.TargetID, Outcome: r.Outcome, HandshakeMillis: r.HandshakeMillis,
			ChainBytes: r.ChainBytes, Detail: r.Detail, EvidenceDigest: r.EvidenceDigest, ObservedAt: r.ObservedAt}
		if t := r.Traffic; t != nil {
			res.Traffic = &store.PQCPilotTraffic{Outcome: t.Outcome, FindingID: t.FindingID, Server: t.Server,
				TLSVersion: t.TLSVersion, Group: t.Group, PQHybrid: t.PQHybrid, LastSeen: t.LastSeen}
		}
		out = append(out, res)
	}
	return out
}

func storePQCPilotVerdict(v PQCPilotVerdict) store.PQCPilotVerdict {
	return store.PQCPilotVerdict{Ready: v.Ready, Halt: v.Halt, Summary: v.Summary, Negotiated: v.Negotiated,
		Rejected: v.Rejected, Unreachable: v.Unreachable, NotAttempted: v.NotAttempted,
		AwaitingTraffic: v.AwaitingTraffic, Unobserved: v.Unobserved}
}
