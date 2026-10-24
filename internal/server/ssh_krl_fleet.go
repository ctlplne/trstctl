// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/agent/sshkrl"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/sshkrlreceipt"
)

// sshKRLReceiptStaleAfter is how long a host's receipt stays current without
// a newer heartbeat. A watcher's own check is stale after two of its polls and
// this margin.
const sshKRLReceiptStaleAfter = 10 * time.Minute

// SSHKRLFleet compares the served KRL with the newest signed receipt of each
// enrolled host agent that runs the KRL watcher (A109). Each receipt's
// installed digest was read back from that host's RevokedKeys file; the served
// digest is computed here from the bytes /ssh/krl serves.
func (s *Server) SSHKRLFleet(ctx context.Context, tenantID string) (api.SSHKRLFleet, error) {
	sp, err := s.sshWorkflowProtocol(tenantID)
	if err != nil {
		return api.SSHKRLFleet{}, err
	}
	if err := sp.syncRevocations(ctx, false); err != nil {
		return api.SSHKRLFleet{}, fmt.Errorf("%w: the revocation list cannot be brought up to date: %v", api.ErrSSHWorkflowUnavailable, err)
	}
	served := sp.KRLBytes()
	version, err := sshkrl.Version(served)
	if err != nil {
		return api.SSHKRLFleet{}, fmt.Errorf("%w: read the served KRL: %v", api.ErrSSHWorkflowUnavailable, err)
	}
	out := api.SSHKRLFleet{
		TenantID: tenantID, Hosts: []api.SSHKRLHost{},
		Served:            api.SSHKRLServed{KRLVersion: version, SHA256: crypto.SHA256Hex(served), RevokedCount: sp.RevokedCount()},
		StaleAfterSeconds: int64(sshKRLReceiptStaleAfter / time.Second),
	}
	if s.store == nil {
		return out, nil
	}
	rows, err := s.store.ListAgentSSHKRLReceipts(ctx, tenantID, 0)
	if err != nil {
		return api.SSHKRLFleet{}, err
	}
	now := time.Now().UTC()
	for _, row := range rows {
		var receipt sshkrlreceipt.Receipt
		if err := json.Unmarshal(row.Receipt, &receipt); err != nil {
			return api.SSHKRLFleet{}, fmt.Errorf("decode SSH KRL receipt of agent %s: %w", row.AgentID, err)
		}
		host := api.SSHKRLHost{
			AgentID: row.AgentID, Agent: row.AgentName, Outcome: receipt.Outcome,
			InstalledVersion: receipt.InstalledVersion, InstalledSHA256: receipt.InstalledSHA256,
			FetchedVersion: receipt.FetchedVersion, FetchedSHA256: receipt.FetchedSHA256,
			CheckedAt: time.Unix(receipt.CheckedAtUnix, 0).UTC(), PollEverySeconds: receipt.PollEverySeconds,
			ReportedAt: row.ReportedAt.UTC(), SignerFingerprint: row.SignerFingerprint,
		}
		if receipt.InstalledAtUnix > 0 {
			installed := time.Unix(receipt.InstalledAtUnix, 0).UTC()
			host.InstalledAt = &installed
		}
		if receipt.Outcome == sshkrlreceipt.OutcomeRefusedDropsRevocations {
			host.Dropped = &api.SSHKRLDropped{Serials: receipt.DroppedSerials, KeyIDs: receipt.DroppedKeyIDs,
				Keys: receipt.DroppedKeys, KeyHashes: receipt.DroppedKeyHashes}
		}
		host.State = sshKRLHostState(host, out.Served.SHA256, now)
		out.Hosts = append(out.Hosts, host)
		out.Summary.Hosts++
		switch host.State {
		case api.SSHKRLHostCurrent:
			out.Summary.Current++
		case api.SSHKRLHostBehind:
			out.Summary.Behind++
		case api.SSHKRLHostRefusing:
			out.Summary.Refusing++
		case api.SSHKRLHostFailing:
			out.Summary.Failing++
		case api.SSHKRLHostStale:
			out.Summary.Stale++
		}
	}
	return out, nil
}

// sshKRLHostState places one receipt against the served list. A host that
// stopped reporting or checking is stale whatever it last said; otherwise a
// refusal or failure is named before the digest comparison, because the host
// keeps an older list in both cases.
func sshKRLHostState(host api.SSHKRLHost, servedSHA256 string, now time.Time) string {
	checkWindow := 2*time.Duration(host.PollEverySeconds)*time.Second + sshKRLReceiptStaleAfter
	switch {
	case now.Sub(host.ReportedAt) > sshKRLReceiptStaleAfter || now.Sub(host.CheckedAt) > checkWindow:
		return api.SSHKRLHostStale
	case host.Outcome == sshkrlreceipt.OutcomeRefusedNotNewer || host.Outcome == sshkrlreceipt.OutcomeRefusedDropsRevocations:
		return api.SSHKRLHostRefusing
	case host.Outcome == sshkrlreceipt.OutcomeFetchFailed || host.Outcome == sshkrlreceipt.OutcomeApplyFailed:
		return api.SSHKRLHostFailing
	case host.InstalledSHA256 == servedSHA256:
		return api.SSHKRLHostCurrent
	default:
		return api.SSHKRLHostBehind
	}
}
