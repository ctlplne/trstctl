// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"syscall"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/sshcollection"
)

const KindSSHTrustCollect = sshcollection.Destination

// collectSSHTrust uses a bounded pool and a bounded lifetime for borrowed keys.
// Each socket must pass both source reserved-range policy and local relay egress.
func collectSSHTrust(ctx context.Context, command sshcollection.Command, material Material) sshcollection.Report {
	digest, _ := command.Digest()
	result := sshcollection.Report{CommandDigest: digest, Results: make([]sshcollection.Observation, len(command.Hosts))}
	for i, h := range command.Hosts {
		result.Results[i] = sshcollection.Observation{Address: h.Address, Status: "cancelled"}
	}
	bounded, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	control := egressControl(func(_ string, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return netsec.ErrSSRFBlocked
		}
		ip := net.ParseIP(host)
		if command.AllowLoopback && ip != nil && ip.IsLoopback() {
			return nil
		}
		if netsec.BlockedIPWithOptions(ip, netsec.BlockedIPOptions{AllowRFC1918: command.AllowRFC1918}) {
			return netsec.ErrSSRFBlocked
		}
		return nil
	})
	remaining := map[string]int{}
	for _, host := range command.Hosts {
		remaining[host.CredentialRef]++
	}
	var authentication sync.Mutex
	done := func(ref string) {
		authentication.Lock()
		defer authentication.Unlock()
		remaining[ref]--
		if remaining[ref] == 0 {
			secret.Wipe(material[ref])
		}
	}
	tasks := make(chan int)
	var workers sync.WaitGroup
	for range min(8, len(command.Hosts)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range tasks {
				h := command.Hosts[index]
				raw, err := crypto.ReadSSHCollection(bounded, crypto.SSHCollectionConnection{Address: h.Address, Username: h.Username, HostKeyFingerprint: h.HostKeyFingerprint, DialControl: control, AuthenticationDone: func() { done(h.CredentialRef) }}, material[h.CredentialRef])
				if err != nil {
					result.Results[index].Status = "connection_or_auth_failed"
					continue
				}
				snapshot, err := sshcollection.DecodeSnapshot(raw)
				secret.Wipe(raw)
				if err != nil {
					result.Results[index].Status = "invalid_snapshot"
					continue
				}
				result.Results[index].Status = "observed"
				result.Results[index].Snapshot = &snapshot
			}
		}()
	}
enqueue:
	for index := range command.Hosts {
		select {
		case tasks <- index:
		case <-bounded.Done():
			for _, host := range command.Hosts[index:] {
				done(host.CredentialRef)
			}
			break enqueue
		}
	}
	close(tasks)
	workers.Wait()
	// Preserve every target outcome when aggregate public readback exceeds the
	// signed channel's bound. Oversized observations cannot become completion.
	for i := range result.Results {
		raw, _ := json.Marshal(result)
		if len(raw) <= sshcollection.MaxJobReportBytes {
			break
		}
		if result.Results[i].Snapshot != nil {
			result.Results[i].Snapshot = nil
			result.Results[i].Status = "report_too_large"
		}
	}
	return result
}

func runSSHTrustCollection(ctx context.Context, ch Channel, job Job) bool {
	command, err := sshcollection.DecodeCommand(job.Payload)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "SSH collection command is invalid")
		return false
	}
	maintainer, ok := ch.(JobLeaseMaintainer)
	if !ok {
		report(ctx, ch, job, OutcomeFailed, "SSH collection needs a maintained job lease")
		return false
	}
	claim, err := maintainHostRenewClaim(ctx, maintainer, job)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "SSH collection claim could not be maintained")
		return false
	}
	defer claim.stop()
	ctx = claim.ctx
	material, destroy, err := redeemHostManagement(ctx, ch, job, command.CredentialRefs())
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "SSH collection credential redemption was not granted")
		return false
	}
	defer destroy()
	result := collectSSHTrust(ctx, command, material)
	destroy()
	if err := result.Validate(command); err != nil {
		report(ctx, ch, job, OutcomeFailed, "SSH collection could not produce a complete target outcome record")
		return false
	}
	detail, err := json.Marshal(result)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "SSH collection result could not be encoded")
		return false
	}
	reportWithEvidence(ctx, ch, job, OutcomeExecuted, string(detail), result.EvidenceDigest())
	return true
}
