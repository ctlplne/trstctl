// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/reportstate"
	"trstctl.com/trstctl/internal/agent/sshtrustfleet"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/sshtrustrollout"
)

// One worker, no prefetched queue. This loop can wait on SSH without taking a
// connector worker or blocking the main heartbeat timer. Pause joins it before
// the main loop renews/destroys its enrolled signing identity.
type sshTrustFleetLoop struct {
	parent       context.Context
	options      agentOptions
	agent        *agent.Agent
	loader       *sshFleetPolicyLoader
	reporter     relayChannel
	pending      *reportstate.Store
	pausedReport atomic.Bool
	mu           sync.Mutex
	cancel       context.CancelFunc
	done         chan struct{}
	closed       bool
}

func sshTrustPendingReportsDir(o agentOptions) (string, error) {
	return filepath.Abs(filepath.Join(filepath.Dir(o.keyPath), "pending-reports-ssh-trust"))
}

func startSSHTrustFleetLoop(ctx context.Context, o agentOptions, a *agent.Agent, conn *grpc.ClientConn, caPEM []byte, serverName string) (*sshTrustFleetLoop, error) {
	loop := &sshTrustFleetLoop{parent: ctx, options: o, agent: a, loader: newSSHFleetPolicyLoader(o.sshTrust)}
	path, err := sshTrustPendingReportsDir(o)
	if err != nil {
		return nil, err
	}
	claiming := o.sshTrust.fleet && agentCarriesRole(a.Roles(), mtls.AgentRoleHost)
	if !claiming {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return loop, nil
		} else if err != nil {
			return nil, err
		}
	}
	binding, err := reportIdentityBinding(a.Identity(), caPEM, serverName)
	if err != nil {
		return nil, err
	}
	pending, err := reportstate.Open(path, binding)
	if err != nil {
		if reason, paused := pendingReportPause(err); paused {
			loop.pausedReport.Store(true)
			// Paths and recovery details are local diagnostics; the heartbeat carries
			// only report_state_paused, never report bytes or the sealing key.
			fmt.Fprintln(os.Stderr, "trstctl-agent: SSH trust claims paused:", reason)
			return loop, nil
		}
		return nil, err
	}
	loop.pending = pending
	loop.reporter = relayChannel{c: transport.NewAgentClient(conn, transport.WithAgentVersion(buildinfo.Version())), id: a.Identity, pending: pending, leaseSeconds: sshtrustfleet.LeaseSeconds}
	loop.Resume()
	return loop, nil
}

func (l *sshTrustFleetLoop) Readiness() *sshtrustrollout.Readiness {
	policy, err := l.loader.load(false)
	r := policy.Readiness
	if id := l.agent.Identity(); r.Enabled && id != nil && l.options.sshTrust.tenantID != "" && l.options.sshTrust.tenantID != id.TenantID() {
		r.IssueCode = "local_configuration_invalid"
	}
	if err != nil {
		r.IssueCode = "local_configuration_invalid"
	}
	if l.pausedReport.Load() {
		r.IssueCode = "report_state_paused"
	}
	return &r
}
func (l *sshTrustFleetLoop) Pause() {
	if l == nil {
		return
	}
	l.mu.Lock()
	cancel, done := l.cancel, l.done
	l.cancel = nil
	l.done = nil
	l.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
func (l *sshTrustFleetLoop) Resume() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.cancel != nil || l.pending == nil {
		return
	}
	ctx, cancel := context.WithCancel(l.parent)
	done := make(chan struct{})
	l.cancel = cancel
	l.done = done
	go func() { defer close(done); l.run(ctx) }()
}
func (l *sshTrustFleetLoop) Stop() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	l.Pause()
	if l.pending != nil {
		_ = l.pending.Close()
	}
}
func (l *sshTrustFleetLoop) run(ctx context.Context) {
	every := l.options.relayPollEvery
	if every < time.Second {
		every = time.Second
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := l.runOnce(ctx); err != nil && ctx.Err() == nil {
			// Do not print arbitrary command or agent-report text. The local policy
			// and signed receipt provide the closed phase/rollback facts.
			fmt.Fprintln(os.Stderr, "trstctl-agent: SSH trust work or receipt delivery needs another attempt")
		}
		timer.Reset(every)
	}
}

func (l *sshTrustFleetLoop) runOnce(ctx context.Context) error {
	rpcCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err := l.reporter.recoverPendingReport(rpcCtx)
	cancel()
	if err != nil {
		l.pausedReport.Store(true)
		return err
	}
	l.pausedReport.Store(false)
	if !l.options.sshTrust.fleet || !agentCarriesRole(l.agent.Roles(), mtls.AgentRoleHost) {
		return nil
	}
	policy, err := l.loader.load(true)
	if err != nil || !policy.Readiness.Ready() {
		return err
	}
	if id := l.agent.Identity(); id == nil || l.options.sshTrust.tenantID != "" && l.options.sshTrust.tenantID != id.TenantID() {
		return errors.New("SSH trust tenant pin differs from enrollment")
	}
	started := time.Now()
	claimCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	jobs, err := l.reporter.ClaimJobs(claimCtx, sshtrustfleet.ClaimableKinds(), 1, sshtrustfleet.LeaseSeconds)
	cancel()
	if err != nil {
		return err
	}
	if len(jobs) > 1 {
		return errors.New("SSH trust claim exceeded its one-worker bound")
	}
	for _, job := range jobs {
		if job.Kind != sshtrustrollout.Destination || job.LeaseExpiresUnix <= 0 {
			return errors.New("SSH trust claim has no bound server lease")
		}
		command, err := sshtrustrollout.DecodeCommand(bytes.NewReader(job.Payload))
		if err != nil {
			return err
		}
		identity := l.agent.Identity()
		if identity == nil {
			return errors.New("SSH trust worker has no enrolled identity")
		}
		// Lease expiry came from the authenticated server. Round its inferred
		// issue time upward to avoid extending a deadline by Unix-second truncation.
		serverNow := time.Unix(job.LeaseExpiresUnix-int64(sshtrustfleet.LeaseSeconds)+1, 0).Add(time.Since(started))
		// Re-read after the network claim: the operator may have replaced a CA
		// pin or action while the RPC was in flight. Invalid current settings
		// become a signed preflight refusal, never a write under old settings.
		policy, policyErr := l.loader.load(true)
		local := sshtrustrollout.LocalAuthority{Enabled: policyErr == nil && policy.Readiness.Ready(), Confirmed: policy.Readiness.Confirmed, AllowedCAFingerprint: policy.Readiness.CAFingerprint, AgentID: sshtrustrollout.EnrolledAgentID(identity.TenantID(), identity.CommonName()), ReadinessDigest: policy.Readiness.PolicyDigest}
		if pinned := l.options.sshTrust.tenantID; pinned != "" && pinned != identity.TenantID() {
			local.Enabled = false
		}
		waiting := time.Now()
		waitBudget := command.ExpiresAt.Sub(serverNow)
		if waitBudget > sshtrustfleet.WorkTimeout {
			waitBudget = sshtrustfleet.WorkTimeout
		}
		waitCtx, waitCancel := context.WithTimeout(ctx, waitBudget)
		release, lockErr := acquireSSHHostMutation(waitCtx)
		waitCancel()
		serverNow = serverNow.Add(time.Since(waiting))
		var report sshtrustrollout.Report
		if lockErr != nil {
			refused, refuseCancel := context.WithCancel(ctx)
			refuseCancel()
			report, _ = sshtrustfleet.ExecuteAt(refused, identity.TenantID(), policy.Config, local, command, serverNow)
			if ctx.Err() == nil {
				report.ReasonCode = "host_busy"
				if !serverNow.Before(command.ExpiresAt) {
					report.ReasonCode = "execution_window_ended"
				}
			}
		} else {
			report, _ = sshtrustfleet.ExecuteAt(ctx, identity.TenantID(), policy.Config, local, command, serverNow)
			release()
		}
		raw, digest, err := report.Encode()
		if err != nil {
			return err
		}
		if err := report.Validate(command, digest); err != nil {
			return err
		}
		outcome := transport.JobOutcomeVerifyFailed
		if report.State == "verified" {
			outcome = transport.JobOutcomeVerified
		}
		reportCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		accepted, err := l.reporter.ReportJobResult(reportCtx, job.JobID, job.Attempt, outcome, string(raw), digest)
		cancel()
		if err != nil || !accepted {
			l.pausedReport.Store(true)
			if err != nil {
				return err
			}
			return errors.New("SSH trust receipt is not acknowledged")
		}
	}
	return nil
}
