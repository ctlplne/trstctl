// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/reportstate"
	"trstctl.com/trstctl/internal/agent/sshtrustfleet"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/sshtrustrollout"
)

func TestSSHTrustFleetRecoversItsReportWhileDisabledAndJoinsBeforeIdentityChange(t *testing.T) {
	path, err := sshTrustPendingReportsDir(agentOptions{keyPath: filepath.Join(t.TempDir(), "agent.key")})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "pending-reports-ssh-trust" {
		t.Fatal("fleet report shares connector namespace")
	}
	pending, err := reportstate.Open(path, "fleet-binding")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pending.Close() }()
	if err := pending.Put(reportstate.Observation{JobID: 226, Attempt: 2, Outcome: transport.JobOutcomeFailed, Detail: []byte("retained closed report"), EvidenceDigest: "sha256:" + strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	left := make(chan struct{})
	var claimed atomic.Int32
	ch := newReceiptRetryChannel(t, func(ctx context.Context, r *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
		if r.JobID != 226 || r.Attempt != 2 || r.Detail != "retained closed report" || len(r.Signature) == 0 {
			t.Error("recovery changed execution facts or omitted signature")
		}
		close(entered)
		<-ctx.Done()
		close(left)
		return nil, ctx.Err()
	}, func(s *receiptRetryChannelServer) {
		s.claim = func(context.Context, *transport.ClaimJobsRequest) (*transport.ClaimJobsResponse, error) {
			claimed.Add(1)
			return &transport.ClaimJobsResponse{}, nil
		}
	})
	ch.pending = pending
	loop := &sshTrustFleetLoop{parent: t.Context(), options: agentOptions{}, pending: pending, reporter: ch}
	loop.Resume()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("disabled fleet mode did not recover retained report")
	}
	workerDone := loop.done
	loop.Pause()
	select {
	case <-workerDone:
	default:
		t.Fatal("pause returned before signer-using worker joined")
	}
	// The remote server observes cancellation asynchronously after the client
	// exits. Identity custody depends on joining the local worker, not on a
	// remote handler's scheduling latency.
	select {
	case <-left:
	case <-time.After(5 * time.Second):
		t.Fatal("remote report handler did not observe cancellation")
	}
	if claimed.Load() != 0 {
		t.Fatal("disabled mode claimed new jobs")
	}
	value, err := pending.Pending()
	if err != nil || value == nil {
		t.Fatal("cancellation discarded unacknowledged observation")
	}
	value.Destroy()
	loop.reporter.c = nil // A closed loop must never restart the signer-using worker.
	loop.Stop()
	loop.Resume()
}

func TestSSHTrustFleetClaimListRunsOnlyOnReadyHost(t *testing.T) {
	dir := t.TempDir()
	var claims atomic.Int32
	ch := newReceiptRetryChannel(t, func(context.Context, *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
		return &transport.ReportJobResultResponse{Accepted: true}, nil
	}, func(s *receiptRetryChannelServer) {
		s.claim = func(_ context.Context, req *transport.ClaimJobsRequest) (*transport.ClaimJobsResponse, error) {
			claims.Add(1)
			if len(req.Kinds) != 1 || req.Kinds[0] != sshtrustrollout.Destination || req.Limit != 1 || req.LeaseSeconds != sshtrustfleet.LeaseSeconds {
				t.Error("dedicated worker widened its claim kinds or bulkhead")
			}
			return &transport.ClaimJobsResponse{}, nil
		}
	})
	key, cert := filepath.Join(dir, "agent.key"), filepath.Join(dir, "agent.crt")
	if err := ch.id().Save(key, cert); err != nil {
		t.Fatal(err)
	}
	a := agent.New(agent.Config{CommonName: ch.id().CommonName(), KeyPath: key, CertPath: cert}, nil)
	if err := a.Bootstrap(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Identity().Destroy)
	ca, config := filepath.Join(dir, "ca.pub"), filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(ca, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPexCbv5HmN6JhIN7b1GaDxkyWFY3uSrHBvKdlQYHONt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("Port 2222\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	action, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	local := sshTrustOptions{fleet: true, confirm: true, caKeyPath: ca, sshdConfig: config, trustedKeys: filepath.Join(dir, "trusted"), validateCmd: action, reloadCmd: action, healthCmd: action}
	loop := &sshTrustFleetLoop{parent: t.Context(), agent: a, reporter: ch, options: agentOptions{sshTrust: local}, loader: newSSHFleetPolicyLoader(local)}
	if err := loop.runOnce(t.Context()); err != nil || claims.Load() != 1 {
		t.Fatalf("ready dedicated worker didn't claim: claims=%d err=%v", claims.Load(), err)
	}
	loop.options.sshTrust.fleet = false
	if err := loop.runOnce(t.Context()); err != nil || claims.Load() != 1 {
		t.Fatalf("local opt-out still claimed: claims=%d err=%v", claims.Load(), err)
	}
	local.confirm = false
	loop.options.sshTrust.fleet = true
	loop.loader = newSSHFleetPolicyLoader(local)
	if err := loop.runOnce(t.Context()); err != nil || claims.Load() != 1 {
		t.Fatalf("unconfirmed policy still claimed: claims=%d err=%v", claims.Load(), err)
	}
}
