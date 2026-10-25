// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"trstctl.com/trstctl/internal/agent/reportstate"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/custody"
)

func terminalReport(outcome string) bool {
	switch outcome {
	case transport.JobOutcomeExecuted, transport.JobOutcomeVerified, transport.JobOutcomeVerifyFailed, transport.JobOutcomeFailed:
		return true
	}
	return false
}

func (r relayChannel) retainAndSendReport(ctx context.Context, value reportstate.Observation) (bool, error) {
	if r.pending != nil {
		if err := r.pending.Put(value); err != nil {
			return false, err
		}
	}
	return r.sendObservation(ctx, value)
}

func (r relayChannel) recoverPendingReport(ctx context.Context) error {
	if r.pending == nil {
		return nil
	}
	value, err := r.pending.Pending()
	if err != nil || value == nil {
		return err
	}
	defer value.Destroy()
	accepted, err := r.sendObservation(ctx, *value)
	if err != nil {
		return fmt.Errorf("recover original terminal report before claiming work: %w", err)
	}
	if !accepted {
		return errors.New("original terminal report remains unacknowledged; no new work will be claimed")
	}
	return nil
}

func (r relayChannel) sendObservation(ctx context.Context, value reportstate.Observation) (bool, error) {
	id := r.id()
	if id == nil {
		return false, errors.New("trstctl-agent: cannot sign a job receipt before enrollment")
	}
	var req *transport.ReportJobResultRequest
	var err error
	// IssuedAt is this attestation's signing time, not a new execution time.
	// The original job, attempt and facts never change during recovery.
	if value.AdoptedPredecessorFingerprint != "" {
		record := custody.Record{}
		if value.Custody != nil {
			record = *value.Custody
		}
		req, err = transport.SignedReportWithAdoption(id, id.TenantID(), id.CommonName(), value.JobID, value.Attempt, value.Outcome, string(value.Detail), value.EvidenceDigest, value.CredentialFingerprint, record, value.AdoptedPredecessorFingerprint, value.AdoptedPredecessorPEM, r.clock().Unix())
	} else if value.Custody != nil {
		req, err = transport.SignedReportWithCustody(id, id.TenantID(), id.CommonName(), value.JobID, value.Attempt, value.Outcome, string(value.Detail), value.EvidenceDigest, value.CredentialFingerprint, *value.Custody, r.clock().Unix())
	} else {
		req, err = transport.SignedReport(id, id.TenantID(), id.CommonName(), value.JobID, value.Attempt, value.Outcome, string(value.Detail), value.EvidenceDigest, r.clock().Unix())
	}
	if err != nil {
		return false, err
	}
	accepted, err := r.sendSignedReport(ctx, req)
	if err != nil || !accepted || r.pending == nil {
		return accepted, err
	}
	if value.HostRenew != nil {
		if r.hostRollback == nil {
			return false, errors.New("trstctl-agent: accepted host report has no rollback store for cleanup")
		}
		if err := r.hostRollback.ClearHostRenewPending(value.HostRenew.Connector, value.HostRenew.TargetID,
			value.JobID, value.HostRenew.Binding, value.CredentialFingerprint); err != nil {
			return false, fmt.Errorf("clear accepted host renewal key before acknowledging report: %w", err)
		}
	}
	if err := r.pending.Acknowledge(value); err != nil {
		return false, fmt.Errorf("persist terminal report acknowledgement: %w", err)
	}
	return true, nil
}

func reportIdentityBinding(id *mtls.AgentIdentity, caPEM []byte, serverName string) (string, error) {
	info, err := certinfo.Inspect(id.CertificateDER())
	if err != nil {
		return "", err
	}
	const prefix = "https://trstctl.com/agent/tenant-registration/v1/"
	registration := ""
	for _, uri := range info.URIs {
		if strings.HasPrefix(uri, prefix) {
			if registration != "" || !strings.HasPrefix(uri, prefix+id.TenantID()+"/") {
				return "", errors.New("agent report state requires one matching tenant registration")
			}
			registration = uri
		}
	}
	if registration == "" {
		// Old certificates have no stable registration identity. Keep them bound
		// to this exact leaf; do not guess across renewal or re-enrollment.
		registration = "legacy-leaf:" + info.SHA256Fingerprint
	}
	identity, err := json.Marshal([]string{serverName, crypto.SHA256Hex(caPEM), id.TenantID(), id.CommonName(), registration})
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(identity), nil
}

// pendingReportsDir is the agent's report store, beside its identity key.
func pendingReportsDir(o agentOptions) (string, error) {
	return filepath.Abs(filepath.Join(filepath.Dir(o.keyPath), "pending-reports"))
}

// openAgentReportState also recovers existing observations when the operator
// disables claiming. Removing a capability must not discard its last result.
func openAgentReportState(o agentOptions, id *mtls.AgentIdentity, caPEM []byte, serverName string, claiming bool) (*reportstate.Store, error) {
	path, err := pendingReportsDir(o)
	if err != nil {
		return nil, err
	}
	if !claiming {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return nil, nil
		} else if err != nil {
			return nil, err
		}
	}
	binding, err := reportIdentityBinding(id, caPEM, serverName)
	if err != nil {
		return nil, err
	}
	return reportstate.Open(path, binding)
}

const pendingReportErrorLimit = 512

// pendingReportPause separates a retained report this registration cannot
// send (B13-R1), which pauses job claims while the agent keeps running, from a
// report-store environment failure (another process owns the store, an
// unusable directory), which still stops the agent. The reason is bounded,
// names the remedy and carries no report contents.
func pendingReportPause(err error) (string, bool) {
	var reason string
	switch {
	case errors.Is(err, reportstate.ErrUnopenable):
		reason = err.Error() + ". It was sealed under another registration or server trust (re-enrollment, a changed --ca-bundle or --server-name), its sealing key is missing, or it is damaged. Restore those settings to send it, or stop the agent and run it once with --set-aside-pending-report to move it aside unsent; job claims stay paused until then"
	case errors.Is(err, reportstate.ErrInvalidPending):
		reason = err.Error() + ". Run the agent build that wrote it to send it, or stop the agent and run it once with --set-aside-pending-report to move it aside unsent; job claims stay paused until then"
	default:
		return "", false
	}
	if len(reason) > pendingReportErrorLimit {
		reason = reason[:pendingReportErrorLimit]
	}
	return reason, true
}

// setAsidePendingReportFor (B13-R1) loads the enrolled identity from disk,
// without connecting, and sets aside a pending report this registration cannot
// open. "" means there was nothing to move: no store, nothing pending, or a
// report the agent can still send.
func setAsidePendingReportFor(o agentOptions) (string, error) {
	path, err := pendingReportsDir(o)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	caPEM, err := os.ReadFile(o.caBundle)
	if err != nil {
		return "", fmt.Errorf("read CA bundle: %w", err)
	}
	id, err := mtls.LoadAgentIdentity(o.commonName, o.keyPath, o.certPath)
	if err != nil {
		return "", fmt.Errorf("load this agent's enrolled identity: %w", err)
	}
	defer id.Destroy()
	serverName := o.serverName
	if serverName == "" {
		serverName = o.commonName
	}
	binding, err := reportIdentityBinding(id, caPEM, serverName)
	if err != nil {
		return "", err
	}
	return reportstate.SetAsideUnopenable(path, binding)
}
