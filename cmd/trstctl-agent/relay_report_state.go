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
	if value.Custody != nil {
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

// openAgentReportState also recovers existing observations when the operator
// disables claiming. Removing a capability must not discard its last result.
func openAgentReportState(o agentOptions, id *mtls.AgentIdentity, caPEM []byte, serverName string, claiming bool) (*reportstate.Store, error) {
	path, err := filepath.Abs(filepath.Join(filepath.Dir(o.keyPath), "pending-reports"))
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
