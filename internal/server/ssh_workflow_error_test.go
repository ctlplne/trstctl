// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/api"
	sshca "trstctl.com/trstctl/internal/protocols/ssh"
)

func TestSSHWorkflowIssuanceErrorSeparatesSignerOutageFromRequestDenial(t *testing.T) {
	outage := sshWorkflowIssuanceError(status.Error(codes.Unavailable, "dial unix /run/trstctl/signer.sock: unavailable"))
	if !errors.Is(outage, api.ErrSSHWorkflowUnavailable) || errors.Is(outage, api.ErrSSHWorkflowRejected) {
		t.Fatalf("signer outage classification = %v, want unavailable only", outage)
	}
	if strings.Contains(outage.Error(), "/run/trstctl") {
		t.Fatalf("signer outage exposed internal socket path: %v", outage)
	}

	denied := sshWorkflowIssuanceError(errors.New("ssh: requested principal is not bound to attested subject"))
	if !errors.Is(denied, api.ErrSSHWorkflowRejected) || errors.Is(denied, api.ErrSSHWorkflowUnavailable) {
		t.Fatalf("request denial classification = %v, want rejected only", denied)
	}
}

func TestCR024SSHAuditFailureIsRetryableWithoutLeakingAppendDetails(t *testing.T) {
	audit := sshWorkflowIssuanceError(errors.Join(sshca.ErrAuditUnavailable, errors.New("private event-log path")))
	if !errors.Is(audit, api.ErrSSHWorkflowUnavailable) || errors.Is(audit, api.ErrSSHWorkflowRejected) {
		t.Fatalf("audit outage classification = %v, want unavailable only", audit)
	}
	if strings.Contains(audit.Error(), "private event-log path") || !strings.Contains(audit.Error(), "audit") {
		t.Fatalf("audit outage response lacks recovery guidance or leaked append details: %v", audit)
	}
}
