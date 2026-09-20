// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/api"
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
