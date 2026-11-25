// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/codesign"
)

func TestCR024CodeSigningAuditOutageRemainsRetryableWithTerminalCause(t *testing.T) {
	appendErr := status.Error(codes.PermissionDenied, "private event-log append detail")
	err := errors.Join(codesign.ErrAuditUnavailable, appendErr)
	wrapped := terminalCodeSigningDomainError(err)
	if codeSigningExecutionIsTerminal(wrapped) {
		t.Fatalf("audit outage was dead-lettered instead of retried: %v", wrapped)
	}
}
