// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"errors"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
)

func TestReceiptAcknowledgementCannotAuthorizeMoreWork(t *testing.T) {
	ch := newReceiptRetryChannel(t, func(context.Context, *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
		return &transport.ReportJobResultResponse{ReceiptRecorded: true, LeaseExpiresUnix: time.Now().Add(time.Hour).Unix()}, nil
	})
	if _, err := ch.ExtendJobClaim(t.Context(), 91, 4); !errors.Is(err, relay.ErrJobClaimLost) {
		t.Fatalf("receipt granted a lease: %v", err)
	}
	for _, outcome := range []string{transport.JobOutcomeExtend, transport.JobOutcomeAuthorizeRollback} {
		if ok, err := ch.sendSignedReport(t.Context(), &transport.ReportJobResultRequest{JobID: 91, Attempt: 4, Outcome: outcome}); err != nil || ok {
			t.Errorf("receipt granted %s: %v %v", outcome, ok, err)
		}
	}
}
