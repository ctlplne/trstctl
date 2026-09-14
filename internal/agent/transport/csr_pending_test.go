// SPDX-License-Identifier: MPL-2.0

package transport_test

import (
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"trstctl.com/trstctl/internal/agent/transport"
)

func TestCSRPendingContractRejectsUnrelatedErrorsAndBoundsDelay(t *testing.T) {
	if delay, ok := transport.CSRPendingRetryDelay(transport.CSRPendingError()); !ok || delay != time.Second {
		t.Fatalf("served pending contract: delay=%s pending=%t", delay, ok)
	}
	for _, tc := range []struct {
		name           string
		code           codes.Code
		domain, reason string
		delay          time.Duration
		pending        bool
		want           time.Duration
	}{
		{"untyped", codes.Unavailable, "", "", time.Second, false, time.Second},
		{"wrong-domain", codes.Unavailable, "other", "CERTIFICATE_ISSUANCE_PENDING", time.Second, false, time.Second},
		{"wrong-reason", codes.Unavailable, "trstctl.agent", "OTHER", time.Second, false, time.Second},
		{"permanent", codes.PermissionDenied, "trstctl.agent", "CERTIFICATE_ISSUANCE_PENDING", time.Second, false, 0},
		{"negative-delay", codes.Unavailable, "trstctl.agent", "CERTIFICATE_ISSUANCE_PENDING", -time.Second, true, time.Second},
		{"long-delay", codes.Unavailable, "trstctl.agent", "CERTIFICATE_ISSUANCE_PENDING", time.Hour, true, time.Second},
		{"bounded-delay", codes.Unavailable, "trstctl.agent", "CERTIFICATE_ISSUANCE_PENDING", 2 * time.Second, true, 2 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := status.New(tc.code, "fixture").WithDetails(&errdetails.ErrorInfo{Domain: tc.domain, Reason: tc.reason}, &errdetails.RetryInfo{RetryDelay: durationpb.New(tc.delay)})
			if err != nil {
				t.Fatal(err)
			}
			if delay, ok := transport.CSRPendingRetryDelay(s.Err()); ok != tc.pending || delay != tc.want {
				t.Fatalf("delay=%s pending=%t", delay, ok)
			}
		})
	}
}
