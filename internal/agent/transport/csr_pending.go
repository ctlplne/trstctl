// SPDX-License-Identifier: MPL-2.0

package transport

import (
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

// CSRPendingError tells an agent to retain its key and repeat the identical
// CSR on the same job claim. It does not authorize a new issuance or claim.
func CSRPendingError() error {
	s := status.New(codes.Unavailable, "certificate issuance is pending; retry the same CSR while this job claim is held")
	withDetails, err := s.WithDetails(
		&errdetails.ErrorInfo{Domain: "trstctl.agent", Reason: "CERTIFICATE_ISSUANCE_PENDING"},
		&errdetails.RetryInfo{RetryDelay: durationpb.New(time.Second)},
	)
	if err != nil {
		return s.Err()
	}
	return withDetails.Err()
}

// CSRPendingRetryDelay recognizes the explicit pending contract. Unrelated
// failures, including an old server's untyped Internal response, are not pending.
func CSRPendingRetryDelay(err error) (time.Duration, bool) {
	s, ok := status.FromError(err)
	if !ok || s.Code() != codes.Unavailable {
		return 0, false
	}
	var pending bool
	delay := time.Second
	for _, detail := range s.Details() {
		switch d := detail.(type) {
		case *errdetails.ErrorInfo:
			pending = pending || (d.Domain == "trstctl.agent" && d.Reason == "CERTIFICATE_ISSUANCE_PENDING")
		case *errdetails.RetryInfo:
			if d.RetryDelay != nil && d.RetryDelay.CheckValid() == nil {
				delay = d.RetryDelay.AsDuration()
			}
		}
	}
	if delay <= 0 || delay > 5*time.Second {
		delay = time.Second
	}
	return delay, pending
}
