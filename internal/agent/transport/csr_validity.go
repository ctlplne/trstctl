// SPDX-License-Identifier: BUSL-1.1

package transport

import (
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CSRValidityRefusalDetail is a fixed public report, never remote error text.
const CSRValidityRefusalDetail = "the control plane refused this host request because the certificate profile signed-validity limits were not met"

func CSRValidityRefusalError() error {
	s := status.New(codes.FailedPrecondition, CSRValidityRefusalDetail)
	detailed, err := s.WithDetails(&errdetails.ErrorInfo{Domain: "trstctl.agent", Reason: "CERTIFICATE_PROFILE_VALIDITY_REFUSED"})
	if err != nil {
		return s.Err()
	}
	return detailed.Err()
}

// IsCSRValidityRefusal recognizes a typed status across the RPC boundary. A
// matching phrase, unrelated status, or upstream metadata is not a diagnosis.
func IsCSRValidityRefusal(err error) bool {
	s, ok := status.FromError(err)
	if !ok || s.Code() != codes.FailedPrecondition {
		return false
	}
	for _, detail := range s.Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok && info.Domain == "trstctl.agent" && info.Reason == "CERTIFICATE_PROFILE_VALIDITY_REFUSED" {
			return true
		}
	}
	return false
}
