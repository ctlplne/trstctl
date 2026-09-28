// SPDX-License-Identifier: BUSL-1.1

package transport

import (
	"errors"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestCSRValidityRefusalSurvivesWireWithoutTrustingErrorText(t *testing.T) {
	wire, err := proto.Marshal(status.Convert(CSRValidityRefusalError()).Proto())
	if err != nil {
		t.Fatal(err)
	}
	var message rpcstatus.Status
	if err := proto.Unmarshal(wire, &message); err != nil {
		t.Fatal(err)
	}
	received := status.FromProto(&message).Err()
	if !IsCSRValidityRefusal(received) {
		t.Fatal("typed validity refusal lost over wire")
	}
	if _, pending := CSRPendingRetryDelay(received); pending {
		t.Fatal("invalid profile was treated as retryable pending issuance")
	}
	for _, err := range []error{nil, errors.New(CSRValidityRefusalDetail), status.Error(codes.FailedPrecondition, CSRValidityRefusalDetail), CSRPendingError()} {
		if IsCSRValidityRefusal(err) {
			t.Fatalf("untyped or unrelated error accepted: %v", err)
		}
	}
	for _, item := range []struct {
		code           codes.Code
		domain, reason string
	}{
		{codes.Internal, "trstctl.agent", "CERTIFICATE_PROFILE_VALIDITY_REFUSED"},
		{codes.FailedPrecondition, "foreign", "CERTIFICATE_PROFILE_VALIDITY_REFUSED"},
		{codes.FailedPrecondition, "trstctl.agent", "UNTRUSTED_REASON"},
	} {
		s, err := status.New(item.code, CSRValidityRefusalDetail).WithDetails(&errdetails.ErrorInfo{Domain: item.domain, Reason: item.reason})
		if err != nil {
			t.Fatal(err)
		}
		if IsCSRValidityRefusal(s.Err()) {
			t.Fatal("unrelated typed status accepted")
		}
	}
}
