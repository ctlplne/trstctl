// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"trstctl.com/trstctl/internal/crypto/tenantwrap"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// A123: every tenant KEK call is at least one HSM operation, so each sits
// inside the signer's in-flight bound; and a custody failure crosses the
// transport as a fixed code with a fixed message (no wrapper path, PIN, key or
// ciphertext detail) that the client turns back into the same error class.
func TestTenantKEKCallsAreBoundedAndFailuresCrossAsFixedCodes(t *testing.T) {
	for _, method := range []string{
		signerpb.SignerService_CreateTenantDomainKEK_FullMethodName,
		signerpb.SignerService_OpenTenantDomainKEK_FullMethodName,
		signerpb.SignerService_WrapTenantDataKey_FullMethodName,
		signerpb.SignerService_UnwrapTenantDataKey_FullMethodName,
	} {
		if !expensiveMethods[method] {
			t.Errorf("%s is outside the signer's in-flight bound", method)
		}
	}

	detail := "module=/usr/lib/hsm.so pin-file=/etc/hsm-pin label=tenant-kek-a"
	for _, c := range []struct {
		err   error
		code  codes.Code
		class error
	}{
		{fmt.Errorf("%w: %s", ErrTenantKEKWrapperUnknown, detail), codes.NotFound, ErrTenantKEKWrapperUnknown},
		{fmt.Errorf("%w: %s", tenantwrap.ErrUnavailable, detail), codes.Unavailable, tenantwrap.ErrUnavailable},
		{tenantwrap.ErrInvalidWrapperKey, codes.Unavailable, tenantwrap.ErrUnavailable},
		{tenantwrap.ErrCorrupt, codes.DataLoss, tenantwrap.ErrCorrupt},
		{tenantwrap.ErrDomainBinding, codes.DataLoss, tenantwrap.ErrCorrupt},
		{fmt.Errorf("%w: %s", tenantwrap.ErrUnwrap, detail), codes.FailedPrecondition, tenantwrap.ErrUnwrap},
		{tenantwrap.ErrCustody, codes.Internal, tenantwrap.ErrCustody},
		{errors.New(detail), codes.Internal, tenantwrap.ErrCustody},
		{context.DeadlineExceeded, codes.DeadlineExceeded, context.DeadlineExceeded},
		{context.Canceled, codes.Canceled, context.Canceled},
	} {
		wire := tenantKEKStatus(c.err)
		if status.Code(wire) != c.code || strings.Contains(wire.Error(), "hsm") {
			t.Errorf("%v crossed as %v (%q), want %v without detail", c.err, status.Code(wire), wire, c.code)
		}
		if back := tenantKEKError(wire); !errors.Is(back, c.class) {
			t.Errorf("%v came back as %v, want %v", c.err, back, c.class)
		}
	}
	if back := tenantKEKError(status.Error(codes.Unimplemented, ErrNoTenantKEKCustody.Error())); !errors.Is(back, ErrNoTenantKEKCustody) {
		t.Errorf("a signer without custody came back as %v", back)
	}
	if tenantKEKError(nil) != nil {
		t.Error("a nil error came back non-nil")
	}
}

// A123: the tenant domain KEK crosses the transport only wrapped. Each tenant
// KEK response carries exactly these fields; a field added to any of them (a
// domain KEK in the clear, say) fails here before it can ship.
func TestTenantKEKResponsesCarryNoDomainKEK(t *testing.T) {
	for _, c := range []struct {
		msg    proto.Message
		fields []string
	}{
		{&signerpb.CreateTenantDomainKEKResponse{}, []string{"wrapped_domain_kek"}},
		{&signerpb.OpenTenantDomainKEKResponse{}, nil},
		{&signerpb.WrapTenantDataKeyResponse{}, []string{"wrapped_data_key"}},
		{&signerpb.UnwrapTenantDataKeyResponse{}, []string{"data_key"}},
	} {
		desc := c.msg.ProtoReflect().Descriptor()
		var got []string
		for i := 0; i < desc.Fields().Len(); i++ {
			got = append(got, string(desc.Fields().Get(i).Name()))
		}
		if strings.Join(got, ",") != strings.Join(c.fields, ",") {
			t.Errorf("%s carries %v, want exactly %v", desc.Name(), got, c.fields)
		}
	}
}
