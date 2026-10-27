// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

type testIssuingCAKeyOp struct {
	certs map[string][]byte
	err   error
}

func (testIssuingCAKeyOp) MintApprovedCredential(context.Context, IssuancePreconditions, IssuanceDecision, crypto.Algorithm) (IssuedCredential, error) {
	return IssuedCredential{}, errors.New("not used")
}

func (op testIssuingCAKeyOp) IssuingCACertificate(tenantID string) ([]byte, error) {
	if op.err != nil {
		return nil, op.err
	}
	return op.certs[tenantID], nil
}

// TestGetAgentIssuingCAPublishesOnlyAnAttachedTenantCA answers with the
// attached key op's certificate for the requested tenant, and refuses a
// tenantless request, a signer without agent credential issuance, and a key op
// that cannot produce the CA.
func TestGetAgentIssuingCAPublishesOnlyAnAttachedTenantCA(t *testing.T) {
	ctx := context.Background()
	server := &Server{}
	_, err := server.GetAgentIssuingCA(ctx, &signerpb.GetAgentIssuingCARequest{TenantId: "tenant-a"})
	requireSignerCode(t, err, codes.FailedPrecondition)

	server.issuanceKeyOp = testIssuingCAKeyOp{certs: map[string][]byte{"tenant-a": []byte("ca-a"), "tenant-b": []byte("ca-b")}}
	for _, invalid := range []*signerpb.GetAgentIssuingCARequest{nil, {}, {TenantId: " tenant-a"}} {
		_, err = server.GetAgentIssuingCA(ctx, invalid)
		requireSignerCode(t, err, codes.InvalidArgument)
	}
	got, err := server.GetAgentIssuingCA(ctx, &signerpb.GetAgentIssuingCARequest{TenantId: "tenant-b"})
	if err != nil || !bytes.Equal(got.GetCertificateDer(), []byte("ca-b")) {
		t.Fatalf("tenant B's CA = %q, %v", got.GetCertificateDer(), err)
	}
	_, err = server.GetAgentIssuingCA(ctx, &signerpb.GetAgentIssuingCARequest{TenantId: "tenant-c"})
	requireSignerCode(t, err, codes.FailedPrecondition)

	server.issuanceKeyOp = testIssuingCAKeyOp{err: errors.New("custody unavailable")}
	_, err = server.GetAgentIssuingCA(ctx, &signerpb.GetAgentIssuingCARequest{TenantId: "tenant-a"})
	requireSignerCode(t, err, codes.FailedPrecondition)
}
