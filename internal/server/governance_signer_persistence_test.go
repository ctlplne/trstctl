// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

type governanceTestSignerProvider struct{ client *signing.Client }

func (p governanceTestSignerProvider) Client() *signing.Client { return p.client }

// A compliance export is a long-lived audit artifact. A fresh control-plane
// process must bind the same signer-owned key instead of minting a local key that
// silently invalidates the operator's pinned verification identity on restart.
func TestComplianceEvidenceSignerPersistsAcrossControlPlaneBuilds(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{}
	configureExternalAuditTestSigner(t, cfg)
	client, err := signing.DialReady(ctx, cfg.Signer.Socket, 10*time.Second)
	if err != nil {
		t.Fatalf("connect isolated signer: %v", err)
	}
	defer func() { _ = client.Close() }()

	var bound []crypto.DigestSigner
	d := Deps{
		Store:  &store.Store{},
		Signer: governanceTestSignerProvider{client: client},
		GovernanceFactory: func(deps GovernanceFactoryDeps) (api.ComplianceEvidenceService, error) {
			bound = append(bound, deps.Signer)
			return stubComplianceEvidence{}, nil
		},
	}
	for i := 0; i < 2; i++ {
		s := &Server{}
		if _, err := s.buildComplianceEvidenceService(ctx, d, &audit.Service{}); err != nil {
			t.Fatalf("build %d: %v", i+1, err)
		}
	}
	if len(bound) != 2 || !bytes.Equal(bound[0].Public().DER, bound[1].Public().DER) {
		t.Fatal("rebuilding the control plane changed the compliance verification key")
	}
	message := []byte(`{"tenant_id":"11111111-1111-4111-8111-111111111111","framework":"soc2"}`)
	signature, err := crypto.SignMessage(bound[0], message)
	if err != nil {
		t.Fatalf("sign through isolated signer: %v", err)
	}
	if err := crypto.VerifyMessage(bound[1].Public().DER, message, signature); err != nil {
		t.Fatalf("verify old export with rebound public key: %v", err)
	}
	wrongPurpose, err := client.SignerForHandleWithPurpose(ctx, complianceEvidenceHandle, signing.PurposeCASign)
	if err != nil {
		t.Fatalf("bind wrong-purpose view: %v", err)
	}
	if _, err := crypto.SignMessage(wrongPurpose, message); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("compliance key signed as CA key: %v", err)
	}
	d.Signer = nil
	if _, err := (&Server{}).buildComplianceEvidenceService(ctx, d, &audit.Service{}); err == nil {
		t.Fatal("governance started without the isolated signer")
	}
}
