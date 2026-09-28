// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
)

// A legacy queued host job reaches the real authenticated CSR RPC. The local
// signing ceiling is deliberately unusable; no error text is used as evidence.
func TestServedHostCSRReturnsTypedValidityRefusal(t *testing.T) {
	h := newRoleHarnessWithEventOptions(t, []string{mtls.AgentRoleHost}, []string{agentJobKindEndpointRenew}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()}, func(d *Deps) { d.LeafProfile.MaxValidity = 2 * time.Minute })
	ctx := t.Context()
	before, err := h.store.ListCertificatesPage(ctx, h.tenant, "00000000-0000-0000-0000-000000000000", nil, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	seedRenewalJob(t, ctx, h, "legacy-profile-validity-rpc", []string{"rpc-profile.example.test"})
	job := claimOneRenewal(t, ctx, h)
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "rpc-profile.example.test", DNSNames: []string{"rpc-profile.example.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	result, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: csr})
	if !transport.IsCSRValidityRefusal(err) || result != nil {
		t.Fatalf("real signer refusal lost typed diagnosis: result=%v error=%v", result, err)
	}
	after, err := h.store.ListCertificatesPage(ctx, h.tenant, "00000000-0000-0000-0000-000000000000", nil, 100, nil)
	if err != nil || len(after) != len(before) {
		t.Fatalf("refusal changed certificate inventory: %d -> %d, %v", len(before), len(after), err)
	}
}
