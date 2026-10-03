// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type onceAWSSTSProvider struct {
	calls int
	fail  bool
	raw   []byte
}

func (p *onceAWSSTSProvider) Name() string                             { return "aws-sts" }
func (p *onceAWSSTSProvider) DynamicSecretNeedsAtMostOnceEffect() bool { return true }
func (p *onceAWSSTSProvider) Generate(_ context.Context, req dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	p.calls++
	if p.fail {
		return dynsecret.Credential{}, errors.New("AWS response was lost after AssumeRole")
	}
	p.raw = []byte("session-secret")
	return dynsecret.Credential{BackendRef: req.LeaseID, Secret: p.raw}, nil
}
func (p *onceAWSSTSProvider) Revoke(context.Context, string) error { return nil }

func TestAWSSTSOutboxUsesAtMostOnceEffectAndReplaysProtectedResult(t *testing.T) {
	ctx := context.Background()
	provider := &onceAWSSTSProvider{}
	d := &secretIntegrationOutboxDispatcher{idem: orchestrator.NewMemoryIdempotency()}
	m := orchestrator.Message{TenantID: "11111111-1111-1111-1111-111111111111"}
	command := projections.DynamicSecretIssueCommand{ID: "22222222-2222-2222-2222-222222222222"}
	req := dynsecret.GenerateRequest{Role: "reader", LeaseID: command.ID, TTL: 20 * time.Minute}
	first, err := d.generateDynamicSecretCredential(ctx, m, command, store.DynamicSecretLease{}, provider, req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.generateDynamicSecretCredential(ctx, m, command, store.DynamicSecretLease{}, provider, req)
	if err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 || !bytes.Equal(first.Secret, second.Secret) || first.BackendRef != second.BackendRef {
		t.Fatalf("AWS STS replay minted a second session: calls=%d", provider.calls)
	}
	if !bytes.Equal(provider.raw, make([]byte, len(provider.raw))) {
		t.Fatal("temporary STS credential bytes were not wiped after recording")
	}
}

func TestAWSSTSOutboxNeverRetriesAmbiguousAssumeRole(t *testing.T) {
	ctx := context.Background()
	provider := &onceAWSSTSProvider{fail: true}
	d := &secretIntegrationOutboxDispatcher{idem: orchestrator.NewMemoryIdempotency()}
	m := orchestrator.Message{TenantID: "11111111-1111-1111-1111-111111111111"}
	command := projections.DynamicSecretIssueCommand{ID: "33333333-3333-3333-3333-333333333333"}
	req := dynsecret.GenerateRequest{Role: "reader", LeaseID: command.ID, TTL: 20 * time.Minute}
	for range 2 {
		_, err := d.generateDynamicSecretCredential(ctx, m, command, store.DynamicSecretLease{}, provider, req)
		if !errors.Is(err, orchestrator.ErrEffectIndeterminate) {
			t.Fatalf("ambiguous AssumeRole result = %v, want indeterminate", err)
		}
	}
	if provider.calls != 1 {
		t.Fatalf("ambiguous AWS STS operation was submitted %d times", provider.calls)
	}
}

func TestAWSSTSIndeterminateTerminalReceiptNamesCloudTrailReconciliation(t *testing.T) {
	provider := &onceAWSSTSProvider{}
	d := &secretIntegrationOutboxDispatcher{fallbackDynamicProviders: []dynsecret.Provider{provider}}
	tenantID := "11111111-1111-1111-1111-111111111111"
	got := d.dynamicSecretTerminalIssueFailure(tenantID, provider.Name(), orchestrator.ErrEffectIndeterminate)
	if !strings.Contains(got, "AssumeRole outcome is indeterminate") || !strings.Contains(got, "CloudTrail") {
		t.Fatalf("ambiguous AWS STS terminal receipt hid reconciliation: %q", got)
	}
	if got := d.dynamicSecretTerminalIssueFailure(tenantID, provider.Name(), errors.New("temporary outage")); strings.Contains(got, "CloudTrail") {
		t.Fatalf("definite pre-call outage was mislabeled as an AWS session: %q", got)
	}
}
