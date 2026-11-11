// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
)

// TestSSHCertificateLeaseRevokesOnlyALiveCertificateA239L11: revoking an SSH
// certificate lease revokes its key ID on the KRL while its certificate is
// still valid. Once the certificate has expired (the usual end of a lease)
// nothing is added: it no longer authenticates anywhere, and the KRL keeps
// only early revocations. A reference that isn't an SSH lease's is refused,
// and so is a provider not attached to the CA.
func TestSSHCertificateLeaseRevokesOnlyALiveCertificateA239L11(t *testing.T) {
	var revoked []string
	p := &configuredSSHCertificateProvider{
		configuredDynamicProvider: &configuredDynamicProvider{id: "ssh-deploy", tenantID: servedTestTenant},
		revoke: func(_ context.Context, tenantID, key string, req api.SSHRevokeCertificateRequest) (api.SSHStatus, error) {
			if tenantID != servedTestTenant || key == "" {
				t.Fatalf("revoke for tenant %q with key %q", tenantID, key)
			}
			revoked = append(revoked, req.KeyID)
			return api.SSHStatus{}, nil
		},
		clock: func() time.Time { return time.Unix(1_800_000_000, 0) },
	}
	ctx := context.Background()
	if err := p.Revoke(ctx, "ssh-key-id:trstctl-lease-live@1800000600"); err != nil {
		t.Fatal(err)
	}
	if err := p.Revoke(ctx, "ssh-key-id:trstctl-lease-expired@1800000000"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(revoked, []string{"trstctl-lease-live"}) {
		t.Fatalf("revoked key IDs = %v, want only the live certificate's", revoked)
	}
	for _, ref := range []string{"ssh-key-id:trstctl-lease-a", "ssh-key-id:other-a@1800000600", "ssh-key-id:trstctl-@1800000600",
		"ssh-key-id:trstctl-lease-a@soon", "trstctl-lease-a@1800000600"} {
		if err := p.Revoke(ctx, ref); err == nil {
			t.Errorf("revoke %q was accepted", ref)
		}
	}
	p.revoke = nil
	if err := p.Revoke(ctx, "ssh-key-id:trstctl-lease-live@1800000600"); err == nil {
		t.Fatal("a provider not attached to the SSH CA revoked")
	}
}
