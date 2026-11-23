// SPDX-License-Identifier: BUSL-1.1

package notify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/credref"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

type countingCredentialResolver struct {
	calls        int
	configuredBy string
	err          error
}

func (r *countingCredentialResolver) ResolveNotificationCredential(_ context.Context, _, _, configuredBy string) (*secret.Buffer, error) {
	r.calls++
	r.configuredBy = configuredBy
	if r.err != nil {
		return nil, r.err
	}
	return nil, errors.New("test resolver refused credential")
}

func TestChannelWorkerNamesReauthorizationWhenConfigurerLosesRead(t *testing.T) {
	resolver := &countingCredentialResolver{err: credref.ErrReadAuthorityRevoked}
	worker := &StoreChannelResolver{credentials: resolver}
	channel := worker.build(t.Context(), "tenant-a", "siem", store.NotificationChannel{
		CredentialRef: "secret://alerts/siem-token", ConfiguredBy: "former-reader",
	})
	err := channel.Notify(t.Context(), Alert{})
	if err == nil || !strings.Contains(err.Error(), "re-save this channel as an authorized principal") {
		t.Fatalf("revoked channel needs an actionable failure, got %v", err)
	}
}

func TestChannelWorkerRejectsNonTenantSecretReferences(t *testing.T) {
	for _, ref := range []string{"file:///tmp/control-plane.key", "env://CONTROL_PLANE_KEY", "secret://bad/../name"} {
		t.Run(ref, func(t *testing.T) {
			resolver := &countingCredentialResolver{}
			worker := &StoreChannelResolver{credentials: resolver}
			got := worker.build(t.Context(), "tenant-a", "siem", store.NotificationChannel{CredentialRef: ref})
			if resolver.calls != 0 {
				t.Fatalf("worker opened %q through the generic credential resolver", ref)
			}
			if _, ok := got.(failingChannel); !ok {
				t.Fatalf("worker accepted %q without a tenant secret", ref)
			}
		})
	}
}

func TestChannelWorkerStillOpensCanonicalTenantSecretReference(t *testing.T) {
	resolver := &countingCredentialResolver{}
	worker := &StoreChannelResolver{credentials: resolver}
	_ = worker.build(t.Context(), "tenant-a", "siem", store.NotificationChannel{
		CredentialRef: "secret://alerts/siem-token?version=2", ConfiguredBy: "operator-a",
	})
	if resolver.calls != 1 || resolver.configuredBy != "operator-a" {
		t.Fatalf("canonical tenant secret opened %d times under %q, want once under operator-a", resolver.calls, resolver.configuredBy)
	}
}
