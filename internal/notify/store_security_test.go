// SPDX-License-Identifier: BUSL-1.1

package notify

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

type countingCredentialResolver struct{ calls int }

func (r *countingCredentialResolver) ResolveNotificationCredential(context.Context, string, string) (*secret.Buffer, error) {
	r.calls++
	return nil, errors.New("test resolver refused credential")
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
	_ = worker.build(t.Context(), "tenant-a", "siem", store.NotificationChannel{CredentialRef: "secret://alerts/siem-token?version=2"})
	if resolver.calls != 1 {
		t.Fatalf("canonical tenant secret opened %d times, want once", resolver.calls)
	}
}
