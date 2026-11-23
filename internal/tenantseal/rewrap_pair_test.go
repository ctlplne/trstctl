// SPDX-License-Identifier: BUSL-1.1
package tenantseal_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/tenantseal"
)

func TestTenantAccessAuthenticatesDEKOnlyRewrapInOneLease(t *testing.T) {
	deployment := newTestKEK(t, 0x71)
	access, err := tenantseal.NewAccess(&fakeDomainStore{}, deployment,
		&recordingRegistry{err: errors.New("tenant wrapper must not be consulted")})
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte(testTenantA + "/secret-store/name")
	before, err := seal.Seal(deployment, []byte("same-value"), aad)
	if err != nil {
		t.Fatal(err)
	}
	after, changed, err := seal.RewrapContainerDEK(before, func(wrapped []byte) ([]byte, bool, error) {
		dek, err := deployment.UnwrapDEK(wrapped)
		if err != nil {
			return nil, false, err
		}
		defer secret.Wipe(dek)
		next, err := deployment.WrapDEK(dek)
		return next, true, err
	})
	if err != nil || !changed || bytes.Equal(before, after) {
		t.Fatalf("DEK-only test rewrap changed=%t err=%v", changed, err)
	}
	if equal, err := tenantseal.VerifyRewrapPair(context.Background(), access, testTenantA, before, after, aad); err != nil || !equal {
		t.Fatalf("tenant pair equal=%t err=%v, want authenticated match", equal, err)
	}
	fresh, err := seal.Seal(deployment, []byte("same-value"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if equal, err := tenantseal.VerifyRewrapPair(context.Background(), access, testTenantA, before, fresh, aad); err != nil || equal {
		t.Fatalf("fresh payload encryption equal=%t err=%v, want mismatch", equal, err)
	}
	if equal, err := tenantseal.VerifyRewrapPair(context.Background(), access, testTenantA, before, after, []byte("wrong-name")); !errors.Is(err, seal.ErrDecrypt) || equal {
		t.Fatalf("wrong AAD equal=%t err=%v, want decrypt refusal", equal, err)
	}
}
