// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/tenantseal"
)

type legacyKMIPFixtureAccess struct{ wrapper seal.KeyWrapper }

func (a legacyKMIPFixtureAccess) WithTenant(_ context.Context, _ string, fn func(tenantseal.Cipher) error) error {
	return fn(verifiedKMIPFixtureCipher{Cipher: legacyTenantCipher(a)})
}

type verifiedKMIPFixtureCipher struct{ tenantseal.Cipher }

func (c verifiedKMIPFixtureCipher) VerifyRewrapPair(before, after, aad []byte) (bool, error) {
	first, err := c.Open(before, aad)
	if err != nil {
		return false, err
	}
	defer secret.Wipe(first)
	second, err := c.Open(after, aad)
	if err != nil {
		return false, err
	}
	defer secret.Wipe(second)
	return bytes.Equal(first, second), nil
}

// The KMIP tests use real sealed key material. Authenticate it with the served
// ingress validator and the test's actual wrapper before admitting the event.
func openKMIPValidatedFixture(t *testing.T, wrapper func() seal.KeyWrapper) *events.Log {
	return openKMIPValidatedFixtureWithAccess(t, func() tenantseal.Access {
		if current := wrapper(); current != nil {
			return legacyKMIPFixtureAccess{wrapper: current}
		}
		return nil
	})
}

func openKMIPValidatedFixtureWithAccess(t *testing.T, access func() tenantseal.Access) *events.Log {
	t.Helper()
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true},
		events.WithRequiredAppendAdmission(), events.WithAppendAdmission(func(ctx context.Context, event events.Event,
			publish func(context.Context) (events.Event, error),
		) (events.Event, error) {
			if err := server.ValidateSealedIngressCandidate(ctx, access(), event); err != nil {
				return events.Event{}, err
			}
			return publish(ctx)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}
