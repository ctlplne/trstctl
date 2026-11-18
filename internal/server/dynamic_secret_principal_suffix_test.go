// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/dynsecret"
)

// recordingPrincipalBackend records every request the provider hands it.
type recordingPrincipalBackend struct{ seen []dynsecret.GenerateRequest }

func (r *recordingPrincipalBackend) CreateCredential(_ context.Context, req dynsecret.GenerateRequest) (string, []byte, error) {
	r.seen = append(r.seen, req)
	return "principal-ref", []byte("credential"), nil
}

func (*recordingPrincipalBackend) Revoke(context.Context, string) error { return nil }

// wrapOnlyKEK wraps keys but cannot derive a purpose-bound digest.
type wrapOnlyKEK struct{}

func (wrapOnlyKEK) WrapDEK(dek []byte) ([]byte, error)       { return dek, nil }
func (wrapOnlyKEK) UnwrapDEK(wrapped []byte) ([]byte, error) { return wrapped, nil }

func principalSuffixProvider(tenantID, id, providerType string, kek seal.KeyWrapper, backend requestDynamicBackend) *configuredDynamicProvider {
	return &configuredDynamicProvider{
		id: id, tenantID: tenantID,
		cfg:          config.DynamicSecretProviderConfig{TenantID: tenantID, ID: id, Type: providerType, AllowStaticRotation: true},
		allowedRoles: map[string]bool{"readonly": true}, maxTTL: time.Hour,
		credentials: integrationCredentialResolver{kek: kek},
		open:        func(context.Context) (requestDynamicBackend, func(), error) { return backend, func() {}, nil },
	}
}

// CR-220: the provider derives every lease's principal suffix under the
// deployment key, from its own tenant and ID, the lease's registration epoch
// and the lease, before any backend sees the request; without a key that can
// derive it, or with a suffix set by anyone else, nothing reaches the backend.
func TestProviderDerivesEachLeasesPrincipalSuffixUnderTheDeploymentKey(t *testing.T) {
	ctx := context.Background()
	kek, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kek.Destroy)
	const tenantA, tenantB = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	lease := dynsecret.GenerateRequest{Role: "readonly", TTL: time.Hour, LeaseID: "lease-kat-1", TenantEpoch: "epoch-kat-1"}

	suffixOf := func(t *testing.T, tenantID, id string, req dynsecret.GenerateRequest) string {
		t.Helper()
		backend := &recordingPrincipalBackend{}
		if _, err := principalSuffixProvider(tenantID, id, "postgresql", kek, backend).Generate(ctx, req); err != nil {
			t.Fatal(err)
		}
		if len(backend.seen) != 1 {
			t.Fatalf("backend saw %d requests, want 1", len(backend.seen))
		}
		got := backend.seen[0]
		if got.LeaseID != req.LeaseID || got.TenantEpoch != req.TenantEpoch || got.Role != req.Role {
			t.Fatalf("the backend's request %+v changed more than the suffix of %+v", got, req)
		}
		return got.PrincipalSuffix
	}

	// Known answer for the whole derivation (computed independently with
	// HKDF-SHA256 and HMAC-SHA256 over the length-prefixed fields).
	base := suffixOf(t, tenantA, "shared-pg", lease)
	if base != "fe279b06ccbde1b6" {
		t.Fatalf("principal suffix = %q, want the known answer fe279b06ccbde1b6", base)
	}
	if again := suffixOf(t, tenantA, "shared-pg", lease); again != base {
		t.Fatalf("a retry of the lease derived %q, want %q", again, base)
	}
	static := lease
	static.Static = true
	if got := suffixOf(t, tenantA, "shared-pg", static); got != base {
		t.Fatalf("a static rotation request derived %q, want %q", got, base)
	}
	otherEpoch, otherLease := lease, lease
	otherEpoch.TenantEpoch = "epoch-kat-2"
	otherLease.LeaseID = "lease-kat-2"
	seen := map[string]string{base: "base"}
	for name, got := range map[string]string{
		"another tenant, same provider ID and lease": suffixOf(t, tenantB, "shared-pg", lease),
		"a re-registered tenant (another epoch)":     suffixOf(t, tenantA, "shared-pg", otherEpoch),
		"another provider":                           suffixOf(t, tenantA, "other-pg", lease),
		"another lease":                              suffixOf(t, tenantA, "shared-pg", otherLease),
	} {
		if earlier, dup := seen[got]; dup {
			t.Errorf("%s derived %q, the same suffix as %s", name, got, earlier)
		}
		seen[got] = name
	}

	// A request with a lease but no registration epoch (the break-glass code
	// request, which names no principal) gets no suffix.
	noEpoch := lease
	noEpoch.TenantEpoch = ""
	if got := suffixOf(t, tenantA, "shared-pg", noEpoch); got != "" {
		t.Fatalf("a request without an epoch got suffix %q", got)
	}
	// A suffix that matches the provider's own derivation is accepted.
	preset := lease
	preset.PrincipalSuffix = base
	if got := suffixOf(t, tenantA, "shared-pg", preset); got != base {
		t.Fatalf("the lease's own pre-set suffix became %q", got)
	}

	differing := lease
	differing.PrincipalSuffix = "0123456789abcdef"
	unverifiable := noEpoch
	unverifiable.PrincipalSuffix = base
	for _, tc := range []struct {
		name string
		kek  seal.KeyWrapper
		req  dynsecret.GenerateRequest
	}{
		{"no deployment key", nil, lease},
		{"a key that cannot derive the digest", wrapOnlyKEK{}, lease},
		{"a pre-set suffix that is not this lease's", kek, differing},
		{"a pre-set suffix with no epoch to check it against", kek, unverifiable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, providerType := range []string{"postgresql", "aws-sts"} {
				backend := &recordingPrincipalBackend{}
				_, err := principalSuffixProvider(tenantA, "shared-pg", providerType, tc.kek, backend).Generate(ctx, tc.req)
				if err == nil {
					t.Fatalf("%s: the request was issued", providerType)
				}
				if len(backend.seen) != 0 {
					t.Fatalf("%s: the refused request reached the backend: %+v", providerType, backend.seen)
				}
				// An at-most-once provider records that nothing was submitted.
				if providerType == "aws-sts" && err.Error() != "orchestrator: protected mutation was not submitted" {
					t.Fatalf("aws-sts refusal = %v, want the confirmed no-mutation result", err)
				}
			}
		})
	}
}
