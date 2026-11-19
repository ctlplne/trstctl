// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/store"
)

type staticPredecessorRecorder struct {
	revoked      []string
	providerType string
}

func (*staticPredecessorRecorder) Name() string { return "fixture-provider" }

func (p *staticPredecessorRecorder) DynamicSecretProviderType() string { return p.providerType }

func (*staticPredecessorRecorder) Generate(context.Context, dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	return dynsecret.Credential{}, errors.New("retirement fixture cannot generate credentials")
}

func (p *staticPredecessorRecorder) Revoke(_ context.Context, reference string) error {
	p.revoked = append(p.revoked, reference)
	return nil
}

// CR-231: an already recorded command's unproved OldRef must not become
// provider retirement authority when its worker resumes.
func TestStaticRetirementRefusesUnprovedRecordedPredecessor(t *testing.T) {
	api := &API{}
	provider := &staticPredecessorRecorder{}
	command := store.SecretStaticRotationCommand{
		Provider: provider.Name(), Key: "fixture-key", OldRef: "unbound-predecessor", NewRef: "issued-successor",
		Phase: store.SecretStaticRotationVerified,
	}
	if err := api.revokeStaticRotationReference(t.Context(), command, provider, true); err == nil {
		t.Error("retirement accepted a predecessor without a source proof")
	}
	if len(provider.revoked) != 0 {
		t.Fatal("retirement reached the provider before proving the predecessor")
	}
}

// CR-231: a reused configured provider ID must not transfer reference
// authority from an earlier native provider to a different backend family.
func TestStaticRotationReferenceRejectsNativeProviderReplacement(t *testing.T) {
	provider := &staticPredecessorRecorder{providerType: "mysql"}
	prior := store.SecretStaticRotationCommand{Provider: provider.Name(), ProviderType: "postgresql"}
	const native = store.SecretRotationScheduleNativeReference
	if staticRotationProviderKeepsReferenceAuthority(prior, provider, native, native, false) {
		t.Fatal("a different native backend inherited the earlier reference authority")
	}
	prior.ProviderType = "mysql"
	if !staticRotationProviderKeepsReferenceAuthority(prior, provider, native, native, false) {
		t.Fatal("the original backend no longer holds the reference authority")
	}
}

func TestStaticRotationLegacyQueueRequiresNativeProviderProofBeforeStaging(t *testing.T) {
	provider := &staticPredecessorRecorder{providerType: "mysql"}
	cmd := store.SecretStaticRotationCommand{Provider: provider.Name(), Phase: store.SecretStaticRotationQueued, OldRef: "none"}
	const native = store.SecretRotationScheduleNativeReference
	if staticRotationProviderKeepsReferenceAuthority(cmd, provider, native, native, false) {
		t.Fatal("provider classification alone granted an untyped legacy command staging authority")
	}
	if !staticRotationProviderKeepsReferenceAuthority(cmd, provider, native, native, true) {
		t.Fatal("a native queue with exact authority was refused")
	}
	provider.providerType = "openrouter"
	if staticRotationProviderKeepsReferenceAuthority(cmd, provider, "openrouter", "", false) {
		t.Fatal("a legacy source with no family acquired a hosted provider")
	}
	if !staticRotationProviderKeepsReferenceAuthority(cmd, provider, "openrouter", "openrouter", false) {
		t.Fatal("a legacy source with an exact hosted family was refused")
	}
}
