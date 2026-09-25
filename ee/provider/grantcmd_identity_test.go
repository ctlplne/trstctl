// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestGrantCommandAuthorizesTheSCIMBoundOIDCIdentity(t *testing.T) {
	ctx := t.Context()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	natsConfig := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true}
	log, err := events.Open(ctx, natsConfig)
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewAuthorityRuntime(st, log)
	now := time.Now().UTC()
	identity := OperatorIdentity{
		ID: "bb5dc4af-8d53-4559-8c13-3d14170a9cb5", ExternalID: "idp-subject-1",
		UserName: "operator@provider.example", Email: "operator@provider.example",
		Role: OperatorAdmin, Active: true, Source: "scim:workforce", CreatedAt: now, UpdatedAt: now,
	}
	if _, err := runtime.Mutations.Append(ctx, "seed-operator", EventOperatorUpserted, providerAuthorityTenant,
		AuthorityEvent{Operator: &identity, EffectiveAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	args := []string{"-operator", identity.ExternalID, "-customer", "bootstrap-customer",
		"-operations", "read,break-glass", "-granted-by", "platform-admin", "-idempotency-key", "bootstrap-1"}
	run := func(args []string) (string, error) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		err := RunGrantCommand(ctx, providerTestDSN, natsConfig, args, &stdout, &stderr)
		return stdout.String(), err
	}
	output, err := run(args)
	if err != nil {
		t.Fatal(err)
	}
	f := newOIDCFixture(t)
	f.auth.cfg.Directory = NewPGAccessStore(st)
	f.auth.cfg.RequireDirectory = true
	claims := f.baseClaims()
	claims["sub"] = identity.ExternalID
	op, ok := f.auth.AuthenticateOperator(f.request(t, f.signer, "idp-k1", claims))
	if !ok || op.ID != identity.ID || !op.MFA {
		t.Fatalf("directory-bound operator = %+v, authenticated=%v", op, ok)
	}
	source := NewPGDelegationSource(st)
	assertScope := func(allowed bool) {
		t.Helper()
		set, err := source.Delegations(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, operation := range []Operation{OpRead, OpBreakGlass} {
			if err := set.Authorize(op, CustomerID("bootstrap-customer"), operation); (err == nil) != allowed {
				t.Fatalf("signed directory identity allowed=%v for %s: %v; command output: %s", allowed, operation, err, output)
			}
		}
		if set.Authorize(op, CustomerID("another-customer"), OpRead) == nil ||
			set.Authorize(op, CustomerID("bootstrap-customer"), OpOffboard) == nil {
			t.Fatal("bootstrap widened customer or operation scope")
		}
		if set.Authorize(Operator{ID: identity.ExternalID}, CustomerID("bootstrap-customer"), OpRead) == nil {
			t.Fatal("grant was also attached to the raw IdP subject")
		}
	}
	assertScope(true)
	if !strings.Contains(output, identity.ID) {
		t.Fatalf("success does not identify the effective directory operator: %s", output)
	}
	before, err := NewPGAccessStore(st).ListOperatorAccess(ctx)
	if err != nil || len(before) != 1 || len(before[0].Delegations) != 2 {
		t.Fatalf("initial authority = %+v, %v", before, err)
	}
	if retry, err := run(args); err != nil || retry != output {
		t.Fatalf("identical command retry = %q, %v", retry, err)
	}
	after, err := NewPGAccessStore(st).ListOperatorAccess(ctx)
	if err != nil || len(after) != 1 || len(after[0].Delegations) != 2 ||
		!after[0].Delegations[0].GrantedAt.Equal(before[0].Delegations[0].GrantedAt) {
		t.Fatalf("retry changed authority: %+v, %v", after, err)
	}
	changed := append([]string(nil), args...)
	changed[5] = "offboard"
	if _, err := run(changed); !errors.Is(err, ErrMutationConflict) {
		t.Fatalf("changed command reused the same key: %v", err)
	}
	assertScope(true)
	revoke := append([]string(nil), args...)
	revoke[1], revoke[9] = identity.UserName, "revoke-1"
	revoke = append(revoke, "-revoke")
	if _, err := run(revoke); err != nil {
		t.Fatal(err)
	}
	assertScope(false)
	if _, err := run(args); err != nil {
		t.Fatal(err)
	}
	assertScope(false) // Replaying the old grant must not undo the later revocation.
	unknown := append([]string(nil), args...)
	unknown[1], unknown[9] = "not-provisioned", "unknown-1"
	var stdout, stderr bytes.Buffer
	if err := RunGrantCommand(ctx, providerTestDSN, natsConfig, unknown, &stdout, &stderr,
		GrantCommandOptions{RequireDirectory: true}); !errors.Is(err, ErrNotFound) || stdout.Len() != 0 {
		t.Fatalf("SCIM-required unknown operator result = %q, %v", stdout.String(), err)
	}
	assertScope(false)
}

type unavailableGrantDirectory struct{}

func (unavailableGrantDirectory) ResolveOperator(context.Context, string) (OperatorIdentity, error) {
	return OperatorIdentity{}, errors.New("directory unavailable")
}

func TestGrantOperatorResolutionFailsClosed(t *testing.T) {
	directory := newAUD58AccessStore()
	directory.identities["canonical"] = OperatorIdentity{
		ID: "canonical", ExternalID: "subject", UserName: "name", Active: true,
	}
	for _, reference := range []string{"canonical", "subject", "name"} {
		got, err := resolveGrantOperator(t.Context(), directory, reference, true, false)
		if err != nil || got != "canonical" {
			t.Fatalf("reference %q resolved to %q: %v", reference, got, err)
		}
	}
	if got, err := resolveGrantOperator(t.Context(), directory, "unprovisioned-subject", false, false); err != nil || got != "unprovisioned-subject" {
		t.Fatalf("non-SCIM bootstrap = %q, %v", got, err)
	}
	for _, revoke := range []bool{false, true} {
		if _, err := resolveGrantOperator(t.Context(), directory, "missing", true, revoke); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing required directory identity revoke=%v: %v", revoke, err)
		}
		for _, required := range []bool{false, true} {
			if got, err := resolveGrantOperator(t.Context(), unavailableGrantDirectory{}, "subject", required, revoke); err == nil || got != "" {
				t.Fatalf("directory outage allowed fallback: %q, %v", got, err)
			}
		}
	}
	identity := directory.identities["canonical"]
	identity.Active = false
	directory.identities["canonical"] = identity
	if _, err := resolveGrantOperator(t.Context(), directory, "subject", true, false); !errors.Is(err, ErrForbidden) {
		t.Fatalf("inactive identity received a grant: %v", err)
	}
	if got, err := resolveGrantOperator(t.Context(), directory, "subject", true, true); err != nil || got != "canonical" {
		t.Fatalf("inactive identity could not have authority revoked: %q, %v", got, err)
	}
}
