package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// Fixed ids for the core-entity graph under test.
const (
	idOwner     = "a0000000-0000-0000-0000-000000000001"
	idIssuer    = "a0000000-0000-0000-0000-000000000002"
	idIdentity  = "a0000000-0000-0000-0000-000000000003"
	idTarget    = "a0000000-0000-0000-0000-000000000004"
	idAgent     = "a0000000-0000-0000-0000-000000000005"
	idPolicy    = "a0000000-0000-0000-0000-000000000006"
	idAttest    = "a0000000-0000-0000-0000-000000000007"
	idSSHIssuer = "a0000000-0000-0000-0000-000000000008"
)

const samplePEM = "-----BEGIN CERTIFICATE-----\nMIIBdummychain\n-----END CERTIFICATE-----"

func strptr(s string) *string { return &s }

// TestCoreEntitiesPersistAndLoad is the acceptance: every top-level entity
// persists and loads through its tenant-guarded repository, including the
// Identity → Owner/Issuer references and an Attestation → Identity reference.
func TestCoreEntitiesPersistAndLoad(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	owner := store.Owner{ID: idOwner, TenantID: tenantA, Kind: store.OwnerService, Name: "billing-svc", Email: "billing@acme.test"}
	if err := s.UpsertOwner(ctx, owner); err != nil {
		t.Fatalf("UpsertOwner: %v", err)
	}
	issuer := store.Issuer{ID: idIssuer, TenantID: tenantA, Kind: store.IssuerX509CA, Name: "Acme Root", Internal: true, Chain: []string{samplePEM}}
	if err := s.UpsertIssuer(ctx, issuer); err != nil {
		t.Fatalf("UpsertIssuer: %v", err)
	}

	nb := time.Now().UTC().Truncate(time.Second)
	na := nb.Add(24 * time.Hour)
	ident := store.Identity{
		ID: idIdentity, TenantID: tenantA, Kind: store.KindX509Certificate,
		Name: "billing.acme.test", OwnerID: idOwner, IssuerID: strptr(idIssuer),
		Status: "issued", NotBefore: &nb, NotAfter: &na,
		Attributes: json.RawMessage(`{"san": ["billing.acme.test"]}`),
	}
	if err := s.UpsertIdentity(ctx, ident); err != nil {
		t.Fatalf("UpsertIdentity: %v", err)
	}

	target := store.DeploymentTarget{ID: idTarget, TenantID: tenantA, Name: "prod-k8s", Type: "kubernetes", Config: json.RawMessage(`{"namespace": "prod"}`)}
	if err := s.UpsertDeploymentTarget(ctx, target); err != nil {
		t.Fatalf("UpsertDeploymentTarget: %v", err)
	}
	agent := store.Agent{ID: idAgent, TenantID: tenantA, Name: "edge-1", Status: "active", Version: "0.1.0"}
	if err := s.UpsertAgent(ctx, agent); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	pb := store.PolicyBinding{ID: idPolicy, TenantID: tenantA, Name: "default-issuance", Policy: "issuance.allow", Scope: json.RawMessage(`{"kind": "x509_certificate"}`)}
	if err := s.UpsertPolicyBinding(ctx, pb); err != nil {
		t.Fatalf("UpsertPolicyBinding: %v", err)
	}
	att := store.Attestation{ID: idAttest, TenantID: tenantA, IdentityID: strptr(idIdentity), Kind: "spiffe", Evidence: json.RawMessage(`{"spiffe_id": "spiffe://acme/billing"}`)}
	if err := s.UpsertAttestation(ctx, att); err != nil {
		t.Fatalf("UpsertAttestation: %v", err)
	}

	// Load each back in the tenant's context.
	gotOwner, err := s.GetOwner(ctx, tenantA, idOwner)
	if err != nil {
		t.Fatalf("GetOwner: %v", err)
	}
	if gotOwner.Name != "billing-svc" || gotOwner.Kind != store.OwnerService || gotOwner.Email != "billing@acme.test" {
		t.Errorf("owner round-trip = %+v", gotOwner)
	}

	gotIdent, err := s.GetIdentity(ctx, tenantA, idIdentity)
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if gotIdent.Kind != store.KindX509Certificate || gotIdent.OwnerID != idOwner {
		t.Errorf("identity round-trip = %+v", gotIdent)
	}
	if gotIdent.IssuerID == nil || *gotIdent.IssuerID != idIssuer {
		t.Errorf("identity issuer ref = %v, want %s", gotIdent.IssuerID, idIssuer)
	}
	if gotIdent.NotAfter == nil || !gotIdent.NotAfter.Equal(na) {
		t.Errorf("identity not_after = %v, want %v", gotIdent.NotAfter, na)
	}
	var attrs map[string]any
	if err := json.Unmarshal(gotIdent.Attributes, &attrs); err != nil {
		t.Fatalf("identity attributes not valid json: %v (%s)", err, gotIdent.Attributes)
	}

	gotAtt, err := s.GetAttestation(ctx, tenantA, idAttest)
	if err != nil {
		t.Fatalf("GetAttestation: %v", err)
	}
	if gotAtt.IdentityID == nil || *gotAtt.IdentityID != idIdentity || gotAtt.Kind != "spiffe" {
		t.Errorf("attestation round-trip = %+v", gotAtt)
	}

	// Every list returns the single row for the tenant.
	for name, n := range map[string]int{
		"owners":             mustLen(t, func() (int, error) { v, e := s.ListOwners(ctx, tenantA); return len(v), e }),
		"issuers":            mustLen(t, func() (int, error) { v, e := s.ListIssuers(ctx, tenantA); return len(v), e }),
		"identities":         mustLen(t, func() (int, error) { v, e := s.ListIdentities(ctx, tenantA); return len(v), e }),
		"deployment_targets": mustLen(t, func() (int, error) { v, e := s.ListDeploymentTargets(ctx, tenantA); return len(v), e }),
		"agents":             mustLen(t, func() (int, error) { v, e := s.ListAgentsPage(ctx, tenantA, nil, store.ZeroUUID, 20); return len(v), e }),
		"policy_bindings":    mustLen(t, func() (int, error) { v, e := s.ListPolicyBindings(ctx, tenantA); return len(v), e }),
		"attestations":       mustLen(t, func() (int, error) { v, e := s.ListAttestations(ctx, tenantA); return len(v), e }),
	} {
		if n != 1 {
			t.Errorf("List %s returned %d, want 1", name, n)
		}
	}
}

func mustLen(t *testing.T, f func() (int, error)) int {
	t.Helper()
	n, err := f()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	return n
}

// TestRepositoriesAreTenantGuarded is the AN-1 acceptance: a repository read in
// one tenant's context cannot see another tenant's rows.
func TestRepositoriesAreTenantGuarded(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if err := s.UpsertOwner(ctx, store.Owner{ID: idOwner, TenantID: tenantA, Kind: store.OwnerService, Name: "acme-svc"}); err != nil {
		t.Fatal(err)
	}

	// Tenant B cannot read tenant A's owner.
	if _, err := s.GetOwner(ctx, tenantB, idOwner); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("GetOwner from tenant B = %v, want ErrNoRows (RLS must hide it)", err)
	}
	// ...nor see it in a listing.
	list, err := s.ListOwners(ctx, tenantB)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Errorf("tenant B lists %d owners, want 0", len(list))
	}
	// Tenant A still sees its own.
	if _, err := s.GetOwner(ctx, tenantA, idOwner); err != nil {
		t.Errorf("GetOwner from tenant A: %v", err)
	}
}

// TestIssuerDistinguishesX509FromChainlessSSH is the acceptance that the Issuer
// model captures an X.509 CA (carries a chain) versus the chainless SSH CA (a
// single trusted signing key, no chain).
func TestIssuerDistinguishesX509FromChainlessSSH(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	x509 := store.Issuer{ID: idIssuer, TenantID: tenantA, Kind: store.IssuerX509CA, Name: "Acme Root", Chain: []string{samplePEM}}
	ssh := store.Issuer{ID: idSSHIssuer, TenantID: tenantA, Kind: store.IssuerSSHCA, Name: "fleet-ssh-ca", PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 fleet"}
	if err := s.UpsertIssuer(ctx, x509); err != nil {
		t.Fatalf("upsert x509 CA: %v", err)
	}
	if err := s.UpsertIssuer(ctx, ssh); err != nil {
		t.Fatalf("upsert ssh CA: %v", err)
	}

	gotX, err := s.GetIssuer(ctx, tenantA, idIssuer)
	if err != nil {
		t.Fatal(err)
	}
	if gotX.Chainless() {
		t.Error("X.509 CA reported Chainless")
	}
	if len(gotX.Chain) == 0 {
		t.Error("X.509 CA must carry a chain")
	}
	if gotX.PublicKey != "" {
		t.Error("X.509 CA must not carry a standalone SSH signing key")
	}

	gotS, err := s.GetIssuer(ctx, tenantA, idSSHIssuer)
	if err != nil {
		t.Fatal(err)
	}
	if !gotS.Chainless() {
		t.Error("SSH CA must be chainless")
	}
	if len(gotS.Chain) != 0 {
		t.Error("SSH CA must have no chain")
	}
	if gotS.PublicKey == "" {
		t.Error("SSH CA must carry its single trusted signing key")
	}

	// Validate rejects the impossible combinations.
	if err := (store.Issuer{Kind: store.IssuerSSHCA, Name: "x", Chain: []string{samplePEM}}).Validate(); err == nil {
		t.Error("an SSH CA carrying a chain must be invalid")
	}
	if err := (store.Issuer{Kind: store.IssuerX509CA, Name: "x"}).Validate(); err == nil {
		t.Error("an X.509 CA without a chain must be invalid")
	}
	// ...and the repository enforces it.
	if err := s.UpsertIssuer(ctx, store.Issuer{ID: idIssuer, TenantID: tenantA, Kind: store.IssuerSSHCA, Name: "bad", Chain: []string{samplePEM}}); err == nil {
		t.Error("UpsertIssuer must reject an SSH CA that carries a chain")
	}
}
