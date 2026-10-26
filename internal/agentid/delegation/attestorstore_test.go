// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

func TestDurableAttestationTrustStore_VerifiesSignedEvidence(t *testing.T) {
	signer, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	store := NewDurableAttestationTrustStore(t.TempDir())
	if err := store.PutVerifier(context.Background(), "attestor-1", signer.Public().DER); err != nil {
		t.Fatalf("PutVerifier: %v", err)
	}
	payload, err := SignAttestation(signer, "attestor-1", "software", "agent-1",
		map[string]string{"attestation_class": "software"}, []byte("nonce-1"))
	if err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}
	got, err := store.VerifyEvidence("software", payload)
	if err != nil {
		t.Fatalf("VerifyEvidence: %v", err)
	}
	if got.Subject != "agent-1" || got.Claims["attestation_class"] != "software" {
		t.Fatalf("verified attestation = %+v", got)
	}
	if _, err := store.VerifyEvidence("software", payload); !errors.Is(err, ErrAttestationReplay) {
		t.Fatalf("VerifyEvidence(replay) = %v, want ErrAttestationReplay", err)
	}
	if _, err := store.VerifyEvidence("tpm", payload); !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("VerifyEvidence(method mismatch) = %v, want ErrAttestationInvalid", err)
	}
}

// A150: a tenant's attestor is held by the signer's floor under that tenant and
// one method. It decides that tenant's evidence alone, cannot vouch for another
// method or a higher class, and is never consulted for another tenant.
func TestDurableAttestationTrustStore_TenantAttestors(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store := NewDurableAttestationTrustStore(dir)
	backend := crypto.NewSoftwareBackend()
	tenantKey, err := backend.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := backend.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	const tenantA, tenantB = "tenant-a", "tenant-b"

	if err := store.ProvisionAgentAttestor(ctx, tenantA, "att-1", tenantKey.Public().DER, "unknown-method"); !errors.Is(err, signing.ErrAgentAttestorInvalid) {
		t.Fatalf("unknown method = %v, want ErrAgentAttestorInvalid", err)
	}
	if err := store.ProvisionAgentAttestor(ctx, tenantA, "../att-1", tenantKey.Public().DER, "tpm"); !errors.Is(err, signing.ErrAgentAttestorInvalid) {
		t.Fatalf("unsafe key ID = %v, want ErrAgentAttestorInvalid", err)
	}
	if err := store.ProvisionAgentAttestor(ctx, tenantA, "att-1", []byte("not a key"), "tpm"); !errors.Is(err, signing.ErrAgentAttestorInvalid) {
		t.Fatalf("unusable key = %v, want ErrAgentAttestorInvalid", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := store.ProvisionAgentAttestor(ctx, tenantA, "att-1", tenantKey.Public().DER, "tpm"); err != nil {
			t.Fatalf("provision attempt %d: %v", attempt, err)
		}
	}
	if err := store.ProvisionAgentAttestor(ctx, tenantA, "att-1", otherKey.Public().DER, "tpm"); !errors.Is(err, signing.ErrAgentAttestorConflict) {
		t.Fatalf("changed key = %v, want ErrAgentAttestorConflict", err)
	}
	if err := store.ProvisionAgentAttestor(ctx, tenantA, "att-1", tenantKey.Public().DER, "hsm"); !errors.Is(err, signing.ErrAgentAttestorConflict) {
		t.Fatalf("changed method = %v, want ErrAgentAttestorConflict", err)
	}
	der, method, err := store.ReadAgentAttestor(ctx, tenantA, "att-1")
	if err != nil || !bytes.Equal(der, tenantKey.Public().DER) || method != "tpm" {
		t.Fatalf("readback = method %q, %v", method, err)
	}
	if _, _, err := store.ReadAgentAttestor(ctx, tenantB, "att-1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("other tenant's readback = %v, want not found", err)
	}

	evidence := func(signer crypto.Signer, keyID, method, nonce string, claims map[string]string) []byte {
		t.Helper()
		payload, err := SignAttestation(signer, keyID, method, "agent-1", claims, []byte(nonce))
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	good := evidence(tenantKey, "att-1", "tpm", "n1", nil)
	got, err := store.VerifyTenantEvidence(tenantA, "tpm", good)
	if err != nil || got.Method != "tpm" || got.Subject != "agent-1" {
		t.Fatalf("tenant evidence = %+v, %v", got, err)
	}
	if _, err := store.VerifyTenantEvidence(tenantA, "tpm", good); !errors.Is(err, ErrAttestationReplay) {
		t.Fatalf("replayed tenant evidence = %v, want ErrAttestationReplay", err)
	}
	if _, err := store.VerifyTenantEvidence(tenantB, "tpm", evidence(tenantKey, "att-1", "tpm", "n2", nil)); !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("another tenant's attestor = %v, want refused", err)
	}
	if _, err := store.VerifyEvidence("tpm", evidence(tenantKey, "att-1", "tpm", "n3", nil)); !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("tenant attestor without a tenant = %v, want refused", err)
	}
	if _, err := store.VerifyTenantEvidence(tenantA, "software", evidence(tenantKey, "att-1", "software", "n4", nil)); !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("evidence for another method = %v, want refused", err)
	}
	if _, err := store.VerifyTenantEvidence(tenantA, "tpm", evidence(tenantKey, "att-1", "tpm", "n5", map[string]string{"attestation_class": "hsm"})); !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("evidence claiming a class above the method = %v, want refused", err)
	}
	if got, err := store.VerifyTenantEvidence(tenantA, "tpm", evidence(tenantKey, "att-1", "tpm", "n6", map[string]string{"attestation_class": "software"})); err != nil || classOfAttestation(got) != ClassSoftware {
		t.Fatalf("evidence claiming a lower class = %+v, %v", got, err)
	}
	if _, err := store.VerifyTenantEvidence(tenantA, "tpm", evidence(otherKey, "att-1", "tpm", "n7", nil)); !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("evidence signed by another key = %v, want refused", err)
	}

	// The operator floor still serves every tenant, unless a tenant registered
	// the same key ID: then the tenant's own binding decides for that tenant.
	operatorKey, err := backend.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutVerifier(ctx, "op-1", operatorKey.Public().DER); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyTenantEvidence(tenantB, "software", evidence(operatorKey, "op-1", "software", "n8", nil)); err != nil {
		t.Fatalf("operator attestor for a tenant without its own = %v", err)
	}
	if err := store.ProvisionAgentAttestor(ctx, tenantA, "op-1", otherKey.Public().DER, "software"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyTenantEvidence(tenantA, "software", evidence(operatorKey, "op-1", "software", "n9", nil)); !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("operator key under a tenant-registered key ID = %v, want refused", err)
	}
	if _, err := store.VerifyTenantEvidence(tenantB, "software", evidence(operatorKey, "op-1", "software", "n10", nil)); err != nil {
		t.Fatalf("operator key for the other tenant = %v", err)
	}

	// Half a binding refuses instead of falling back, reads back as absent, and
	// an exact retry completes it.
	if err := os.Remove(filepath.Join(dir, attestorTenantFloorDir, tenantA, "att-1.method")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReadAgentAttestor(ctx, tenantA, "att-1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("half-written binding readback = %v, want not found", err)
	}
	if _, err := store.VerifyTenantEvidence(tenantA, "tpm", evidence(tenantKey, "att-1", "tpm", "n11", nil)); !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("half-written binding = %v, want refused", err)
	}
	if err := store.ProvisionAgentAttestor(ctx, tenantA, "att-1", tenantKey.Public().DER, "tpm"); err != nil {
		t.Fatalf("exact retry completing the binding: %v", err)
	}
	if _, err := store.VerifyTenantEvidence(tenantA, "tpm", evidence(tenantKey, "att-1", "tpm", "n12", nil)); err != nil {
		t.Fatalf("completed binding = %v", err)
	}
}

// The key ID inside evidence is untrusted. It must name an attestor, never a
// path to another public file on the signer's floor.
func TestDurableAttestationTrustStore_EvidenceKeyIDIsNotAPath(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	signer, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewDurableReachabilityTrustStore(dir).PutVerdictSigner(ctx, "verdict-key", signer.Public().DER); err != nil {
		t.Fatal(err)
	}
	store := NewDurableAttestationTrustStore(dir)
	if err := store.PutVerifier(ctx, "../escape", signer.Public().DER); err == nil {
		t.Fatal("an operator key ID with a path separator was stored")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var reachDir string
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != attestorFloorDir {
			reachDir = entry.Name()
		}
	}
	payload, err := SignAttestation(signer, "../"+reachDir+"/verdict-key", "software", "agent-1", nil, []byte("n1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"", "tenant-a"} {
		if _, err := store.VerifyTenantEvidence(tenant, "software", payload); !errors.Is(err, ErrAttestationInvalid) {
			t.Fatalf("evidence naming another floor file (tenant %q) = %v, want refused", tenant, err)
		}
	}
}
