// SPDX-License-Identifier: BUSL-1.1

// CR-011 served regression for S4-L1: import_existing_ca must reject signer
// handles that are unowned, reserved for the platform, or owned by a neighbor.
// The initial reproduction also established these attack preconditions:
//   - who the attacker must be: a single admin cannot approve with a token it
//     minted for a second subject (F262 refuses delegated approvals), so the
//     attacker tenant needs two of its own principals holding issuers:write;
//   - another tenant's claimed ca-hierarchy-* handle (expected: refused);
//   - another tenant's PCAS trust root (handle derivable from the tenant id,
//     created with the exact client call the genesis worker makes);
//   - another tenant's AGID issuing-CA key (handle derivable from the tenant id);
//   - the platform agent-ca;
//   - the platform issuing-ca.
//
// The attacker never sees a private key; it needs only public material (the
// victim key's public half or the public CA certificate).
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/succession"
)

const v5AttackerTenant = "44444444-4444-4444-8444-444444444444"

type v5Attacker struct {
	t     *testing.T
	h     *servedHarness
	admin string // the attacker tenant's CA operator (issuers:write)
	ghost string // a second subject the operator minted through the served API (delegated)
	cust  string // a second, self-authenticated principal of the attacker tenant (issuers:write)
	n     int
}

func (a *v5Attacker) idem(label string) string {
	a.n++
	return fmt.Sprintf("v5-%s-%d", label, a.n)
}

// bind runs the whole served import_existing_ca flow for handle.
func (a *v5Attacker) bind(label, handle, chainPEM string, spec map[string]any) (int, servedCAAuthority, []byte) {
	a.t.Helper()
	ceremony := createImportExistingCACeremony(a.t, a.h, a.admin, chainPEM, handle, spec, 1, a.idem(label+"-ceremony"))
	approveCACeremony(a.t, a.h, a.cust, ceremony.ID, 1, a.idem(label+"-approval"))
	code, body := doBearer(a.t, a.h.ts, http.MethodPost, "/api/v1/ca/authorities/imported", a.admin, a.idem(label+"-import"), map[string]any{
		"ceremony_id": ceremony.ID, "certificate_pem": chainPEM, "signer_handle": handle, "spec": spec,
	})
	var got servedCAAuthority
	if code == http.StatusCreated {
		if err := json.Unmarshal(body, &got); err != nil {
			a.t.Fatalf("%s: decode imported authority: %v body=%s", label, err, body)
		}
	}
	return code, got, body
}

func (a *v5Attacker) expectOwnershipConflict(label string, code int, body []byte) {
	a.t.Helper()
	if code != http.StatusConflict {
		a.t.Errorf("%s: cross-tenant or reserved handle import = HTTP %d body=%s; want 409", label, code, body)
	}
}

// issue mints a leaf for tmpl from the attacker's authority and returns its DER.
func (a *v5Attacker) issue(label, authorityID string, tmpl crypto.CertificateRequestTemplate) []byte {
	a.t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		a.t.Fatal(err)
	}
	a.t.Cleanup(key.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(tmpl, key)
	if err != nil {
		a.t.Fatalf("%s: CSR: %v", label, err)
	}
	code, body := doBearer(a.t, a.h.ts, http.MethodPost, "/api/v1/ca/authorities/"+authorityID+"/issue", a.admin, a.idem(label+"-leaf"), map[string]any{
		"csr_pem":     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		"ttl_seconds": int64((24 * time.Hour).Seconds()),
	})
	if code != http.StatusCreated {
		a.t.Errorf("%s: leaf issuance under the bound authority = HTTP %d body=%s", label, code, body)
		return nil
	}
	var leaf servedCAIssuedLeaf
	if err := json.Unmarshal(body, &leaf); err != nil || leaf.CertificatePEM == "" {
		a.t.Fatalf("%s: decode leaf: %v body=%s", label, err, body)
	}
	return caCertDER(a.t, []byte(leaf.CertificatePEM))
}

// revoke runs the attacker tenant's own revoke_ca ceremony for authorityID.
func (a *v5Attacker) revoke(label, authorityID string) (int, []byte) {
	a.t.Helper()
	ceremony := startCARevokeCeremony(a.t, a.h, a.admin, authorityID, "key_compromise", a.idem(label+"-revoke-ceremony"))
	approveCACeremony(a.t, a.h, a.cust, ceremony.ID, 1, a.idem(label+"-revoke-approval"))
	return doBearer(a.t, a.h.ts, http.MethodPost, "/api/v1/ca/authorities/"+authorityID+"/revoke", a.admin, a.idem(label+"-revoke"), map[string]any{
		"ceremony_id": ceremony.ID, "reason": "key_compromise",
	})
}

// fabricatedChain is what an attacker who knows only a victim key's PUBLIC half
// presents: an intermediate over that public key, named like the victim's CA,
// signed by an attacker-made root. Nothing anchors the root.
func v5FabricatedChain(t *testing.T, victimPublic crypto.PublicKey, victimCN string) (string, []byte) {
	t.Helper()
	rootKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rootKey.Destroy)
	root, err := crypto.SelfSignedHierarchyCA(rootKey, crypto.HierarchyCAProfile{CommonName: "V5 attacker root", MaxPathLen: 1, TTL: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("attacker root: %v", err)
	}
	inter, err := crypto.SignIntermediateHierarchyCA(root.CertificateDER, rootKey, victimPublic, crypto.HierarchyCAProfile{CommonName: victimCN, MaxPathLen: 0, TTL: 20 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("attacker intermediate over the victim public key: %v", err)
	}
	return string(inter.CertificatePEM) + string(root.CertificatePEM), inter.CertificateDER
}

func v5Spec(cn string, maxPathLen int) map[string]any {
	return map[string]any{
		"common_name": cn, "max_path_len": maxPathLen,
		"ttl_seconds": int64((2 * 365 * 24 * time.Hour).Seconds()), "signature_algorithm": "ecdsa-p256",
	}
}

func TestV5L1TenantAdminBindsUnclaimedSignerHandlesAcrossTenants(t *testing.T) {
	ctx := context.Background()
	h := newOperatingServedHarness(t, config.Protocols{}, withAgentChannel)
	client := h.signer.Client()
	victim := h.tenant // the operating tenant fixture

	// The attacker is a neighbouring tenant: its CA operator (an ordinary
	// operator-role permission set) and one more principal of its own.
	registerServedTenantID(t, h, v5AttackerTenant, "attacker tenant")
	admin := seedServedAPIToken(t, ctx, h.store, v5AttackerTenant, "attacker-admin",
		[]string{"issuers:write", "issuers:read", "certs:issue", "access:write"})
	cust := seedServedAPIToken(t, ctx, h.store, v5AttackerTenant, "attacker-custodian", []string{"issuers:write", "issuers:read"})
	// A single admin cannot be its own second custodian: a token it mints for
	// another subject is delegated and the approval route refuses it (F262).
	ghost := createServedToken(t, h.ts, admin, "attacker-ghost-custodian", []string{"issuers:write", "issuers:read"})
	a := &v5Attacker{t: t, h: h, admin: admin, ghost: ghost, cust: cust}
	probe := createImportExistingCACeremony(t, h, admin, string(h.caPEM), issuingCAHandle, v5Spec("probe", 0), 1, "v5-ghost-probe")
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+probe.ID+"/approvals", ghost, "v5-ghost-approve", nil); code != http.StatusForbidden {
		t.Errorf("self-minted (delegated) approver token = HTTP %d %s; want 403", code, body)
	} else {
		t.Logf("single-admin ghost approver refused as designed (F262): HTTP %d", code)
	}

	// 1. Another tenant's CLAIMED hierarchy handle is protected by the claim table.
	t.Run("victim ca-hierarchy handle (claimed)", func(t *testing.T) {
		a.t = t
		op := seedServedAPIToken(t, ctx, h.store, victim, "victim-ca-operator", []string{"issuers:write", "issuers:read", "certs:issue"})
		ap := seedServedAPIToken(t, ctx, h.store, victim, "victim-ca-custodian", []string{"issuers:write", "issuers:read"})
		rootSpec := map[string]any{"common_name": "victim tenant root", "max_path_len": 1,
			"ttl_seconds": int64((365 * 24 * time.Hour).Seconds()), "signature_algorithm": "ecdsa-p256"}
		ceremony := createCACeremony(t, h, op, "create_root", "", rootSpec, 1, "v5-victim-root-ceremony")
		approveCACeremony(t, h, ap, ceremony.ID, 1, "v5-victim-root-approval")
		victimRoot := createRootCA(t, h, op, ceremony.ID, rootSpec, "v5-victim-root")
		if !strings.HasPrefix(victimRoot.SignerHandle, "ca-hierarchy-") {
			t.Fatalf("victim root handle = %q", victimRoot.SignerHandle)
		}
		code, got, body := a.bind("claimed", victimRoot.SignerHandle, victimRoot.CertificatePEM, v5Spec("victim tenant root", 1))
		a.expectOwnershipConflict("claimed hierarchy handle", code, body)
		if code == http.StatusCreated {
			t.Errorf("attacker bound the victim tenant's CLAIMED hierarchy handle %q (authority %s)", victimRoot.SignerHandle, got.ID)
		} else {
			t.Logf("claimed hierarchy handle refused as expected: HTTP %d %s", code, strings.TrimSpace(string(body)))
		}
	})

	// A victim-owned key without a claim row proves the signer enforces the
	// owner independently of the PostgreSQL claim table.
	t.Run("victim unclaimed tenant CA key", func(t *testing.T) {
		a.t = t
		const handle = "v5-victim-unclaimed-ca"
		victimKey, err := client.GenerateOwnedDualControlCAKeyHandle(ctx, victim, crypto.ECDSAP256, handle, h.authz)
		if err != nil {
			t.Fatal(err)
		}
		chainPEM, _ := v5FabricatedChain(t, victimKey.Public(), "V5 victim unclaimed CA")
		code, _, body := a.bind("unclaimed-owned", handle, chainPEM, v5Spec("V5 victim unclaimed CA", 0))
		a.expectOwnershipConflict("unclaimed victim-owned CA", code, body)
	})

	// 2. Another tenant's PCAS trust root: handle = f(tenant id); created exactly as
	// the genesis worker does (genesis.go:81,155 GenerateKeyHandle, unconstrained).
	t.Run("victim PCAS tenant root", func(t *testing.T) {
		a.t = t
		rootHandle := succession.TenantRootHandle(victim)
		victimRoot, err := client.GenerateKeyHandle(ctx, crypto.ECDSAP256, rootHandle)
		if err != nil {
			t.Fatalf("victim PCAS root (genesis path): %v", err)
		}
		chainPEM, interDER := v5FabricatedChain(t, victimRoot.Public(), "V5 forged PCAS CA")
		code, got, body := a.bind("pcas-root", rootHandle, chainPEM, v5Spec("V5 forged PCAS CA", 0))
		a.expectOwnershipConflict("PCAS root", code, body)
		if code != http.StatusCreated {
			t.Logf("PCAS root bind refused: HTTP %d %s", code, body)
			return
		}
		t.Errorf("attacker tenant bound victim tenant %s's PCAS trust root %q as its own %s authority %s (HTTP 201, possession_proof=%q)",
			victim, rootHandle, got.Kind, got.ID, got.PossessionProof)
		if leaf := a.issue("pcas-root", got.ID, crypto.CertificateRequestTemplate{CommonName: "pcas-misuse.example.test", DNSNames: []string{"pcas-misuse.example.test"}}); leaf != nil {
			if err := crypto.VerifyLeafSignedByCA(leaf, interDER); err == nil {
				t.Errorf("victim's PCAS trust-root key signed an attacker-chosen X.509 leaf for the attacker tenant")
			}
		}
		rc, rb := a.revoke("pcas-root", got.ID)
		revoked, _ := client.KeyRevoked(ctx, rootHandle)
		_, signErr := victimRoot.SignDigest(crypto.SHA256Sum([]byte("victim genesis anchor")), crypto.SignOptions{Hash: crypto.SHA256})
		if rc == http.StatusOK && revoked {
			t.Errorf("attacker tenant permanently revoked victim tenant %s's PCAS trust root in the signer (HTTP %d); the victim's next root signature = %v",
				victim, rc, status.Code(signErr))
		} else {
			t.Logf("revoke: HTTP %d %s revoked=%v", rc, rb, revoked)
		}
	})

	// 3. Another tenant's AGID issuing-CA handle. CR-188 already refuses its
	// generic Sign path, but importing it can still bind and revoke the key.
	// This fixture uses the production handle shape; its public half is enough
	// for an attacker-made chain and the import ceremony.
	t.Run("victim AGID issuing CA", func(t *testing.T) {
		a.t = t
		handle := "agid-issuing-ca-" + victim
		victimKey, err := client.GenerateKeyHandle(ctx, crypto.ECDSAP256, handle)
		if err != nil {
			t.Fatalf("victim AGID CA key: %v", err)
		}
		victimCN := "AGID Issuing CA " + victim
		chainPEM, _ := v5FabricatedChain(t, victimKey.Public(), victimCN)
		code, got, body := a.bind("agid", handle, chainPEM, v5Spec(victimCN, 0))
		a.expectOwnershipConflict("AGID issuing CA", code, body)
		if code != http.StatusCreated {
			t.Logf("AGID bind refused: HTTP %d %s", code, body)
			return
		}
		t.Errorf("attacker tenant bound victim tenant %s's AGID issuing-CA key %q (authority %s, HTTP 201)", victim, handle, got.ID)
		rc, rb := a.revoke("agid", got.ID)
		revoked, _ := client.KeyRevoked(ctx, handle)
		if rc == http.StatusOK && revoked {
			t.Errorf("attacker tenant revoked victim tenant %s's AGID issuing CA handle %q", victim, handle)
		} else {
			t.Logf("AGID revoke: HTTP %d %s revoked=%v", rc, rb, revoked)
		}
	})

	// 4. The platform agent CA (agentchannel.go:82, {CA_SIGN}, dual-control).
	t.Run("platform agent-ca", func(t *testing.T) {
		a.t = t
		if len(h.srv.agentCACertDER) == 0 {
			t.Fatal("agent channel did not provision the agent CA")
		}
		agentCAPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.srv.agentCACertDER}))
		info, _ := certinfo.Inspect(h.srv.agentCACertDER)
		code, got, body := a.bind("agent-ca", agentCAHandle, agentCAPEM, v5Spec(info.CommonName, 0))
		a.expectOwnershipConflict("agent CA", code, body)
		if code != http.StatusCreated {
			t.Logf("agent-ca bind refused: HTTP %d %s", code, body)
			return
		}
		t.Errorf("attacker tenant bound the platform agent CA %q (authority %s, HTTP 201)", agentCAHandle, got.ID)
		leaf := a.issue("agent-ca", got.ID, crypto.CertificateRequestTemplate{CommonName: "agent.trstctl.local", DNSNames: []string{"agent.trstctl.local"}})
		if leaf != nil && crypto.VerifyLeafSignedByCA(leaf, h.srv.agentCACertDER) == nil {
			li, _ := certinfo.Inspect(leaf)
			t.Errorf("attacker minted a certificate for the agent-channel server name %v (EKUs %v) that chains to the agent CA every tenant's agents pin",
				li.DNSNames, li.ExtKeyUsages)
		}
	})

	// 5. The platform issuing CA, by a single tenant admin.
	t.Run("platform issuing-ca", func(t *testing.T) {
		a.t = t
		platformCA, err := client.SignerForDualControlHandle(ctx, issuingCAHandle, signing.PurposeCASign, h.authz)
		if err != nil {
			t.Fatal(err)
		}
		info, _ := certinfo.Inspect(h.srv.caCertDER)
		code, got, body := a.bind("issuing-ca", issuingCAHandle, string(h.caPEM), v5Spec(info.CommonName, 0))
		a.expectOwnershipConflict("platform issuing CA", code, body)
		if code != http.StatusCreated {
			t.Logf("issuing-ca bind refused: HTTP %d %s", code, body)
			return
		}
		t.Errorf("attacker tenant (operator issuers:write + one custodian issuers:write) bound the platform issuing CA (authority %s, HTTP 201, possession_proof=%q)", got.ID, got.PossessionProof)
		leaf := a.issue("issuing-ca", got.ID, crypto.CertificateRequestTemplate{CommonName: "api.victim-tenant.example.test", DNSNames: []string{"api.victim-tenant.example.test"}})
		if leaf != nil && crypto.VerifyLeafSignedByCA(leaf, caCertDER(t, h.caPEM)) == nil && bytes.Equal(caCertDER(t, h.caPEM), h.srv.caCertDER) {
			t.Errorf("attacker leaf for api.victim-tenant.example.test verifies under the platform CA certificate the server publishes to every tenant")
		}
		rc, _ := a.revoke("issuing-ca", got.ID)
		revoked, _ := client.KeyRevoked(ctx, issuingCAHandle)
		_, signErr := platformCA.SignDigest(crypto.SHA256Sum([]byte("victim tenant issuance")), crypto.SignOptions{Hash: crypto.SHA256})
		if rc == http.StatusOK && revoked {
			t.Errorf("the same tenant admin revoked the platform issuing CA for every tenant: next platform signature = %v", status.Code(signErr))
		}
	})
}
