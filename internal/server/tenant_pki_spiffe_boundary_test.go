// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/tenantnames"
)

// The Workload API has a tenant CA. A tenant-controlled request to the shared
// platform issuer must not produce a second certificate for that trust domain.
func TestCR042PlatformIssuerRefusesSPIFFEWorkloadIdentity(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	registerServedTenantID(t, h, "66666666-6666-4666-8666-666666666666", "neighbor tenant")
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "other-tenant.svc.test",
		DNSNames:   []string{"other-tenant.svc.test"},
		URIs:       []string{"spiffe://served.test/other-tenant/workload"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := h.srv.IssueLeafWithProfile(context.Background(), csr, time.Hour, crypto.LeafProfile{})
	if err == nil || !strings.Contains(err.Error(), "SPIFFE") || len(leaf) != 0 {
		t.Fatalf("platform CA signed a workload identity: leaf length=%d, error=%v", len(leaf), err)
	}
}

// The secrets API signs directly through PKIProvider, outside the lifecycle
// dispatcher. Its tenant-written profile must obey the same operator grant.
func TestCR042PKISecretCannotMintNeighborDNSName(t *testing.T) {
	const attacker = "66666666-6666-4666-8666-666666666666"
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDNSNamespaces = tenantnames.Grants{
			servedTestTenant: {"victim.test"},
			attacker:         {"attacker.test"},
		}
	})
	registerServedTenantID(t, h, attacker, "attacker tenant")
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "device.victim.test", DNSNames: []string{"device.victim.test"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, h.store, attacker, "secrets:read", "secrets:write")
	code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/pki", token, "cr042-cross-tenant", map[string]any{
		"csr_pem":     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
		"ttl_seconds": 3600,
	})
	if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "DNS namespace") {
		t.Fatalf("neighbor PKI secret = %d %s, want namespace refusal", code, body)
	}
	vault := vaultServedRequestKey(t, h, token, http.MethodPost, "/v1/pki/sign/default", "cr042-vault-cross-tenant", map[string]any{
		"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "ttl": "1h",
	}, http.StatusUnprocessableEntity)
	if !strings.Contains(string(vault), "DNS namespace") {
		t.Fatalf("Vault PKI sign did not explain the tenant namespace refusal: %s", vault)
	}
	ownedKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ownedKey.Destroy)
	ownedCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "device.attacker.test", DNSNames: []string{"device.attacker.test"},
	}, ownedKey)
	if err != nil {
		t.Fatal(err)
	}
	code, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/pki", token, "cr042-owned", map[string]any{
		"csr_pem":     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: ownedCSR})),
		"ttl_seconds": 3600,
	})
	if code != http.StatusCreated {
		t.Fatalf("operator-granted PKI secret = %d %s", code, body)
	}
}

func TestCR042ESTProtocolCarriesTenantToPlatformNameGrant(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{
		EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	}, func(d *Deps) {
		d.TenantDNSNamespaces = tenantnames.Grants{
			servedTestTenant:                       {"est-owned.test"},
			"66666666-6666-4666-8666-666666666666": {"neighbor.test"},
		}
	})
	registerServedTenantID(t, h, "66666666-6666-4666-8666-666666666666", "neighbor tenant")
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "device.est-owned.test", DNSNames: []string{"device.est-owned.test"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewTLSServer(h.srv.Handler())
	t.Cleanup(listener.Close)
	issued := estEnroll(t, listener.Client(), listener.URL+"/.well-known/est/simpleenroll", seedAPIToken(t, h.store, h.tenant), csr, http.StatusOK)
	if err := crypto.VerifyLeafSignedByCA(issued, h.srv.caCertDER); err != nil {
		t.Fatalf("EST did not use the intended signer-held platform CA: %v", err)
	}
}

// A certificate profile is tenant-written, so it cannot prove that the tenant
// owns a DNS name. With two tenants and no operator namespace grant, the
// shared CA must refuse the name instead of assigning it to the first asker.
func TestCR042UnboundSharedCARefusesDNSInMultiTenant(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	registerServedTenantID(t, h, "66666666-6666-4666-8666-666666666666", "neighbor tenant")
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "payments.neighbor.test", DNSNames: []string{"payments.neighbor.test"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := h.srv.IssueLeafWithProfile(context.Background(), csr, time.Hour, crypto.LeafProfile{})
	if err == nil || len(leaf) != 0 {
		t.Fatalf("unbound shared CA signed a tenant DNS name: leaf length=%d, error=%v", len(leaf), err)
	}
}

func TestCR042OperatorTenantDNSNamespaceBindsPlatformIssuer(t *testing.T) {
	const neighbor = "66666666-6666-4666-8666-666666666666"
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.TenantDNSNamespaces = tenantnames.Grants{
			servedTestTenant: {"owned.served.test"},
			neighbor:         {"neighbor.test"},
		}
	})
	registerServedTenantID(t, h, neighbor, "neighbor tenant")
	profile := crypto.LeafProfile{PermittedDNSSuffixes: []string{"served.test", "neighbor.test"}}
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"api.owned.served.test", true},
		{"payments.neighbor.test", false},
		{"api.owned.served.test.evil", false},
		{"", false},
	} {
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
			CommonName: tc.name, DNSNames: []string{tc.name},
		}, key)
		if err != nil {
			key.Destroy()
			t.Fatal(err)
		}
		leaf, err := h.srv.IssueLeafWithProfile(withPlatformIssuanceTenant(context.Background(), h.tenant), csr, time.Hour, profile)
		key.Destroy()
		if tc.ok && (err != nil || len(leaf) == 0) {
			t.Fatalf("owned name %q refused: %v", tc.name, err)
		}
		if !tc.ok && (err == nil || len(leaf) != 0) {
			t.Fatalf("neighbor name %q signed: leaf length=%d, error=%v", tc.name, len(leaf), err)
		}
	}
}
