// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// A197: a tenant registers a KMIP client over the API and gets a one-time
// enrollment. A client certificate enrolls with it once and is bound to that
// tenant only: the secret is spent, another tenant can neither enroll nor
// claim the certificate, and each tenant lists only its own clients. A new
// enrollment moves the client to a new certificate, an expired one enrolls
// nothing, and removing the registration unbinds the certificate.
func TestServedKMIPClientRegistrationsBindACertificateToOneTenant(t *testing.T) {
	ctx := context.Background()
	var directory KMIPClientDirectory
	h := newServedHarness(t, config.Protocols{KMIP: config.KMIPProtocol{
		Enabled: true, ClientRegistrations: true, CertFile: "kmip-server.crt", KeyFile: "kmip-server.key",
	}}, func(d *Deps) {
		d.KMIPFactory = func(deps KMIPFactoryDeps) (KMIPRuntime, error) {
			directory = deps.Clients
			return &fakeKMIPRuntime{addr: "127.0.0.1:0"}, nil
		}
	})
	if directory == nil {
		t.Fatal("the KMIP runtime was not handed the client directory")
	}
	const tenantB = "22222222-2222-4222-8222-222222222222"
	registerServedTenant(t, h, "tenant a")
	registerServedTenantID(t, h, tenantB, "tenant b")
	tokA := seedScopedToken(t, h.store, h.tenant, "keys:read", "keys:write")
	tokB := seedScopedToken(t, h.store, tenantB, "keys:read", "keys:write")
	type enrollment struct {
		Client struct {
			ID, State, Fingerprint string
		} `json:"client"`
		Enrollment struct {
			Username, Password string
		} `json:"enrollment"`
	}
	register := func(tok, idem, name string) enrollment {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/kmip/clients", tok, idem, map[string]any{"name": name})
		var out enrollment
		if status != http.StatusCreated || json.Unmarshal(body, &out) != nil || out.Enrollment.Password == "" || out.Client.State != "awaiting_enrollment" {
			t.Fatalf("register %s = %d %s", name, status, body)
		}
		return out
	}
	list := func(tok string) []map[string]any {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodGet, "/api/v1/kmip/clients", tok, "", nil)
		var out struct {
			Items []map[string]any `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("list = %d %s", status, body)
		}
		return out.Items
	}
	certA, certA2, certB := servedClientCertificate(t, "array-a"), servedClientCertificate(t, "array-a-renewed"), servedClientCertificate(t, "array-b")
	tenantOf := func(cert []byte) string {
		t.Helper()
		tenant, found, err := directory.KMIPClientTenant(ctx, cert)
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			return ""
		}
		return tenant
	}

	a := register(tokA, "kmip-register-a", "storage array")
	if tenant, err := directory.EnrollKMIPClient(ctx, a.Enrollment.Username, []byte("not-the-secret"), certA); err == nil {
		t.Fatalf("a wrong secret enrolled into %s", tenant)
	}
	if tenant, err := directory.EnrollKMIPClient(ctx, a.Enrollment.Username, []byte(a.Enrollment.Password), certA); err != nil || tenant != h.tenant {
		t.Fatalf("enrollment = %q, %v; want tenant A", tenant, err)
	}
	if _, err := directory.EnrollKMIPClient(ctx, a.Enrollment.Username, []byte(a.Enrollment.Password), certA2); err == nil {
		t.Fatal("a spent enrollment bound a second certificate")
	}
	if tenantOf(certA) != h.tenant {
		t.Fatal("the enrolled certificate does not select tenant A")
	}

	b := register(tokB, "kmip-register-b", "storage array")
	if _, err := directory.EnrollKMIPClient(ctx, b.Enrollment.Username, []byte(b.Enrollment.Password), certA); err == nil {
		t.Fatal("tenant B claimed tenant A's enrolled certificate")
	}
	if tenant, err := directory.EnrollKMIPClient(ctx, b.Enrollment.Username, []byte(b.Enrollment.Password), certB); err != nil || tenant != tenantB {
		t.Fatalf("tenant B's enrollment = %q, %v", tenant, err)
	}
	if items := list(tokA); len(items) != 1 || items[0]["id"] != a.Client.ID || items[0]["state"] != "enrolled" || items[0]["fingerprint"] == "" {
		t.Fatalf("tenant A lists %v", items)
	}
	if items := list(tokB); len(items) != 1 || items[0]["id"] != b.Client.ID {
		t.Fatalf("tenant B lists %v", items)
	}

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/kmip/clients/"+a.Client.ID+"/enrollment", tokA, "kmip-reenroll-a", nil)
	var renewed enrollment
	if status != http.StatusOK || json.Unmarshal(body, &renewed) != nil || renewed.Client.State != "enrolled_reenrolling" {
		t.Fatalf("new enrollment = %d %s", status, body)
	}
	if tenantOf(certA) != h.tenant {
		t.Fatal("the bound certificate stopped working before the new one enrolled")
	}
	if tenant, err := directory.EnrollKMIPClient(ctx, renewed.Enrollment.Username, []byte(renewed.Enrollment.Password), certA2); err != nil || tenant != h.tenant {
		t.Fatalf("re-enrollment = %q, %v", tenant, err)
	}
	if tenantOf(certA) != "" || tenantOf(certA2) != h.tenant {
		t.Fatal("re-enrollment did not move the client to its new certificate")
	}
	if status, body := secretsReqKey(t, h, http.MethodDelete, "/api/v1/kmip/clients/"+b.Client.ID, tokA, "kmip-remove-cross", nil); status != http.StatusNotFound {
		t.Fatalf("tenant A removing tenant B's client = %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h, http.MethodDelete, "/api/v1/kmip/clients/"+a.Client.ID, tokA, "kmip-remove-a", nil); status != http.StatusNoContent {
		t.Fatalf("remove = %d %s", status, body)
	}
	if tenantOf(certA2) != "" || tenantOf(certB) != tenantB {
		t.Fatal("removing tenant A's client did not unbind exactly its certificate")
	}

	c := register(tokA, "kmip-register-c", "expired")
	if _, err := h.store.SystemPool().Exec(ctx, `UPDATE kmip_clients SET enrollment_expires_at = now() - interval '1 minute' WHERE id = $1`, c.Client.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.EnrollKMIPClient(ctx, c.Enrollment.Username, []byte(c.Enrollment.Password), certA); err == nil {
		t.Fatal("an expired enrollment bound a certificate")
	}
}

// Without the KMIP listener's client registrations the routes answer 503.
func TestServedKMIPClientRegistrationsNeedTheListener(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	registerServedTenant(t, h, "tenant a")
	tok := seedScopedToken(t, h.store, h.tenant, "keys:read", "keys:write")
	if status, body := secretsReqKey(t, h, http.MethodGet, "/api/v1/kmip/clients", tok, "", nil); status != http.StatusServiceUnavailable {
		t.Fatalf("registrations without the listener = %d %s; want 503", status, body)
	}
}

// servedClientCertificate is a TLS client certificate no deployment CA issued,
// as an appliance brings its own.
func servedClientCertificate(t *testing.T, name string) []byte {
	t.Helper()
	material, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), name+".test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(material.ControlPlane.CertFile) // #nosec G304 -- test-generated TLS material in the test's temp dir (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no client certificate")
	}
	return block.Bytes
}
