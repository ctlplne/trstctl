// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/profile"
)

// The service constructs the leaf on behalf of the Azure signing key. Inspect
// the certificate returned through the real API and durable issuance worker.
func TestNativeAzureKeysCAAppliesBoundProfileAtSigning(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	root, err := crypto.SelfSignedHierarchyCA(key, crypto.HierarchyCAProfile{CommonName: "Test issuer", TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	const authority = "azure-native"
	const crlURL = "https://pki.example.test/azure.crl"
	const ocspURL = "https://pki.example.test/azure-ocsp"
	const issuerURL = "https://pki.example.test/azure.cer"
	entry := config.ExternalCAConfig{ID: authority, Name: authority, Type: "azurekv", CACertFile: filepath.Join(t.TempDir(), "issuer.pem")}
	if err := os.WriteFile(entry.CACertFile, root.CertificatePEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"crl_distribution_points":["`+crlURL+`"],"ocsp_servers":["`+ocspURL+`"],"issuing_certificate_urls":["`+issuerURL+`"]}`), &entry); err != nil {
		t.Fatal(err)
	}
	factory, err := externalCAFactoryFromConfig(entry, nil, nil, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		d.ExternalCAs = []ExternalCA{{ID: authority, Name: entry.Name, Type: entry.Type, Factory: factory}}
	})
	const ceiling = 2 * time.Hour
	storeServerTestProfile(t, h.store, h.tenant, "application", profile.CertificateProfile{
		Name: "application", AllowedDNSSuffixes: []string{"example.test"}, AllowedEKUs: []string{"serverAuth"}, MaxValidity: profile.Duration(ceiling),
	})
	// A caller can disconnect between durable admission and worker dispatch.
	// Edit the active policy in that gap, then retry the identical command.
	checkQueuedAzureProfile(t, h, authority)
	body := externalCAIssueRequestBody(t, "web.example.test")
	body["profile_name"] = "application"
	delete(body, "ttl_seconds")
	issued := issueExternalCAWithBody(t, h, authority, "native-profile", body)
	info, err := certinfo.Inspect([]byte(issued.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(info.ExtKeyUsages, []string{"serverAuth"}) {
		t.Errorf("issued EKUs = %v, want serverAuth", info.ExtKeyUsages)
	}
	if !slices.Equal(info.CRLDistributionPoints, []string{crlURL}) || !slices.Equal(info.OCSPServers, []string{ocspURL}) || !slices.Equal(info.IssuingCertificateURL, []string{issuerURL}) {
		t.Errorf("issuer-specific status and chain pointers missing from signed certificate: CRL %v, OCSP %v, issuer %v", info.CRLDistributionPoints, info.OCSPServers, info.IssuingCertificateURL)
	}
	if duration := info.NotAfter.Sub(info.NotBefore); duration > ceiling {
		t.Errorf("signed validity = %s, exceeds profile ceiling %s", duration, ceiling)
	}
	// The CSR and API both describe the same requested certificate. A narrower
	// signed request and an unknown profile must be enforced before dispatch.
	const path = "/api/v1/external-cas/" + authority + "/issue"
	for _, tc := range []struct{ label, name, usage string }{
		{"unknown profile", "retired", "serverAuth"}, {"usage outside profile", "application", "clientAuth"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			request := externalCAIssueRequestBody(t, "web.example.test")
			delete(request, "ttl_seconds")
			request["profile_name"] = tc.name
			request["csr_pem"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: serverTestCSR(t, "web.example.test", []string{tc.usage})}))
			key := "native-refusal-" + tc.usage
			code, _ := doExternalCARequest(t, h, http.MethodPost, path, key, request)
			if code != http.StatusUnprocessableEntity {
				t.Errorf("profile refusal status %d, want 422", code)
			}
			if n := externalCAIntentOutboxCount(t, h, key+":external-ca:"+authority); n != 0 {
				t.Errorf("queued %d CA jobs for a refused request", n)
			}
		})
	}
	deviceKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(deviceKey.Destroy)
	otherCN, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "printer.example.test", DNSNames: []string{"web.example.test"},
	}, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	for label, csrPEM := range map[string]string{
		"unbound-common-name": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: otherCN})),
		"unbound-department":  publicDepartmentCSR,
	} {
		t.Run(label, func(t *testing.T) {
			request := externalCAIssueRequestBody(t, "web.example.test")
			delete(request, "ttl_seconds")
			request["profile_name"], request["csr_pem"] = "application", csrPEM
			code, _ := doExternalCARequest(t, h, http.MethodPost, path, label, request)
			if code != http.StatusUnprocessableEntity || externalCAIntentOutboxCount(t, h, label+":external-ca:"+authority) != 0 {
				t.Errorf("subject outside the authorized DNS identity reached issuance; HTTP %d", code)
			}
		})
	}
	storeServerTestProfile(t, h.store, h.tenant, "application", profile.CertificateProfile{
		Name: "application", AllowedDNSSuffixes: []string{"new.example.test"}, AllowedEKUs: []string{"clientAuth"},
	})
	replay := issueExternalCAWithBody(t, h, authority, "native-profile", body)
	if replay.CertificatePEM != issued.CertificatePEM {
		t.Error("replay after profile edit returned a different certificate")
	}

}

func checkQueuedAzureProfile(t *testing.T, h *servedHarness, authority string) {
	t.Helper()
	const name, key = "queued-revision", "queued-native"
	const host = "device.example.test"
	storeServerTestProfile(t, h.store, h.tenant, name, profile.CertificateProfile{
		Name: name, AllowedDNSSuffixes: []string{"example.test"}, AllowedEKUs: []string{"serverAuth"},
	})
	req := api.ExternalCAIssueRequest{CSRDER: externalCACSR(t, host), DNSNames: []string{host}, TTLSeconds: 3600, ProfileName: name}
	submit := func(ctx context.Context) (api.ExternalCAIssuedCertificate, error) {
		return h.srv.externalCAs.IssueExternalCA(ctx, h.tenant, authority, key, "same-authenticated-binding", req)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	first := make(chan error, 1)
	go func() { _, err := submit(ctx); first <- err }()
	deadline := time.Now().Add(12 * time.Second)
	for externalCAIntentOutboxCount(t, h, key+":external-ca:"+authority) == 0 {
		select {
		case err := <-first:
			t.Fatalf("initial admission ended before queuing: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for persisted profile admission")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-first
	storeServerTestProfile(t, h.store, h.tenant, name, profile.CertificateProfile{
		Name: name, AllowedDNSSuffixes: []string{"replacement.example.test"}, AllowedEKUs: []string{"clientAuth"},
	})
	startServedExternalCADispatcher(t, h)
	issued, err := submit(t.Context())
	if err != nil {
		t.Errorf("retry of queued issuance after profile edit: %v", err)
		return
	}
	info, err := certinfo.Inspect([]byte(issued.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(info.ExtKeyUsages, []string{"serverAuth"}) {
		t.Errorf("worker did not use the admitted serverAuth revision: EKUs %v", info.ExtKeyUsages)
	}
}

// Public PKCS#10 fixture for web.example.test bearing a Shipping department.
const publicDepartmentCSR = `-----BEGIN CERTIFICATE REQUEST-----
MIIBFjCBvgIBADAuMRkwFwYDVQQDDBB3ZWIuZXhhbXBsZS50ZXN0MREwDwYDVQQL
DAhTaGlwcGluZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJo6wydB4oXtW9tb
m/+mbqzNHYiUlbiArtE61V3I7IZSC5w09J4vSK+x/caV1uFGJWNxyBjWFEFQms0O
scN9f6CgLjAsBgkqhkiG9w0BCQ4xHzAdMBsGA1UdEQQUMBKCEHdlYi5leGFtcGxl
LnRlc3QwCgYIKoZIzj0EAwIDRwAwRAIgEXkDvXfX9IaGjV0vFjM1f0TmidMGC0K3
/zlvJAqUsCYCIAHEYVk59wHwIDNJa9SrMHTDSH3ses54SGsGLvkWoH8P
-----END CERTIFICATE REQUEST-----
`
