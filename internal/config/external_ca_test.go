// SPDX-License-Identifier: MPL-2.0

package config

import (
	"strings"
	"testing"
)

func TestValidateExternalCAsAcceptsEveryCompiledProvider(t *testing.T) {
	const secretRef = "file:/var/lib/trstctl/secrets/upstream" // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
	mtls := ExternalCANetworkConfig{
		RootCAFile: "/var/lib/trstctl/ca.pem", ClientCertFile: "/var/lib/trstctl/client.pem", ClientKeyFile: "/var/lib/trstctl/client-key.pem",
	}
	items := []ExternalCAConfig{
		{ID: "adcs", Type: "adcs", Name: "ADCS", Endpoint: "https://adcs.example/certsrv", CAConfig: `HOST\CA`, Template: "WebServer"},
		{ID: "awspca", Type: "awspca", Name: "AWS PCA", Endpoint: "https://acm-pca.us-east-1.amazonaws.com", Region: "us-east-1", CertificateAuthorityARN: "arn:aws:acm-pca:us-east-1:123:certificate-authority/id", AccessKeyID: "AKID", SecretAccessKeyRef: secretRef},
		{ID: "azurekv", Type: "azurekv", Name: "Azure KV", TenantID: "d0d00000-0000-4000-8000-000000000101", Endpoint: "https://vault.vault.azure.net", ManagedKeyRef: "https://vault.vault.azure.net/keys/issuing-ca/version-1", CACertFile: "/var/lib/trstctl/azure-ca.pem"},
		{ID: "digicert", Type: "digicert", Name: "DigiCert", Endpoint: "https://www.digicert.com", APIKeyRef: secretRef},
		{ID: "ejbca", Type: "ejbca", Name: "EJBCA", Endpoint: "https://ejbca.example", BearerTokenRef: secretRef, CAName: "Issuing CA", CertificateProfile: "TLS", EndEntityProfile: "TLS"},
		{ID: "entrust", Type: "entrust", Name: "Entrust", Endpoint: "https://entrust.example", CAID: "root", Network: mtls},
		{ID: "gcpcas", Type: "gcpcas", Name: "GCP CAS", Endpoint: "https://privateca.googleapis.com", CAPool: "projects/p/locations/l/caPools/pool", BearerTokenRef: secretRef},
		{ID: "globalsign", Type: "globalsign", Name: "GlobalSign", Endpoint: "https://emea.api.hvca.globalsign.com:8443", APIKeyRef: secretRef, APISecretRef: secretRef},
		{ID: "letsencrypt", Type: "letsencrypt", Name: "Let's Encrypt", DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory"},
		{ID: "sectigo", Type: "sectigo", Name: "Sectigo", Endpoint: "https://cert-manager.com", Login: "operator", PasswordRef: secretRef, CustomerURI: "customer", OrgID: 1, CertType: 2},
		{ID: "shellca", Type: "shellca", Name: "Shell CA", Command: "/usr/local/bin/ca-signer", EnvRefs: map[string]string{"CA_TOKEN": secretRef}},
		{ID: "smallstep", Type: "smallstep", Name: "Smallstep", Endpoint: "https://step-ca.example:9000", ProvisionerName: "trstctl", ProvisionerKeyRef: secretRef},
		{ID: "vaultpki", Type: "vaultpki", Name: "Vault PKI", Endpoint: "https://vault.example:8200", BearerTokenRef: secretRef, Mount: "pki", Role: "workload"},
		{ID: "venafi", Type: "venafi", Name: "Venafi", Endpoint: "https://tpp.example", AccessTokenRef: secretRef, PolicyDN: `\VED\Policy\trstctl`},
	}
	if err := ValidateExternalCAs(items); err != nil {
		t.Fatalf("ValidateExternalCAs: %v", err)
	}
}

func TestValidateExternalCAsFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		item ExternalCAConfig
		want string
	}{
		{"unknown", ExternalCAConfig{ID: "x", Type: "made-up", Name: "x"}, "not a built-in"},
		{"duplicate", ExternalCAConfig{ID: "same", Type: "digicert", Name: "d", Endpoint: "https://ca.example", APIKeyRef: "file:/safe/key"}, "duplicated"}, // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		{"inline-secret", ExternalCAConfig{ID: "d", Type: "digicert", Name: "d", Endpoint: "https://ca.example", APIKeyRef: "plaintext"}, "file:/absolute/path"},
		{"plain-http", ExternalCAConfig{ID: "d", Type: "digicert", Name: "d", Endpoint: "http://ca.example", APIKeyRef: "file:/safe/key"}, "must use https"},                                                                                             // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		{"non-loopback-insecure-opt-in", ExternalCAConfig{ID: "d", Type: "digicert", Name: "d", Endpoint: "http://10.0.0.8", APIKeyRef: "file:/safe/key", Network: ExternalCANetworkConfig{AllowInsecureHTTP: true}}, "loopback"},                        // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		{"unused-insecure-opt-in", ExternalCAConfig{ID: "d", Type: "digicert", Name: "d", Endpoint: "https://ca.example", APIKeyRef: "file:/safe/key", Network: ExternalCANetworkConfig{AllowInsecureHTTP: true}}, "requires an HTTP loopback endpoint"}, // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		{"entrust-without-mtls", ExternalCAConfig{ID: "e", Type: "entrust", Name: "e", Endpoint: "http://ca.example", CAID: "ca", Network: ExternalCANetworkConfig{AllowInsecureHTTP: true}}, "requires a network mTLS identity"},
		{"unbounded-private", ExternalCAConfig{ID: "d", Type: "digicert", Name: "d", Endpoint: "https://10.0.0.4", APIKeyRef: "file:/safe/key", Network: ExternalCANetworkConfig{AllowPrivateEndpoint: true}}, "requires private_egress_cidrs"}, // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		{"partial-mtls", ExternalCAConfig{ID: "e", Type: "entrust", Name: "e", Endpoint: "https://ca.example", CAID: "ca", Network: ExternalCANetworkConfig{ClientCertFile: "/safe/client.pem"}}, "must be set together"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			items := []ExternalCAConfig{tc.item}
			if tc.name == "duplicate" {
				items = append(items, tc.item)
			}
			err := ValidateExternalCAs(items)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestValidateExternalCAsAllowsExplicitLoopbackHTTPEmulator(t *testing.T) {
	err := ValidateExternalCAs([]ExternalCAConfig{{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		ID: "d", Type: "digicert", Name: "d", Endpoint: "http://127.0.0.1:18080", APIKeyRef: "file:/safe/key",
		Network: ExternalCANetworkConfig{AllowInsecureHTTP: true},
	}})
	if err != nil {
		t.Fatalf("loopback emulator config: %v", err)
	}
}

func TestExternalCAProviderIDsAreStableAndComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, typ := range ExternalCATypes {
		if typ == "" || seen[typ] {
			t.Fatalf("invalid ExternalCATypes entry %q", typ)
		}
		seen[typ] = true
	}
	if len(seen) != 14 {
		t.Fatalf("compiled external CA types = %d, want 14: %v", len(seen), ExternalCATypes)
	}
}
