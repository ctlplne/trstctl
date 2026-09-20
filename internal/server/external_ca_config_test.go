// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
)

type factoryTestCA struct {
	err error
}

func (factoryTestCA) Name() string { return "factory-test" }

func (c factoryTestCA) Issue(context.Context, ca.IssueRequest) (ca.Certificate, error) {
	return ca.Certificate{CertificatePEM: []byte("certificate")}, c.err
}

func TestFactoryExternalCACreatesAndCleansEveryIssue(t *testing.T) {
	created, cleaned := 0, 0
	wrapped := factoryExternalCA{name: "one-shot", factory: func(context.Context) (ca.CA, func(), error) {
		created++
		return factoryTestCA{}, func() { cleaned++ }, nil
	}}
	for i := 0; i < 2; i++ {
		if _, err := wrapped.Issue(context.Background(), ca.IssueRequest{}); err != nil {
			t.Fatal(err)
		}
	}
	if created != 2 || cleaned != 2 {
		t.Fatalf("created/cleaned = %d/%d, want 2/2", created, cleaned)
	}
}

func TestFactoryExternalCACleansFailurePaths(t *testing.T) {
	cleaned := 0
	wrapped := factoryExternalCA{name: "one-shot", factory: func(context.Context) (ca.CA, func(), error) {
		return factoryTestCA{err: errors.New("upstream failed")}, func() { cleaned++ }, nil
	}}
	if _, err := wrapped.Issue(context.Background(), ca.IssueRequest{}); err == nil {
		t.Fatal("Issue succeeded")
	}
	if cleaned != 1 {
		t.Fatalf("cleanup calls = %d, want 1", cleaned)
	}
}

func TestExternalCAConfigRegistryDoesNotLoadCredentialsAtStartup(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-created")
	items, err := externalCAsFromConfig(context.Background(), []config.ExternalCAConfig{{
		ID: "digicert", Type: "digicert", Name: "DigiCert", Endpoint: "https://www.digicert.com", APIKeyRef: "file:" + missing,
	}}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("construct registry: %v", err)
	}
	if len(items) != 1 || items[0].Factory == nil || items[0].CA != nil {
		t.Fatalf("registry items = %+v", items)
	}
	if _, cleanup, err := items[0].Factory(context.Background()); err == nil || cleanup != nil {
		t.Fatalf("factory missing credential = cleanup %v, err %v", cleanup != nil, err)
	}
}

func TestExternalCAReceiverIdempotencyClassificationIsConservative(t *testing.T) {
	for _, typ := range []string{"awspca", "aws-pca", "gcpcas", "gcp-cas"} {
		if !externalCATypeHasReceiverIdempotency(typ) {
			t.Errorf("%s should use its provider-enforced request token", typ)
		}
	}
	for _, typ := range []string{"azurekv", "azure-key-vault", "digicert", "future-adapter"} {
		if externalCATypeHasReceiverIdempotency(typ) {
			t.Errorf("%s was classified receiver-idempotent without a create-or-reconcile contract", typ)
		}
	}
}

func TestExternalCAConfigRejectsACMEWithoutIsolatedSigner(t *testing.T) {
	_, err := externalCAsFromConfig(context.Background(), []config.ExternalCAConfig{{
		ID: "letsencrypt", Type: "letsencrypt", Name: "Let's Encrypt",
		DirectoryURL: "https://acme.example/directory",
	}}, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "isolated signing service is required") {
		t.Fatalf("ACME registry without signer error = %v", err)
	}
}

func TestExternalCARegistryHidesTenantBoundAuthority(t *testing.T) {
	registry := &externalCARegistry{
		items: []api.ExternalCA{{ID: "azure", Type: "azurekv", Name: "Azure", Status: "available"}},
		byID: map[string]externalCAEntry{
			"azure": {meta: api.ExternalCA{ID: "azure"}, tenantID: "tenant-a"},
		},
	}
	visible, err := registry.ListExternalCAs(context.Background(), "tenant-a")
	if err != nil || len(visible) != 1 {
		t.Fatalf("own tenant catalog = %+v err=%v", visible, err)
	}
	hidden, err := registry.ListExternalCAs(context.Background(), "tenant-b")
	if err != nil || len(hidden) != 0 {
		t.Fatalf("other tenant catalog = %+v err=%v", hidden, err)
	}
	if _, err := registry.IssueExternalCA(context.Background(), "tenant-b", "azure", "idempotent", "binding", api.ExternalCAIssueRequest{}); !errors.Is(err, api.ErrExternalCANotFound) {
		t.Fatalf("cross-tenant issue error = %v, want not found", err)
	}
}

func TestExternalCASecretSetLocksAndDestroysFileBytes(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- fixture mode in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("authority-bearing-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	set := &externalCASecretSet{}
	t.Cleanup(set.Destroy)
	loaded, err := set.Load("file:" + path)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded) != "authority-bearing-token" {
		t.Fatalf("loaded = %q", loaded)
	}
	if len(set.buffers) != 1 {
		t.Fatalf("owned buffers = %d, want 1", len(set.buffers))
	}
	buffer := set.buffers[0]
	if buffer.Len() != len(loaded) || &buffer.Bytes()[0] != &loaded[0] {
		t.Fatal("loaded bytes are not borrowed from the owned secret buffer")
	}
	set.Destroy()
	// Destroy wipes and unmaps on Linux. A borrowed slice is invalid afterward;
	// reading it to look for zeroes is a use-after-free, not a zeroization check.
	// secret's wipe/release tests own that lower-level contract. Check that this
	// owner destroyed the actual buffer and that no subsequent borrow can run.
	if len(set.buffers) != 0 || buffer.Bytes() != nil || buffer.Len() != 0 {
		t.Fatal("destroyed secret buffer remains accessible")
	}
	if err := buffer.Use(func([]byte) error {
		t.Fatal("destroyed buffer allowed a secret borrow")
		return nil
	}); !errors.Is(err, secret.ErrDestroyed) {
		t.Fatalf("borrow after destroy = %v, want ErrDestroyed", err)
	}
}

func TestExternalCAFactoryErrorsDoNotEchoCredentialPathContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-secret-value")
	items, err := externalCAsFromConfig(context.Background(), []config.ExternalCAConfig{{
		ID: "gcp", Type: "gcpcas", Name: "GCP", Endpoint: "https://privateca.googleapis.com",
		CAPool: "projects/p/locations/l/caPools/pool", BearerTokenRef: "file:" + path,
	}}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = items[0].Factory(context.Background())
	if err == nil || strings.Contains(err.Error(), "authority-bearing-token") {
		t.Fatalf("error = %v", err)
	}
}

func TestExternalCAHTTPClientRejectsCredentialBearingRedirectsAcrossOrigins(t *testing.T) {
	client, cleanup, err := externalCAHTTPClient("https://ca.example.test/directory", config.ExternalCANetworkConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	origin, _ := http.NewRequest(http.MethodGet, "https://ca.example.test/start", nil)
	sameOrigin, _ := http.NewRequest(http.MethodGet, "https://ca.example.test/next", nil)
	if err := client.CheckRedirect(sameOrigin, []*http.Request{origin}); err != nil {
		t.Fatalf("same-origin HTTPS redirect rejected: %v", err)
	}
	for _, target := range []string{
		"http://ca.example.test/plaintext",
		"https://attacker.example.test/steal",
		"https://ca.example.test:8443/other-origin",
	} {
		redirect, _ := http.NewRequest(http.MethodGet, target, nil)
		redirect.Header.Set("Authorization", "Bearer must-not-cross-origin")
		if err := client.CheckRedirect(redirect, []*http.Request{origin}); err == nil {
			t.Fatalf("credential-bearing redirect to %s was accepted", target)
		}
	}
}

func TestExternalCAHTTPClientRejectsFreshOriginEscapeBeforeDial(t *testing.T) {
	client, cleanup, err := externalCAHTTPClient("https://ca.example.test/directory", config.ExternalCANetworkConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for _, target := range []string{
		"https://steering.example.test/fresh-acme-url",
		"http://ca.example.test/plaintext-downgrade",
		"https://ca.example.test:8443/different-port",
		"https://injected:credential@ca.example.test/userinfo",
	} {
		request, _ := http.NewRequest(http.MethodPost, target, nil)
		request.Header.Set("Authorization", "Bearer must-not-leave-configured-origin")
		if _, err := client.Transport.RoundTrip(request); !errors.Is(err, netsec.ErrSSRFBlocked) {
			t.Fatalf("fresh request to %s error = %v, want ErrSSRFBlocked before dial", target, err)
		}
	}
}
