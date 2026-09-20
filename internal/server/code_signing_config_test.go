// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

func TestCodeSigningAlgorithmsAndTenantResolverFailClosed(t *testing.T) {
	for raw, want := range map[string]crypto.Algorithm{
		"": crypto.ECDSAP256, " ECDSA-P256 ": crypto.ECDSAP256,
		"rsa-2048": crypto.RSA2048, "RSA-3072": crypto.RSA3072, "rsa-4096": crypto.RSA4096,
	} {
		got, err := codeSigningAlgorithm(raw)
		if err != nil || got != want {
			t.Fatalf("codeSigningAlgorithm(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	if _, err := codeSigningAlgorithm("ed25519"); err == nil {
		t.Fatal("codeSigningAlgorithm accepted an unsupported SHA-256 signing algorithm")
	}
	if got, err := codeSigningEphemeralAlgorithm(""); err != nil || got != crypto.ECDSAP256 {
		t.Fatalf("default ephemeral algorithm = %q, %v", got, err)
	}
	for _, raw := range []string{"rsa-2048", "unknown"} {
		if _, err := codeSigningEphemeralAlgorithm(raw); err == nil {
			t.Fatalf("codeSigningEphemeralAlgorithm(%q) succeeded", raw)
		}
	}

	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	resolver := &tenantCodeSigningKeyResolver{keys: map[string]crypto.DigestSigner{
		codeSigningKeyIdentity("tenant-a", "release"): signer,
	}}
	resolved, err := resolver.Signer(" tenant-a ", " release ")
	if err != nil || resolved.Algorithm() != crypto.ECDSAP256 {
		t.Fatalf("tenant resolver = %T, %v", resolved, err)
	}
	if _, err := resolver.Signer("tenant-b", "release"); err == nil {
		t.Fatal("tenant resolver crossed tenant boundary")
	}
	var absent *tenantCodeSigningKeyResolver
	if _, err := absent.Signer("tenant-a", "release"); err == nil {
		t.Fatal("nil tenant resolver succeeded")
	}
}

func TestCodeSigningCompositionRequiresIsolatedSignerAndConstrainedHandles(t *testing.T) {
	got, err := codeSigningConfigFromConfig(context.Background(), config.CodeSigning{}, nil, nil, nil)
	if err != nil || got.Keys != nil || got.NewEphemeralSigner != nil {
		t.Fatalf("disabled code signing config = %+v, %v", got, err)
	}
	if _, err := codeSigningConfigFromConfig(context.Background(), config.CodeSigning{Enabled: true}, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "isolated signing service") {
		t.Fatalf("enabled code signing without signer error = %v", err)
	}
	if _, err := bindOrCreateCodeSigningKey(context.Background(), nil, "", crypto.ECDSAP256, false, false, nil); err == nil {
		t.Fatal("empty signer handle succeeded")
	}
	if _, err := bindOrCreateCodeSigningKey(context.Background(), nil, "release", crypto.ECDSAP256, false, true, nil); err == nil || !strings.Contains(err.Error(), "dual-control") {
		t.Fatalf("dual-control handle without authorizer error = %v", err)
	}
}

func TestCodeSigningGitHubOIDCAttestorsLoadInlineAndFileJWKS(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	jwk, err := crypto.PublicJWK(signer.Public(), "github-actions")
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "github.jwks.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}

	attestors, err := codeSigningAttestorsFromConfig([]config.CodeSigningGitHubOIDC{
		{TenantID: "tenant-inline", Issuer: "https://token.actions.githubusercontent.com", Audience: "sigstore", JWKSJSON: string(document), AllowedOwners: []string{" acme ", "", "acme"}},
		{TenantID: "tenant-file", Audience: "sigstore", JWKSFile: path},
	})
	if err != nil {
		t.Fatalf("codeSigningAttestorsFromConfig: %v", err)
	}
	for _, tenantID := range []string{"tenant-inline", "tenant-file"} {
		if len(attestors[tenantID]) != 1 || attestors[tenantID][0].Method() == "" {
			t.Fatalf("tenant %s attestors = %#v", tenantID, attestors[tenantID])
		}
	}

	cases := []struct {
		name  string
		items []config.CodeSigningGitHubOIDC
		want  string
	}{
		{"tenant required", []config.CodeSigningGitHubOIDC{{JWKSJSON: string(document)}}, "tenant_id"},
		{"exclusive sources", []config.CodeSigningGitHubOIDC{{TenantID: "tenant-a", JWKSJSON: string(document), JWKSFile: path}}, "mutually exclusive"},
		{"source required", []config.CodeSigningGitHubOIDC{{TenantID: "tenant-a"}}, "JWKS is required"},
		{"file read", []config.CodeSigningGitHubOIDC{{TenantID: "tenant-a", JWKSFile: filepath.Join(t.TempDir(), "missing")}}, "read JWKS"},
		{"invalid document", []config.CodeSigningGitHubOIDC{{TenantID: "tenant-a", JWKSJSON: `{"keys":"not-an-array"}`}}, "tenant-a"},
		{"duplicate tenant", []config.CodeSigningGitHubOIDC{{TenantID: "tenant-a", JWKSJSON: string(document)}, {TenantID: "tenant-a", JWKSJSON: string(document)}}, "more than once"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := codeSigningAttestorsFromConfig(tc.items)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestCodeSigningCompositionBindsPurposeConstrainedIsolatedKeys(t *testing.T) {
	authorizer := testSignAuthorizer(t)
	client := serveSignerWithAuthorizer(t, authorizer)
	logKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer logKey.Destroy()
	logKeyPath := filepath.Join(t.TempDir(), "rekor-log-public.pem")
	if err := os.WriteFile(logKeyPath, crypto.MarshalPublicKeyPEM(logKey.Public().DER), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.CodeSigning{
		Enabled: true,
		Keys: []config.CodeSigningKey{{
			TenantID: "tenant-a", ID: "release", Handle: "codesign-release-test",
			Algorithm: "ecdsa-p256", CreateIfMissing: true,
		}},
		Rekor: config.CodeSigningRekor{
			Endpoint: "https://rekor.example.test/api/v1/log/entries", LogPublicKeyFile: logKeyPath,
		},
	}
	composed, err := codeSigningConfigFromConfig(context.Background(), cfg, signing.StaticProvider{C: client}, authorizer, nil)
	if err != nil {
		t.Fatalf("codeSigningConfigFromConfig: %v", err)
	}
	key, err := composed.Keys.Signer("tenant-a", "release")
	if err != nil || key.Algorithm() != crypto.ECDSAP256 {
		t.Fatalf("composed tenant key = %T, %v", key, err)
	}
	if _, err := composed.Keys.Signer("tenant-b", "release"); err == nil {
		t.Fatal("composed resolver exposed another tenant's key")
	}
	if composed.TransparencyHandler == nil || composed.RekorDestination != defaultRekorDestination {
		t.Fatal("composition omitted the configured Rekor outbox handler")
	}
	if got := composed.AttestorsForTenant("tenant-a"); len(got) != 0 {
		t.Fatalf("unexpected attestors = %#v", got)
	}

	ephemeral, handle, err := composed.NewEphemeralSigner(context.Background(), "operation-a", crypto.ECDSAP256)
	if err != nil || ephemeral == nil || handle != codeSigningEphemeralHandle("operation-a") {
		t.Fatalf("new ephemeral signer = %T, %q, %v", ephemeral, handle, err)
	}
	rebound, reboundHandle, err := composed.NewEphemeralSigner(context.Background(), "operation-a", crypto.ECDSAP256)
	if err != nil || rebound == nil || reboundHandle != handle {
		t.Fatalf("idempotent ephemeral signer = %T, %q, %v", rebound, reboundHandle, err)
	}
	if err := composed.DestroyEphemeralSigner(context.Background(), handle); err != nil {
		t.Fatalf("destroy ephemeral signer: %v", err)
	}
	if err := composed.DestroyEphemeralSigner(context.Background(), handle); err != nil {
		t.Fatalf("idempotent destroy ephemeral signer: %v", err)
	}

	cfg.Keys[0].CreateIfMissing = false
	if _, err := codeSigningConfigFromConfig(context.Background(), cfg, signing.StaticProvider{C: client}, authorizer, nil); err != nil {
		t.Fatalf("bind existing constrained key: %v", err)
	}
	cfg.Keys[0].Algorithm = "rsa-2048"
	if _, err := codeSigningConfigFromConfig(context.Background(), cfg, signing.StaticProvider{C: client}, authorizer, nil); err == nil || !strings.Contains(err.Error(), "uses ECDSA-P256") {
		t.Fatalf("algorithm-confused existing handle error = %v", err)
	}

	dual, err := bindOrCreateCodeSigningKey(context.Background(), client, "codesign-dual-test", crypto.ECDSAP256, true, true, authorizer)
	if err != nil {
		t.Fatalf("provision dual-control code-signing key: %v", err)
	}
	if err := dual.Destroy(context.Background()); err != nil {
		t.Fatalf("destroy dual-control key: %v", err)
	}
}
