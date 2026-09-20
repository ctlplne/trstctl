// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/attest/githuboidc"
	"trstctl.com/trstctl/internal/codesign"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/signing"
)

type tenantCodeSigningKeyResolver struct {
	keys map[string]crypto.DigestSigner
}

var _ codesign.KeyResolver = (*tenantCodeSigningKeyResolver)(nil)

func (r *tenantCodeSigningKeyResolver) Signer(tenantID, keyID string) (crypto.DigestSigner, error) {
	if r == nil {
		return nil, fmt.Errorf("codesign: no key %s", keyID)
	}
	signer, ok := r.keys[codeSigningKeyIdentity(tenantID, keyID)]
	if !ok {
		return nil, fmt.Errorf("codesign: no key %s for tenant", keyID)
	}
	return signer, nil
}

func (r *tenantCodeSigningKeyResolver) CodeSigningKeyMetadata(tenantID, keyID string) (string, bool) {
	if r == nil {
		return "", false
	}
	signer, ok := r.keys[codeSigningKeyIdentity(tenantID, keyID)]
	if !ok || signer == nil {
		return "", false
	}
	return string(signer.Algorithm()), true
}

// codeSigningConfigFromConfig is the production composition seam named by the
// wiring census. Every private operation stays behind SignerProvider.Client();
// neither persistent nor keyless private key material enters this process.
func codeSigningConfigFromConfig(ctx context.Context, cfg config.CodeSigning, signer SignerProvider, tokenProvider signing.SignTokenProvider, guard *egress.Guard) (CodeSigningConfig, error) {
	if !cfg.Enabled {
		return CodeSigningConfig{}, nil
	}
	if signer == nil || signer.Client() == nil {
		return CodeSigningConfig{}, fmt.Errorf("code-signing requires the isolated signing service")
	}
	client := signer.Client()
	resolver := &tenantCodeSigningKeyResolver{keys: make(map[string]crypto.DigestSigner, len(cfg.Keys))}
	for _, keyCfg := range cfg.Keys {
		if strings.TrimSpace(keyCfg.TenantID) == "" || strings.TrimSpace(keyCfg.ID) == "" {
			return CodeSigningConfig{}, fmt.Errorf("code-signing key requires tenant_id and id")
		}
		identity := codeSigningKeyIdentity(keyCfg.TenantID, keyCfg.ID)
		if _, duplicate := resolver.keys[identity]; duplicate {
			return CodeSigningConfig{}, fmt.Errorf("code-signing duplicate tenant/key id %q", keyCfg.ID)
		}
		algorithm, err := codeSigningAlgorithm(keyCfg.Algorithm)
		if err != nil {
			return CodeSigningConfig{}, fmt.Errorf("code-signing key %s: %w", keyCfg.ID, err)
		}
		handle := strings.TrimSpace(keyCfg.Handle)
		if handle == "" {
			handle = "codesign-" + crypto.SHA256Hex([]byte(identity))[:32]
		}
		remote, err := bindOrCreateCodeSigningKey(ctx, client, handle, algorithm, keyCfg.CreateIfMissing, keyCfg.RequireDualControl, tokenProvider)
		if err != nil {
			return CodeSigningConfig{}, fmt.Errorf("code-signing key %s: %w", keyCfg.ID, err)
		}
		resolver.keys[identity] = remote
	}

	attestors, err := codeSigningAttestorsFromConfig(cfg.GitHubOIDCTenants)
	if err != nil {
		return CodeSigningConfig{}, err
	}
	ephemeralAlgorithm, err := codeSigningEphemeralAlgorithm(cfg.EphemeralAlgorithm)
	if err != nil {
		return CodeSigningConfig{}, err
	}
	rekor, err := rekorHandlerFromConfig(cfg.Rekor, guard)
	if err != nil {
		return CodeSigningConfig{}, err
	}
	return CodeSigningConfig{
		Keys: resolver,
		AttestorsForTenant: func(tenantID string) []attest.Attestor {
			return append([]attest.Attestor(nil), attestors[strings.TrimSpace(tenantID)]...)
		},
		EphemeralAlgorithm: ephemeralAlgorithm,
		NewEphemeralSigner: func(ctx context.Context, operationID string, algorithm crypto.Algorithm) (crypto.DigestSigner, string, error) {
			handle := codeSigningEphemeralHandle(operationID)
			remote, err := client.GenerateConstrainedKeyHandle(ctx, algorithm, handle, []signing.KeyPurpose{signing.PurposeCodeSign}, signing.PurposeCodeSign)
			if status.Code(err) == codes.AlreadyExists {
				remote, err = client.SignerForHandleWithPurpose(ctx, handle, signing.PurposeCodeSign)
			}
			if err != nil {
				return nil, "", fmt.Errorf("bind isolated ephemeral code-signing key: %w", err)
			}
			return remote, handle, nil
		},
		DestroyEphemeralSigner: func(ctx context.Context, handle string) error {
			remote, err := client.SignerForHandleWithPurpose(ctx, handle, signing.PurposeCodeSign)
			if status.Code(err) == codes.NotFound {
				return nil
			}
			if err != nil {
				return err
			}
			return remote.Destroy(ctx)
		},
		RekorDestination:    defaultRekorDestination,
		TransparencyHandler: rekor,
	}, nil
}

func codeSigningKeyIdentity(tenantID, keyID string) string {
	return strings.TrimSpace(tenantID) + "\x00" + strings.TrimSpace(keyID)
}

func codeSigningAlgorithm(raw string) (crypto.Algorithm, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "ecdsa-p256":
		return crypto.ECDSAP256, nil
	case "rsa-2048":
		return crypto.RSA2048, nil
	case "rsa-3072":
		return crypto.RSA3072, nil
	case "rsa-4096":
		return crypto.RSA4096, nil
	default:
		return "", fmt.Errorf("unsupported SHA-256 signing algorithm %q", raw)
	}
}

func codeSigningEphemeralAlgorithm(raw string) (crypto.Algorithm, error) {
	algorithm, err := codeSigningAlgorithm(raw)
	if err != nil {
		return "", fmt.Errorf("code-signing ephemeral algorithm: %w", err)
	}
	if algorithm != crypto.ECDSAP256 {
		return "", fmt.Errorf("code-signing ephemeral algorithm must be ecdsa-p256")
	}
	return algorithm, nil
}

func bindOrCreateCodeSigningKey(ctx context.Context, client *signing.Client, handle string, algorithm crypto.Algorithm, create, dualControl bool, tokenProvider signing.SignTokenProvider) (*signing.RemoteSigner, error) {
	if strings.TrimSpace(handle) == "" {
		return nil, fmt.Errorf("signer handle is required")
	}
	if dualControl && tokenProvider == nil {
		return nil, fmt.Errorf("dual-control key requires signer.auth_token_command or an explicitly enabled co-resident eval authorizer")
	}
	bind := func() (*signing.RemoteSigner, error) {
		if dualControl {
			return client.SignerForDualControlHandle(ctx, handle, signing.PurposeCodeSign, tokenProvider)
		}
		return client.SignerForHandleWithPurpose(ctx, handle, signing.PurposeCodeSign)
	}
	remote, err := bind()
	if err == nil {
		if remote.Algorithm() != algorithm {
			return nil, fmt.Errorf("existing signer handle %q uses %s, want %s", handle, remote.Algorithm(), algorithm)
		}
		return remote, nil
	}
	if status.Code(err) != codes.NotFound || !create {
		return nil, fmt.Errorf("bind signer handle %q: %w", handle, err)
	}
	if dualControl {
		remote, err = client.GenerateDualControlKeyHandle(ctx, algorithm, handle, []signing.KeyPurpose{signing.PurposeCodeSign}, signing.PurposeCodeSign, tokenProvider)
	} else {
		remote, err = client.GenerateConstrainedKeyHandle(ctx, algorithm, handle, []signing.KeyPurpose{signing.PurposeCodeSign}, signing.PurposeCodeSign)
	}
	if status.Code(err) == codes.AlreadyExists {
		remote, err = bind() // another replica won the idempotent provision race
	}
	if err != nil {
		return nil, fmt.Errorf("provision signer handle %q: %w", handle, err)
	}
	return remote, nil
}

func codeSigningAttestorsFromConfig(items []config.CodeSigningGitHubOIDC) (map[string][]attest.Attestor, error) {
	out := make(map[string][]attest.Attestor, len(items))
	for _, item := range items {
		tenantID := strings.TrimSpace(item.TenantID)
		if tenantID == "" {
			return nil, fmt.Errorf("code-signing GitHub OIDC tenant_id is required")
		}
		var document []byte
		switch {
		case strings.TrimSpace(item.JWKSJSON) != "" && strings.TrimSpace(item.JWKSFile) != "":
			return nil, fmt.Errorf("code-signing GitHub OIDC tenant %s: jwks_json and jwks_file are mutually exclusive", tenantID)
		case strings.TrimSpace(item.JWKSJSON) != "":
			document = []byte(item.JWKSJSON)
		case strings.TrimSpace(item.JWKSFile) != "":
			var err error
			document, err = os.ReadFile(item.JWKSFile)
			if err != nil {
				return nil, fmt.Errorf("code-signing GitHub OIDC tenant %s: read JWKS: %w", tenantID, err)
			}
		default:
			return nil, fmt.Errorf("code-signing GitHub OIDC tenant %s: JWKS is required", tenantID)
		}
		jwks, err := crypto.ParseJWKS(document)
		if err != nil {
			return nil, fmt.Errorf("code-signing GitHub OIDC tenant %s: %w", tenantID, err)
		}
		owners := make(map[string]bool, len(item.AllowedOwners))
		for _, owner := range item.AllowedOwners {
			if owner = strings.TrimSpace(owner); owner != "" {
				owners[owner] = true
			}
		}
		if _, duplicate := out[tenantID]; duplicate {
			return nil, fmt.Errorf("code-signing GitHub OIDC tenant %s is configured more than once", tenantID)
		}
		out[tenantID] = []attest.Attestor{&githuboidc.Attestor{
			JWKS: jwks, Issuer: strings.TrimSpace(item.Issuer), Audience: strings.TrimSpace(item.Audience), AllowedOwners: owners,
		}}
	}
	return out, nil
}
