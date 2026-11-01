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
	"trstctl.com/trstctl/internal/store"
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

// managedKeyLookup reads a tenant's managed-key record; production passes
// store.GetManagedKey.
type managedKeyLookup func(ctx context.Context, tenantID, provider, keyID string) (store.ManagedKey, error)

// codeSigningConfigFromConfig is the production composition seam named by the
// wiring census. Every private operation stays behind SignerProvider.Client();
// neither persistent nor keyless private key material enters this process.
func codeSigningConfigFromConfig(ctx context.Context, cfg config.CodeSigning, signer SignerProvider, tokenProvider signing.SignTokenProvider, guard *egress.Guard, managedKeys managedKeyLookup) (CodeSigningConfig, error) {
	if !cfg.Enabled {
		return CodeSigningConfig{}, nil
	}
	if signer == nil || signer.Client() == nil {
		return CodeSigningConfig{}, fmt.Errorf("code-signing requires the isolated signing service")
	}
	client := signer.Client()
	resolver := &tenantCodeSigningKeyResolver{keys: make(map[string]crypto.DigestSigner, len(cfg.Keys))}
	var certificates map[string][][]byte
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
		var remote crypto.DigestSigner
		if strings.TrimSpace(keyCfg.ManagedKeyProvider) != "" || strings.TrimSpace(keyCfg.ManagedKeyID) != "" {
			remote, err = bindManagedCodeSigningKey(ctx, client, keyCfg, algorithm, tokenProvider, managedKeys)
		} else {
			handle := strings.TrimSpace(keyCfg.Handle)
			if handle == "" {
				handle = "codesign-" + crypto.SHA256Hex([]byte(identity))[:32]
			}
			remote, err = bindOrCreateCodeSigningKey(ctx, client, handle, algorithm, keyCfg.CreateIfMissing, keyCfg.RequireDualControl, tokenProvider)
		}
		if err != nil {
			return CodeSigningConfig{}, fmt.Errorf("code-signing key %s: %w", keyCfg.ID, err)
		}
		resolver.keys[identity] = remote
		if path := strings.TrimSpace(keyCfg.CertificateChainFile); path != "" {
			raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured certificate chain path (CWE-22)
			if err != nil {
				return CodeSigningConfig{}, fmt.Errorf("code-signing key %s: certificate_chain_file: %w", keyCfg.ID, err)
			}
			chain, err := loadCodeSigningKeyChain(raw, remote)
			if err != nil {
				return CodeSigningConfig{}, fmt.Errorf("code-signing key %s: certificate_chain_file: %w", keyCfg.ID, err)
			}
			if certificates == nil {
				certificates = map[string][][]byte{}
			}
			certificates[identity] = chain
		}
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
		Keys: resolver, KeyCertificates: certificates,
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

// bindManagedCodeSigningKey binds a code-signing key held in an HSM or cloud
// KMS — an Enterprise managed key (P9). The private operation runs in that
// provider through the isolated signer, which requires an independent
// authorization for every signature and journals each by the code-signing
// command's operation id, so a redelivered command gets its first signature.
func bindManagedCodeSigningKey(ctx context.Context, client *signing.Client, keyCfg config.CodeSigningKey, algorithm crypto.Algorithm, tokenProvider signing.SignTokenProvider, lookup managedKeyLookup) (crypto.DigestSigner, error) {
	tenantID := strings.TrimSpace(keyCfg.TenantID)
	provider, keyID := strings.TrimSpace(keyCfg.ManagedKeyProvider), strings.TrimSpace(keyCfg.ManagedKeyID)
	switch {
	case provider == "" || keyID == "":
		return nil, fmt.Errorf("managed_key_provider and managed_key_id are both required")
	case strings.TrimSpace(keyCfg.Handle) != "" || keyCfg.CreateIfMissing || keyCfg.RequireDualControl:
		return nil, fmt.Errorf("a managed key cannot also name a signer handle, create_if_missing or require_dual_control")
	case tokenProvider == nil:
		return nil, fmt.Errorf("a managed key requires signer.auth_token_command or an explicitly enabled co-resident eval authorizer")
	case lookup == nil:
		return nil, fmt.Errorf("managed keys are not available to code signing in this deployment")
	}
	key, err := lookup(ctx, tenantID, provider, keyID)
	if err != nil {
		return nil, fmt.Errorf("managed key %s/%s: %w", provider, keyID, err)
	}
	if key.State != "active" {
		return nil, fmt.Errorf("managed key %s/%s is %s, not active", provider, keyID, key.State)
	}
	if crypto.Algorithm(key.Algorithm) != algorithm {
		return nil, fmt.Errorf("managed key %s/%s uses %s, want %s", provider, keyID, key.Algorithm, algorithm)
	}
	return client.SignerForManagedKey(tenantID, key.Provider, key.KeyID, algorithm, key.PublicDER, signing.PurposeCodeSign, tokenProvider)
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
