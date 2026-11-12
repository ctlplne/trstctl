// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/akeyless"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/bitwardensm"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/conjur"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/githubactions"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/gitlabci"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/infisical"
	"trstctl.com/trstctl/internal/netsec"
)

// secretStoreProvider builds the secret stores beyond the cloud secret
// managers: the code hosts' GitHub Actions, Dependabot and Codespaces
// secrets and GitLab project, group and instance CI/CD variables (A173,
// OD-2), and the Infisical, Conjur, Akeyless and Bitwarden Secrets Manager
// stores (OD-13). It reports false for a provider it does not know, so the
// caller names it unsupported. Credentials are resolved for this one run.
func secretStoreProvider(ctx context.Context, p cloudSecretProviderConfig) (cloudsecret.Provider, bool, error) {
	provider := strings.TrimSpace(p.Provider)
	switch provider {
	case githubactions.ProviderName, gitlabci.ProviderName, infisical.ProviderName, conjur.ProviderName,
		akeyless.ProviderName, bitwardensm.ProviderName:
	default:
		return nil, false, nil
	}
	endpoint := strings.TrimSpace(p.Endpoint)
	client := netsec.SafeClient(30 * time.Second)
	if endpoint != "" {
		var err error
		if client, err = cloudHTTPClient(endpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs); err != nil {
			return nil, true, err
		}
	}
	if identity := strings.TrimSpace(p.IdentityEndpoint); identity != "" {
		// The client already allows the API endpoint; the identity service
		// must pass the same egress rules.
		if _, err := cloudHTTPClient(identity, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs); err != nil {
			return nil, true, fmt.Errorf("identity_endpoint: %w", err)
		}
	}
	built, err := buildSecretStoreProvider(ctx, provider, p, endpoint, client)
	return built, true, err
}

// resolvedRef resolves an optional credential reference to a token
// provider: nil when the reference is empty.
func resolvedRef(ctx context.Context, name, ref string) (cloudcert.TokenProvider, error) {
	if strings.TrimSpace(ref) == "" {
		return nil, nil
	}
	value, err := resolveDiscoveryCredentialRef(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", name, err)
	}
	return cloudcert.StaticToken(value), nil
}

func buildSecretStoreProvider(ctx context.Context, provider string, p cloudSecretProviderConfig, endpoint string, client *http.Client) (cloudsecret.Provider, error) {
	var token cloudcert.TokenProvider
	switch provider {
	case githubactions.ProviderName, gitlabci.ProviderName, bitwardensm.ProviderName, infisical.ProviderName:
		// Conjur and Akeyless sign in with their own credentials; a token_ref
		// left on them is never resolved.
		var err error
		if token, err = resolvedRef(ctx, "token_ref", p.TokenRef); err != nil {
			return nil, err
		}
		if token == nil && provider != infisical.ProviderName {
			return nil, fmt.Errorf("%s token_ref is required", provider)
		}
	}
	switch provider {
	case githubactions.ProviderName:
		return githubactions.New(githubactions.Config{
			BaseURL: endpoint, Owner: p.Owner, Repo: p.Repo, Environments: p.Environments, Org: p.Org,
			Stores: p.Stores, UserCodespaces: p.UserCodespaces,
			Token: token, NamePrefix: p.NamePrefix, InspectContent: p.InspectContent, HTTPClient: client,
		})
	case gitlabci.ProviderName:
		return gitlabci.New(gitlabci.Config{
			BaseURL: endpoint, Project: p.Project, Group: p.Group, Instance: p.Instance,
			Token: token, NamePrefix: p.NamePrefix, InspectContent: p.InspectContent, HTTPClient: client,
		})
	case infisical.ProviderName:
		clientSecret, err := resolvedRef(ctx, "client_secret_ref", p.ClientSecretRef)
		if err != nil {
			return nil, err
		}
		return infisical.New(infisical.Config{
			BaseURL: endpoint, ClientID: p.ClientID, ClientSecret: clientSecret, Token: token,
			Project: p.Project, Environments: p.Environments, SecretPath: p.PathPrefix,
			NamePrefix: p.NamePrefix, InspectContent: p.InspectContent, HTTPClient: client,
		})
	case conjur.ProviderName:
		apiKey, err := resolvedRef(ctx, "api_key_ref", p.APIKeyRef)
		if err != nil {
			return nil, err
		}
		if apiKey == nil {
			return nil, errors.New("conjur api_key_ref is required")
		}
		return conjur.New(conjur.Config{
			BaseURL: endpoint, Account: p.Account, Login: p.Login, APIKey: apiKey, PathPrefix: p.PathPrefix,
			NamePrefix: p.NamePrefix, InspectContent: p.InspectContent, HTTPClient: client,
		})
	case akeyless.ProviderName:
		accessKey, err := resolvedRef(ctx, "client_secret_ref", p.ClientSecretRef)
		if err != nil {
			return nil, err
		}
		return akeyless.New(akeyless.Config{
			BaseURL: endpoint, AccessID: p.ClientID, AccessKey: accessKey, PathPrefix: p.PathPrefix,
			NamePrefix: p.NamePrefix, InspectContent: p.InspectContent, HTTPClient: client,
		})
	default:
		return bitwardensm.New(bitwardensm.Config{
			BaseURL: endpoint, IdentityURL: p.IdentityEndpoint, AccessToken: token,
			NamePrefix: p.NamePrefix, InspectContent: p.InspectContent, HTTPClient: client,
		})
	}
}
