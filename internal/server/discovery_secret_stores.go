// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/doppler"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/githubactions"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/gitlabci"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/onepassword"
	"trstctl.com/trstctl/internal/netsec"
)

// secretStoreProvider builds the code-host and secret-store providers beyond
// the cloud secret managers (A173): GitHub Actions secrets, GitLab CI/CD
// variables, 1Password Connect and Doppler. It reports false for a provider
// it does not know, so the caller names it unsupported.
func secretStoreProvider(ctx context.Context, p cloudSecretProviderConfig) (cloudsecret.Provider, bool, error) {
	provider := strings.TrimSpace(p.Provider)
	switch provider {
	case githubactions.ProviderName, gitlabci.ProviderName, onepassword.ProviderName, doppler.ProviderName:
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
	token, err := resolveDiscoveryCredentialRef(ctx, p.TokenRef)
	if err != nil {
		return nil, true, fmt.Errorf("resolve token_ref: %w", err)
	}
	built, err := buildSecretStoreProvider(provider, p, endpoint, cloudcert.StaticToken(token), client)
	return built, true, err
}

func buildSecretStoreProvider(provider string, p cloudSecretProviderConfig, endpoint string, token cloudcert.TokenProvider, client *http.Client) (cloudsecret.Provider, error) {
	switch provider {
	case githubactions.ProviderName:
		return githubactions.New(githubactions.Config{
			BaseURL: endpoint, Owner: p.Owner, Repo: p.Repo, Environments: p.Environments, Org: p.Org,
			Token: token, NamePrefix: p.NamePrefix, InspectContent: p.InspectContent, HTTPClient: client,
		})
	case gitlabci.ProviderName:
		return gitlabci.New(gitlabci.Config{
			BaseURL: endpoint, Project: p.Project, Group: p.Group,
			Token: token, NamePrefix: p.NamePrefix, InspectContent: p.InspectContent, HTTPClient: client,
		})
	case onepassword.ProviderName:
		return onepassword.New(onepassword.Config{
			BaseURL: endpoint, Vaults: p.Vaults,
			Token: token, NamePrefix: p.NamePrefix, InspectContent: p.InspectContent, HTTPClient: client,
		})
	default:
		return doppler.New(doppler.Config{
			BaseURL: endpoint, Project: p.Project, Configs: p.Configs,
			Token: token, NamePrefix: p.NamePrefix, InspectContent: p.InspectContent, HTTPClient: client,
		})
	}
}
