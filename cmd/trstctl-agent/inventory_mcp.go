// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent"
	agentdiscovery "trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secretscan/validity"
)

// MCP client configuration inventory (P7): the MCP servers desktop
// assistants and IDEs on this host are configured to start or call, with any
// static credential named by field and never sent.
var inventoryMCPConfigRoots = flag.String("inventory-mcp-config-roots", "",
	"comma-separated directories (home or configuration directories) whose MCP client configuration files the agent reads, by format: each configured server, its transport and program or host, and which fields hold a static credential; values never leave the host, and an unchanged rescan sends nothing")

// Checks of the static tokens found there (P14-L2): opt-in by provider, each
// made from this host at the provider's identity endpoint, with only the
// verdict reported.
var (
	inventoryMCPValidityProviders = flag.String("inventory-mcp-validity-providers", "",
		"comma-separated providers (github, gitlab, slack) whose static tokens in MCP client configuration this agent checks from this host at the provider's identity endpoint: only the verdict (valid, invalid, unknown or unchecked, with the user or workspace) is reported, never the value; empty checks none")
	inventoryMCPValidityEndpoints = flag.String("inventory-mcp-validity-endpoints", "",
		"comma-separated provider=https://base pairs for --inventory-mcp-validity-providers (a GitHub Enterprise Server's https://host/api/v3, a self-managed GitLab's root); default each provider's public endpoint")
	inventoryMCPValidityAllowlist = flag.String("inventory-mcp-validity-allowlist", "",
		"comma-separated https://host[:port] destinations an MCP credential check may call; empty declares the default endpoint of each named provider, and a check aimed anywhere else is refused before it is sent")
)

// mcpValidityProviders are the providers a bare token found in MCP client
// configuration can be checked with.
var mcpValidityProviders = map[string]bool{validity.ProviderGitHub: true, validity.ProviderGitLab: true, validity.ProviderSlack: true}

// mcpChecker checks the static tokens MCP client configuration holds, when
// providers are named (set at startup by setupMCPValidity).
var mcpChecker *validity.Checker

// setupMCPValidity validates the MCP credential check flags at startup.
func setupMCPValidity() error {
	// The egress-safe client, as the control plane's checks use: a check
	// reaches public addresses only.
	c, err := mcpValidityChecker(*inventoryMCPConfigRoots, *inventoryMCPValidityProviders, *inventoryMCPValidityEndpoints,
		*inventoryMCPValidityAllowlist, netsec.SafeClient(10*time.Second))
	if err != nil {
		return err
	}
	mcpChecker = c
	return nil
}

// mcpValidityChecker builds the MCP credential checker, or nil when no
// provider is named.
func mcpValidityChecker(roots, providers, endpoints, allowlist string, client *http.Client) (*validity.Checker, error) {
	named := splitList(providers)
	if len(named) == 0 {
		if strings.TrimSpace(endpoints) != "" || strings.TrimSpace(allowlist) != "" {
			return nil, errors.New("--inventory-mcp-validity-endpoints and --inventory-mcp-validity-allowlist need --inventory-mcp-validity-providers")
		}
		return nil, nil
	}
	if len(splitList(roots)) == 0 {
		return nil, errors.New("--inventory-mcp-validity-providers needs --inventory-mcp-config-roots")
	}
	seen := map[string]bool{}
	for _, p := range named {
		if !mcpValidityProviders[p] || seen[p] {
			return nil, fmt.Errorf("--inventory-mcp-validity-providers: %q must be github, gitlab or slack, named once", p)
		}
		seen[p] = true
	}
	eps := map[string]string{}
	for _, pair := range splitList(endpoints) {
		p, base, ok := strings.Cut(pair, "=")
		u, err := url.Parse(base)
		if !ok || !seen[p] || err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return nil, fmt.Errorf("--inventory-mcp-validity-endpoints: %q must be a named provider=https://base", pair)
		}
		eps[p] = base
	}
	allow := splitList(allowlist)
	for _, entry := range allow {
		u, err := url.Parse(entry)
		if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
			return nil, fmt.Errorf("--inventory-mcp-validity-allowlist: %q must be https://host[:port]", entry)
		}
	}
	return validity.New(validity.Config{Providers: named, Endpoints: eps, Allowlist: allow, Client: client}), nil
}

func reportMCPInventory(ctx context.Context, a *agent.Agent, ch agent.ChannelClient, keyPath string) {
	roots := splitList(*inventoryMCPConfigRoots)
	if len(roots) == 0 {
		return
	}
	state := filepath.Join(filepath.Dir(keyPath), "mcp-inventory.digest")
	var checkers []agentdiscovery.CredentialChecker
	if mcpChecker != nil {
		checkers = append(checkers, mcpChecker)
	}
	resp, sent, err := a.ReportMCPInventory(ctx, ch, roots, state, checkers...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: MCP client configuration inventory report failed:", err)
		return
	}
	if sent {
		fmt.Printf("trstctl-agent: reported %d MCP servers (run %s, rejected %d)\n", resp.Recorded, resp.RunID, resp.Rejected)
	}
}
