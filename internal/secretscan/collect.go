// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// CollectConfig (N6) has trstctl read a third-party scan's content from the
// provider itself instead of an export an operator downloaded: an image from
// its registry, Slack channel history, Jira issues, and (OD-4) Microsoft
// Teams channel messages and Confluence content. The connection's
// credentials are operator-approved references resolved by the worker; a
// private endpoint needs allow_private_endpoint and its CIDRs, as for
// annotation.
type CollectConfig struct {
	BaseURL     string `json:"base_url"`
	TokenRef    string `json:"token_ref,omitempty"`
	UsernameRef string `json:"username_ref,omitempty"`
	// Registry: the repository and a tag or sha256 digest.
	Repository string `json:"repository,omitempty"`
	Reference  string `json:"reference,omitempty"`
	// Slack: channel IDs. Teams: the team's channel IDs (19:...@thread...).
	Channels []string `json:"channels,omitempty"`
	// Teams: the team's ID (a GUID) whose channels are read.
	Team string `json:"team,omitempty"`
	// Jira: the issues to read.
	JQL string `json:"jql,omitempty"`
	// Confluence: the pages, blog posts and comments to read, by CQL.
	CQL string `json:"cql,omitempty"`
	// CI logs: github or gitlab, and the repository (owner/name, or a GitLab
	// project's ID or path).
	System string `json:"system,omitempty"`
	Repo   string `json:"repo,omitempty"`
	// Since bounds Slack history and Jira issues to the last duration ("720h").
	Since                string   `json:"since,omitempty"`
	MaxItems             int      `json:"max_items,omitempty"`
	MaxBytes             int64    `json:"max_bytes,omitempty"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
}

var (
	collectRepository = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)
	collectReference  = regexp.MustCompile(`^(?:[A-Za-z0-9_][A-Za-z0-9._-]{0,127}|sha256:[a-f0-9]{64})$`)
	collectChannel    = regexp.MustCompile(`^[CGD][A-Z0-9]{2,20}$`)
	collectGitHubRepo = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
	collectGitLabRepo = regexp.MustCompile(`^(?:[0-9]{1,12}|[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+){1,20})$`)
	collectTeamsTeam  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// A Teams channel ID: 19:<id>@thread.tacv2 (or the older .skype).
	collectTeamsChannel = regexp.MustCompile(`^19:[A-Za-z0-9_-]{1,200}@thread\.(?:tacv2|skype)$`)
)

// SinceDuration is the collection's lookback; zero reads everything.
func (c CollectConfig) SinceDuration() (time.Duration, error) {
	if strings.TrimSpace(c.Since) == "" {
		return 0, nil
	}
	return time.ParseDuration(c.Since)
}

// ValidateCollect checks a native collection for a provider: an https (or
// private-granted) base URL, the provider's selectors, bounded limits and a
// lookback, and no export fields beside it.
func ValidateCollect(provider string, c *CollectConfig) error {
	if c == nil {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(c.BaseURL))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Scheme != "https" && (u.Scheme != "http" || !c.AllowPrivateEndpoint)) {
		return errors.New("collect.base_url must be an https URL (plain http only with allow_private_endpoint) with no user, query or fragment")
	}
	if c.AllowPrivateEndpoint && len(c.PrivateEgressCIDRs) == 0 {
		return errors.New("collect.allow_private_endpoint needs private_egress_cidrs")
	}
	if c.MaxItems < 0 || c.MaxItems > 100000 || c.MaxBytes < 0 || c.MaxBytes > 4<<30 {
		return errors.New("collect.max_items (at most 100000) and collect.max_bytes (at most 4 GiB) must be bounded")
	}
	if since, err := c.SinceDuration(); err != nil || since < 0 || since > 400*24*time.Hour {
		return errors.New("collect.since must be a duration up to 400 days, such as 720h")
	}
	if c.UsernameRef != "" && c.TokenRef == "" {
		return errors.New("collect.username_ref needs token_ref")
	}
	normalized := NormalizeThirdPartyProvider(provider)
	if normalized != ThirdPartyProviderTeams && c.Team != "" {
		return errors.New("collect.team is for a Teams collection")
	}
	if normalized != ThirdPartyProviderConfluence && c.CQL != "" {
		return errors.New("collect.cql is for a Confluence collection")
	}
	switch normalized {
	case ThirdPartyProviderContainerRegistry:
		if !collectRepository.MatchString(c.Repository) || !collectReference.MatchString(c.Reference) {
			return errors.New("collect.repository and collect.reference (a tag or sha256 digest) name the image")
		}
		if len(c.Channels) > 0 || c.JQL != "" || c.Since != "" || c.System != "" || c.Repo != "" {
			return errors.New("a registry collection names only its image")
		}
	case ThirdPartyProviderSlack:
		if len(c.Channels) == 0 || len(c.Channels) > 100 {
			return errors.New("collect.channels names 1 to 100 Slack channel IDs")
		}
		for _, ch := range c.Channels {
			if !collectChannel.MatchString(ch) {
				return fmt.Errorf("collect.channels: %q is not a Slack channel ID", ch)
			}
		}
		if c.TokenRef == "" || c.Repository != "" || c.Reference != "" || c.JQL != "" {
			return errors.New("a Slack collection names its channels and a bot token reference")
		}
	case ThirdPartyProviderJira:
		if strings.TrimSpace(c.JQL) == "" || len(c.JQL) > 2000 || c.TokenRef == "" || c.Repository != "" || len(c.Channels) > 0 {
			return errors.New("a Jira collection names its issues by JQL and a token reference")
		}
	case ThirdPartyProviderTeams:
		if !collectTeamsTeam.MatchString(c.Team) {
			return errors.New("collect.team is the team's ID (a GUID)")
		}
		if len(c.Channels) == 0 || len(c.Channels) > 100 {
			return errors.New("collect.channels names 1 to 100 of the team's channel IDs")
		}
		for _, ch := range c.Channels {
			if !collectTeamsChannel.MatchString(ch) {
				return fmt.Errorf("collect.channels: %q is not a Teams channel ID (19:...@thread.tacv2)", ch)
			}
		}
		if c.TokenRef == "" || c.Repository != "" || c.Reference != "" || c.JQL != "" || c.System != "" || c.Repo != "" {
			return errors.New("a Teams collection names its team, channels and a Microsoft Graph token reference")
		}
	case ThirdPartyProviderConfluence:
		if strings.TrimSpace(c.CQL) == "" || len(c.CQL) > 2000 || c.TokenRef == "" || c.Repository != "" || c.Reference != "" ||
			len(c.Channels) > 0 || c.JQL != "" || c.System != "" || c.Repo != "" {
			return errors.New("a Confluence collection names its content by CQL and a token reference")
		}
	case ThirdPartyProviderCICDLog:
		switch {
		case c.System != "github" && c.System != "gitlab":
			return errors.New("collect.system is github or gitlab")
		case c.System == "github" && !collectGitHubRepo.MatchString(c.Repo):
			return errors.New("collect.repo is a GitHub owner/name")
		case c.System == "gitlab" && (len(c.Repo) > 1024 || !collectGitLabRepo.MatchString(c.Repo)):
			return errors.New("collect.repo is a GitLab project ID or path")
		case c.TokenRef == "" || c.Repository != "" || len(c.Channels) > 0 || c.JQL != "":
			return errors.New("a CI log collection names its system, repository and a token reference")
		}
	default:
		return fmt.Errorf("third-party provider %q is not collected natively", provider)
	}
	return nil
}
