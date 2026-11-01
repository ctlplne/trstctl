// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// AnnotationConfig is where a third-party scan's findings are written back
// at the provider (A174): the provider API's base URL and a token by
// reference (Jira may add a username reference for basic authentication),
// the private-endpoint allowance, and for CI logs and container images the
// object the artifact came from. Slack and Jira findings carry their object
// from the export itself. Auto annotates each new finding without an
// operator; otherwise an operator annotates a finding from its detail.
type AnnotationConfig struct {
	System               string   `json:"system,omitempty"`
	BaseURL              string   `json:"base_url"`
	TokenRef             string   `json:"token_ref"`
	UsernameRef          string   `json:"username_ref,omitempty"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
	Repo                 string   `json:"repo,omitempty"`
	CommitSHA            string   `json:"commit_sha,omitempty"`
	Repository           string   `json:"repository,omitempty"`
	Digest               string   `json:"digest,omitempty"`
	Auto                 bool     `json:"auto,omitempty"`
}

var (
	commitSHAPattern = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ErrNoAnnotation reports a scan configured without an annotation connection.
var ErrNoAnnotation = errors.New("secretscan: this scan has no annotation connection")

// ValidateAnnotation checks an annotation block for a third-party provider.
func ValidateAnnotation(provider string, a *AnnotationConfig) error {
	if a == nil {
		return nil
	}
	base, err := url.Parse(strings.TrimSpace(a.BaseURL))
	if err != nil || base.Host == "" || (base.Scheme != "https" && (base.Scheme != "http" || !a.AllowPrivateEndpoint)) {
		return errors.New("annotation.base_url must be an https URL (http only for an approved private endpoint)")
	}
	if strings.TrimSpace(a.TokenRef) == "" {
		return errors.New("annotation.token_ref is required")
	}
	if a.AllowPrivateEndpoint && len(a.PrivateEgressCIDRs) == 0 {
		return errors.New("annotation.allow_private_endpoint needs private_egress_cidrs")
	}
	switch NormalizeThirdPartyProvider(provider) {
	case ThirdPartyProviderCICDLog:
		if a.System != "github" && a.System != "gitlab" {
			return errors.New("annotation.system must be github or gitlab for a CI log")
		}
		if strings.TrimSpace(a.Repo) == "" || !commitSHAPattern.MatchString(strings.TrimSpace(a.CommitSHA)) {
			return errors.New("annotation.repo and annotation.commit_sha (hex) name the CI run's commit")
		}
	case ThirdPartyProviderContainerRegistry:
		if strings.TrimSpace(a.Repository) == "" || !digestPattern.MatchString(strings.TrimSpace(a.Digest)) {
			return errors.New("annotation.repository and annotation.digest (sha256:...) name the image")
		}
	case ThirdPartyProviderSlack, ThirdPartyProviderJira:
		if a.System != "" || a.Repo != "" || a.CommitSHA != "" || a.Repository != "" || a.Digest != "" {
			return fmt.Errorf("a %s finding's place comes from the export; annotation names only the connection", provider)
		}
	default:
		return fmt.Errorf("third-party provider %q has no annotation", provider)
	}
	return nil
}

// AnnotationProvider names the provider API a scan's findings are annotated
// at: slack, jira, github or gitlab (CI logs), or registry.
func (c ThirdPartyScanConfig) AnnotationProvider() string {
	if c.Annotation == nil {
		return ""
	}
	switch NormalizeThirdPartyProvider(c.Provider) {
	case ThirdPartyProviderSlack:
		return "slack"
	case ThirdPartyProviderJira:
		return "jira"
	case ThirdPartyProviderCICDLog:
		return c.Annotation.System
	case ThirdPartyProviderContainerRegistry:
		return "registry"
	default:
		return ""
	}
}

// ConfiguredObject is the provider object a CI log or container image came
// from, as the annotation names it. Slack and Jira objects come from the
// export (LocateThirdPartyObject), so they have none here.
func (c ThirdPartyScanConfig) ConfiguredObject() map[string]string {
	if c.Annotation == nil {
		return nil
	}
	switch NormalizeThirdPartyProvider(c.Provider) {
	case ThirdPartyProviderCICDLog:
		return map[string]string{"kind": "ci_commit", "repo": strings.TrimSpace(c.Annotation.Repo), "commit_sha": strings.TrimSpace(c.Annotation.CommitSHA)}
	case ThirdPartyProviderContainerRegistry:
		return map[string]string{"kind": "oci_image", "repository": strings.TrimSpace(c.Annotation.Repository), "digest": strings.TrimSpace(c.Annotation.Digest)}
	default:
		return nil
	}
}

// ProviderObject is the provider object of one finding: configured for CI
// logs and images, located in the export for Slack and Jira.
func (c ThirdPartyScanConfig) ProviderObject(artifactPath, file string, line int) (map[string]string, bool) {
	if object := c.ConfiguredObject(); object != nil {
		return object, true
	}
	return LocateThirdPartyObject(c.Provider, artifactPath, file, line)
}
