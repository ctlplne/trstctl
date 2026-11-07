// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// SlackAppConfig is the Slack app an operator registered at Slack (N8): its
// client ID, the client secret and signing secret by reference, Slack's base
// URL, and the public URL Slack returns installs to
// (<public_url>/integrations/slack/oauth/callback) and sends interactions and
// the /trstctl command to.
type SlackAppConfig struct {
	ClientID        string `json:"client_id,omitempty"`
	ClientSecretRef string `json:"client_secret_ref,omitempty"`
	// AppTokenRef (A277) is the app-level token (xapp-) for Socket Mode:
	// trstctl opens the connection and Slack delivers commands and button
	// presses over it, so no inbound endpoint is served. Without it,
	// SigningSecretRef serves Slack's request URLs instead (N8).
	AppTokenRef      string `json:"app_token_ref,omitempty"`
	SigningSecretRef string `json:"signing_secret_ref,omitempty"`
	// APIBase is Slack (https://slack.com by default).
	APIBase string `json:"api_base,omitempty"`
	// PublicURL is this control plane's public https base URL.
	PublicURL string `json:"public_url,omitempty"`
	// AllowPrivateAPI permits a private or loopback api_base (a stand-in),
	// within PrivateEgressCIDRs.
	AllowPrivateAPI    bool     `json:"allow_private_api,omitempty"`
	PrivateEgressCIDRs []string `json:"private_egress_cidrs,omitempty"`
}

// Enabled reports whether the Slack app is configured.
func (c SlackAppConfig) Enabled() bool { return strings.TrimSpace(c.ClientID) != "" }

// SocketMode reports whether Slack's deliveries arrive over trstctl's own
// outbound connection (A277) rather than inbound request URLs.
func (c SlackAppConfig) SocketMode() bool { return strings.TrimSpace(c.AppTokenRef) != "" }

// Validate checks a configured Slack app.
func (c SlackAppConfig) Validate() error {
	if !c.Enabled() {
		if c.ClientSecretRef != "" || c.SigningSecretRef != "" || c.AppTokenRef != "" || c.PublicURL != "" {
			return errors.New("slack_app needs client_id")
		}
		return nil
	}
	if strings.TrimSpace(c.ClientSecretRef) == "" || (strings.TrimSpace(c.AppTokenRef) == "" && strings.TrimSpace(c.SigningSecretRef) == "") {
		return errors.New("slack_app needs client_secret_ref and app_token_ref (Socket Mode, no inbound endpoint) or signing_secret_ref (request URLs)")
	}
	if strings.TrimSpace(c.AppTokenRef) != "" && strings.TrimSpace(c.SigningSecretRef) != "" {
		return errors.New("slack_app takes app_token_ref (Socket Mode) or signing_secret_ref (request URLs), not both")
	}
	public, err := url.Parse(c.PublicURL)
	if err != nil || public.Host == "" || public.RawQuery != "" || public.User != nil || strings.HasSuffix(c.PublicURL, "/") ||
		(public.Scheme != "https" && (public.Scheme != "http" || !c.AllowPrivateAPI)) {
		return fmt.Errorf("slack_app.public_url %q must be this control plane's https base URL", c.PublicURL)
	}
	if c.APIBase != "" {
		base, err := url.Parse(c.APIBase)
		if err != nil || base.Host == "" || (base.Scheme != "https" && (base.Scheme != "http" || !c.AllowPrivateAPI)) {
			return fmt.Errorf("slack_app.api_base %q must be an https URL", c.APIBase)
		}
	}
	if c.AllowPrivateAPI && len(c.PrivateEgressCIDRs) == 0 {
		return errors.New("slack_app.allow_private_api needs private_egress_cidrs")
	}
	return nil
}
