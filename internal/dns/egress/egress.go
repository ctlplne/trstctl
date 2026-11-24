// SPDX-License-Identifier: BUSL-1.1

// Package egress validates tenant-selected DNS-01 provider destinations. It
// handles the HTTP providers and the UDP RFC 2136 server with one policy.
package egress

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/netsec"
)

// Validate checks a provider's configured endpoint before it can be stored or
// used by an outbox worker. DNS answers are checked again by the client dialer.
func Validate(provider string, raw json.RawMessage, opts netsec.SafeClientOptions) error {
	var cfg struct {
		Endpoint string `json:"endpoint"`
		Server   string `json:"server"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("dns-01 egress: invalid provider config: %w", err)
	}
	if provider == "rfc2136" {
		if cfg.Endpoint != "" || cfg.Server == "" {
			return fmt.Errorf("dns-01 egress: rfc2136 requires server and forbids endpoint")
		}
		return validateServer(cfg.Server, opts)
	}
	if cfg.Server != "" {
		return fmt.Errorf("dns-01 egress: HTTP provider forbids server")
	}
	if cfg.Endpoint == "" {
		if provider == "webhook" {
			return fmt.Errorf("dns-01 egress: webhook requires endpoint")
		}
		return nil // vendor packages use their fixed public HTTPS default
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.User != nil || u.Opaque != "" || u.Fragment != "" || strings.ContainsAny(cfg.Endpoint, "\r\n\x00") {
		return fmt.Errorf("dns-01 egress: invalid HTTPS endpoint")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("dns-01 egress: endpoint must use HTTP or HTTPS")
	}
	// The static URL guard validates the host against the same CIDR policy.
	// Actual HTTP/HTTPS scheme, resolved addresses and redirects are enforced
	// by the guarded client at dial time.
	check := *u
	check.Scheme = "https"
	if err := netsec.ValidatePublicHTTPSURLWithOptions(check.String(), opts); err != nil {
		return fmt.Errorf("dns-01 egress: %w", err)
	}
	return nil
}

func validateServer(server string, opts netsec.SafeClientOptions) error {
	if strings.TrimSpace(server) != server || strings.ContainsAny(server, "/@?#\\\r\n\x00") {
		return fmt.Errorf("dns-01 egress: invalid RFC 2136 server")
	}
	host := server
	if net.ParseIP(server) == nil {
		if h, port, err := net.SplitHostPort(server); err == nil {
			if port == "" {
				return fmt.Errorf("dns-01 egress: invalid RFC 2136 server port")
			}
			host = h
		} else if strings.Contains(server, ":") {
			return fmt.Errorf("dns-01 egress: invalid RFC 2136 server")
		}
	}
	if host == "" {
		return fmt.Errorf("dns-01 egress: missing RFC 2136 server host")
	}
	if err := netsec.ValidatePublicHTTPSURLWithOptions("https://"+net.JoinHostPort(host, "53"), opts); err != nil {
		return fmt.Errorf("dns-01 egress: %w", err)
	}
	return nil
}
