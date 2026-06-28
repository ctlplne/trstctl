package ca

import (
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

const defaultExternalCATimeout = 10 * time.Second

// HTTPClientConfig is the outbound network policy for HTTP-backed external CA
// connectors. The zero value is public-HTTPS-only through the shared SSRF guard.
// AllowPrivateCIDRs is the explicit private-CA allowlist: resolved private IPs
// are allowed only when they fall inside one of these prefixes.
type HTTPClientConfig struct {
	AllowPrivateCIDRs []netip.Prefix
}

// DefaultExternalCAHTTPClient is the guarded default for HTTP-backed CA plugins.
func DefaultExternalCAHTTPClient(cfg HTTPClientConfig) *http.Client {
	return netsec.SafeClientWithOptions(defaultExternalCATimeout, netsec.SafeClientOptions{
		AllowPrivateCIDRs: append([]netip.Prefix(nil), cfg.AllowPrivateCIDRs...),
	})
}

// ValidateExternalCAEndpoint checks operator-configured CA endpoints before a
// request is built. DNS rebinding is still caught later by the guarded dialer.
func ValidateExternalCAEndpoint(provider, endpoint string, cfg HTTPClientConfig) error {
	if err := netsec.ValidatePublicHTTPSURLWithOptions(endpoint, netsec.SafeClientOptions{
		AllowPrivateCIDRs: append([]netip.Prefix(nil), cfg.AllowPrivateCIDRs...),
	}); err != nil {
		return fmt.Errorf("%s: validate endpoint: %w", provider, err)
	}
	return nil
}
