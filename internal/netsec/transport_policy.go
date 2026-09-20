// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// ValidateHTTPSOrInsecureLoopbackURL enforces the one narrow plaintext escape
// hatch used by local development emulators. HTTPS is always acceptable at this
// layer. HTTP is acceptable only when the caller explicitly opted in and the URL
// names localhost or a literal address in 127.0.0.0/8 or ::1.
//
// This checks the URL text. InsecureLoopbackClient performs the matching
// resolved-address check immediately before each socket is opened, so a poisoned
// localhost resolver entry cannot turn the development escape hatch into public
// or private-network plaintext egress.
func ValidateHTTPSOrInsecureLoopbackURL(raw string, allowInsecureLoopback bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("%w: outbound endpoint must be an absolute URL", ErrSSRFBlocked)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if !allowInsecureLoopback {
			return fmt.Errorf("%w: outbound endpoint must use https; plaintext requires explicit insecure-loopback opt-in", ErrSSRFBlocked)
		}
		if !isLoopbackURLHost(u.Hostname()) {
			return fmt.Errorf("%w: insecure HTTP endpoint must be localhost, 127.0.0.0/8, or ::1", ErrSSRFBlocked)
		}
		return nil
	default:
		return fmt.Errorf("%w: outbound endpoint must use https", ErrSSRFBlocked)
	}
}

// IsInsecureLoopbackHTTPURL reports whether raw is an HTTP URL whose host is in
// the narrowly accepted loopback name/address set. Callers must still require an
// explicit operator opt-in before constructing a client for it.
func IsInsecureLoopbackHTTPURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && strings.EqualFold(u.Scheme, "http") && u.Host != "" && isLoopbackURLHost(u.Hostname())
}

func isLoopbackURLHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}

// InsecureLoopbackClient returns a client that can physically dial only
// loopback addresses. It is intentionally more restrictive than SafeClient:
// public and RFC-1918 addresses are both refused, even if a resolver returns one
// for the literal hostname "localhost". Redirects are rechecked before dialing.
func InsecureLoopbackClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	transport := &http.Transport{
		DialContext:           dialLoopbackContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableKeepAlives:     true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("netsec: too many redirects")
			}
			if req == nil || req.URL == nil {
				return fmt.Errorf("%w: redirect is missing a URL", ErrSSRFBlocked)
			}
			if err := ValidateHTTPSOrInsecureLoopbackURL(req.URL.String(), true); err != nil {
				return err
			}
			if len(via) > 0 {
				previous := via[len(via)-1].URL
				if !strings.EqualFold(req.URL.Scheme, previous.Scheme) || !strings.EqualFold(req.URL.Host, previous.Host) {
					return fmt.Errorf("%w: insecure-loopback client refuses a cross-origin or scheme-changing redirect", ErrSSRFBlocked)
				}
			}
			if !isLoopbackURLHost(req.URL.Hostname()) {
				return fmt.Errorf("%w: insecure-loopback client refuses a non-loopback redirect", ErrSSRFBlocked)
			}
			return nil
		},
	}
}

func dialLoopbackContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid loopback address: %v", ErrSSRFBlocked, err)
	}
	if !isLoopbackURLHost(host) {
		return nil, fmt.Errorf("%w: insecure-loopback client refuses host %q", ErrSSRFBlocked, host)
	}

	addresses := []netip.Addr{}
	if literal, parseErr := netip.ParseAddr(host); parseErr == nil {
		addresses = append(addresses, literal.Unmap())
	} else {
		resolved, resolveErr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve loopback host %q: %w", host, resolveErr)
		}
		for _, item := range resolved {
			item = item.Unmap()
			if !item.IsLoopback() {
				return nil, fmt.Errorf("%w: loopback host %q resolved to non-loopback %s", ErrSSRFBlocked, host, item)
			}
			addresses = append(addresses, item)
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("%w: loopback host %q resolved to no addresses", ErrSSRFBlocked, host)
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	var dialErr error
	for _, item := range addresses {
		connection, connectErr := dialer.DialContext(ctx, network, net.JoinHostPort(item.String(), port))
		if connectErr == nil {
			return connection, nil
		}
		dialErr = errors.Join(dialErr, connectErr)
	}
	return nil, dialErr
}
