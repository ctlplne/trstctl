// SPDX-License-Identifier: BUSL-1.1

package ari

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

const maxBody = 1 << 20

// ErrNotAdvertised means the ACME directory does not offer RFC 9773. The
// caller may use its ordinary renewal fallback and check the directory later.
var ErrNotAdvertised = errors.New("ari: renewal information is not advertised")

// Client fetches ACME Renewal Information from an upstream CA's renewalInfo
// endpoint (RFC 9773). Scheduling and persistence belong to its caller.
type Client struct {
	http *http.Client
}

// NewClient returns an ARI client using c, or the SSRF-safe client (SEC-005) when
// c is nil. renewalInfoBase comes from the upstream CA's ACME directory document,
// so the default must not be able to reach loopback or internal addresses; tests
// against a loopback ACME server pass netsec.InsecureLoopbackClient explicitly.
func NewClient(c *http.Client) *Client {
	if c == nil {
		c = netsec.SafeClient(30 * time.Second)
	}
	return &Client{http: c}
}

// DiscoverRenewalInfo reads the ACME directory's public renewalInfo URL. Its
// HTTP client must carry the same operator egress and TLS policy as the selected
// upstream CA. The returned URL is routing metadata, not permission to bypass
// that policy: the caller must bind a second client to its origin before GET.
func (c *Client) DiscoverRenewalInfo(ctx context.Context, directoryURL string) (string, error) {
	directory, err := url.Parse(directoryURL)
	if err != nil || directory == nil || (directory.Scheme != "https" && directory.Scheme != "http") ||
		directory.Host == "" || directory.User != nil || directory.Fragment != "" || directory.Opaque != "" {
		return "", fmt.Errorf("ari: invalid ACME directory endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, directory.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "trstctl-ari/1")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("ari: fetch ACME directory: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxBody {
		return "", fmt.Errorf("ari: directory response exceeds %d bytes", maxBody)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ari: ACME directory returned status %d", resp.StatusCode)
	}
	var payload struct {
		RenewalInfo string `json:"renewalInfo"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", fmt.Errorf("ari: decode ACME directory: %w", err)
	}
	if payload.RenewalInfo == "" {
		return "", ErrNotAdvertised
	}
	endpoint, err := renewalInfoEndpoint(payload.RenewalInfo)
	if err != nil || (directory.Scheme == "https" && endpoint.Scheme != "https") {
		return "", fmt.Errorf("ari: invalid renewal info endpoint")
	}
	return endpoint.String(), nil
}

// FetchRenewalInfo GETs the renewal info for certID from the renewalInfo endpoint
// and returns it along with the server's Retry-After hint (when to poll again).
func (c *Client) FetchRenewalInfo(ctx context.Context, renewalInfoBase, certID string) (RenewalInfo, time.Duration, error) {
	if !ValidCertID(certID) {
		return RenewalInfo{}, 0, fmt.Errorf("ari: malformed certificate identifier")
	}
	base, err := renewalInfoEndpoint(renewalInfoBase)
	if err != nil {
		return RenewalInfo{}, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base.String(), "/")+"/"+certID, nil)
	if err != nil {
		return RenewalInfo{}, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "trstctl-ari/1")
	resp, err := c.http.Do(req)
	if err != nil {
		return RenewalInfo{}, 0, fmt.Errorf("ari: fetch renewal info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return RenewalInfo{}, 0, err
	}
	if len(data) > maxBody {
		return RenewalInfo{}, 0, fmt.Errorf("ari: response exceeds %d bytes", maxBody)
	}
	if resp.StatusCode != http.StatusOK {
		return RenewalInfo{}, 0, fmt.Errorf("ari: renewal info returned status %d", resp.StatusCode)
	}
	var info RenewalInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return RenewalInfo{}, 0, fmt.Errorf("ari: decode renewal info: %w", err)
	}
	if info.SuggestedWindow.Start.IsZero() || !info.SuggestedWindow.End.After(info.SuggestedWindow.Start) {
		return RenewalInfo{}, 0, fmt.Errorf("ari: invalid suggested window")
	}
	return info, parseRetryAfter(resp.Header.Get("Retry-After")), nil
}

func renewalInfoEndpoint(raw string) (*url.URL, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint == nil || (endpoint.Scheme != "https" && endpoint.Scheme != "http") ||
		endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery ||
		endpoint.Fragment != "" || endpoint.Opaque != "" {
		return nil, fmt.Errorf("ari: invalid renewal info endpoint")
	}
	return endpoint, nil
}

// parseRetryAfter reads a Retry-After header (delta-seconds or HTTP-date).
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if when, err := http.ParseTime(v); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
	}
	return 0
}
