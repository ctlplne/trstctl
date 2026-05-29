package ari

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const maxBody = 1 << 20

// Client fetches ACME Renewal Information from an upstream CA's renewalInfo
// endpoint (RFC 9773). It drives renewal timing off the CA's advertised window
// rather than a fixed cron (F6).
type Client struct {
	http *http.Client
}

// NewClient returns an ARI client using c (or a default client when c is nil).
func NewClient(c *http.Client) *Client {
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{http: c}
}

// FetchRenewalInfo GETs the renewal info for certID from the renewalInfo endpoint
// and returns it along with the server's Retry-After hint (when to poll again).
func (c *Client) FetchRenewalInfo(ctx context.Context, renewalInfoBase, certID string) (RenewalInfo, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, renewalInfoBase+"/"+certID, nil)
	if err != nil {
		return RenewalInfo{}, 0, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return RenewalInfo{}, 0, fmt.Errorf("ari: fetch renewal info: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return RenewalInfo{}, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return RenewalInfo{}, 0, fmt.Errorf("ari: renewal info returned status %d", resp.StatusCode)
	}
	var info RenewalInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return RenewalInfo{}, 0, fmt.Errorf("ari: decode renewal info: %w", err)
	}
	return info, parseRetryAfter(resp.Header.Get("Retry-After")), nil
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
