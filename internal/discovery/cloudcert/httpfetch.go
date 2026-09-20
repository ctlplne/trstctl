// SPDX-License-Identifier: BUSL-1.1

package cloudcert

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// maxBody caps a provider response body.
const maxBody = 8 << 20 // 8 MiB

// RetryPolicy bounds how a rate-limited request is retried.
type RetryPolicy struct {
	Max  int           // maximum retries after the first attempt
	Base time.Duration // base backoff, doubled per attempt
}

// DefaultRetry is a conservative bounded policy.
func DefaultRetry() RetryPolicy { return RetryPolicy{Max: 4, Base: 200 * time.Millisecond} }

// Fetch issues req (cloning it per attempt and replaying body) and returns the
// response body, retrying on 429/503 up to the policy, honoring a Retry-After
// header when present. This is the read-only transport the enumerators share, so
// rate limits are respected and the number of calls is bounded.
func Fetch(ctx context.Context, hc *http.Client, req *http.Request, body []byte, rp RetryPolicy) ([]byte, error) {
	if rp.Base <= 0 {
		rp.Base = DefaultRetry().Base
	}
	var lastStatus int
	for attempt := 0; ; attempt++ {
		r := req.Clone(ctx)
		if body != nil {
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}
		resp, err := hc.Do(r) // #nosec G704 -- fetches the cloud provider endpoint declared by the operator's discovery source (CWE-918)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			wait := retryAfter(resp, rp.Base, attempt)
			_ = resp.Body.Close()
			lastStatus = resp.StatusCode
			if attempt >= rp.Max {
				return nil, fmt.Errorf("cloudcert: rate limited (status %d) after %d attempts", lastStatus, attempt+1)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("cloudcert: status %d: %s", resp.StatusCode, bytes.TrimSpace(data))
		}
		return data, nil
	}
}

// GetSigned issues a read-only GET with an optional bearer token, sharing the
// bounded rate-limit retry. It is the transport the token-authenticated
// enumerators (Azure Key Vault, GCP) use.
func GetSigned(ctx context.Context, hc *http.Client, url, bearer string, rp RetryPolicy) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return Fetch(ctx, hc, req, nil, rp)
}

// retryAfter returns the wait before the next attempt: the Retry-After header
// (seconds) if present, else exponential backoff from the base.
func retryAfter(resp *http.Response, base time.Duration, attempt int) time.Duration {
	if h := resp.Header.Get("Retry-After"); h != "" {
		if secs, err := strconv.Atoi(h); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second
		}
	}
	wait := base
	for i := 0; i < attempt; i++ {
		wait *= 2
	}
	return wait
}
