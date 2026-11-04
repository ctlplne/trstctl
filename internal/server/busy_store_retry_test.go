// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// dodBusyStoreRetry reports whether response is the API's documented
// busy-store backpressure — 503 "datastore is busy … retry" — and how long to
// wait before resending the same request with the same Idempotency-Key, which
// replays the completed result when the first attempt's work finished (CI-L35).
// Any other status, including any other 503, is returned to the caller as is,
// and the sixth busy answer is too.
func dodBusyStoreRetry(response *http.Response, attempt int) (time.Duration, bool) {
	if response.StatusCode != http.StatusServiceUnavailable || attempt >= 6 {
		return 0, false
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	_ = response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil || !bytes.Contains(body, []byte("datastore is busy")) {
		return 0, false
	}
	wait := 2 * time.Second
	if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && seconds >= 1 {
		wait = time.Duration(min(seconds, 10)) * time.Second
	}
	return wait, true
}

// CI-L35: the managed-key proof resends only the API's documented busy-store
// backpressure — 503 "datastore is busy … retry" — honoring Retry-After within
// 1–10 s, and gives up after the sixth busy answer. Any other answer, another
// 503 included, reaches the proof's assertions unchanged.
func TestDODBusyStoreRetryResendsOnlyTheBusyStore503(t *testing.T) {
	answer := func(status int, retryAfter, body string) *http.Response {
		h := http.Header{}
		if retryAfter != "" {
			h.Set("Retry-After", retryAfter)
		}
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body))}
	}
	busy := `{"detail":"datastore is busy; the request was bounded by its acquire/statement deadline — retry","status":503}`
	for _, tc := range []struct {
		name    string
		resp    *http.Response
		attempt int
		retry   bool
		wait    time.Duration
	}{
		{"busy store, Retry-After 3", answer(http.StatusServiceUnavailable, "3", busy), 1, true, 3 * time.Second},
		{"busy store, no Retry-After", answer(http.StatusServiceUnavailable, "", busy), 2, true, 2 * time.Second},
		{"busy store, Retry-After capped", answer(http.StatusServiceUnavailable, "90", busy), 1, true, 10 * time.Second},
		{"busy store, sixth answer", answer(http.StatusServiceUnavailable, "1", busy), 6, false, 0},
		{"signer unavailable 503", answer(http.StatusServiceUnavailable, "1", `{"detail":"signer unavailable"}`), 1, false, 0},
		{"400 never retried", answer(http.StatusBadRequest, "", busy), 1, false, 0},
		{"success", answer(http.StatusOK, "", `{}`), 1, false, 0},
	} {
		wait, retry := dodBusyStoreRetry(tc.resp, tc.attempt)
		if retry != tc.retry || wait != tc.wait {
			t.Errorf("%s: retry=%v wait=%s, want %v %s", tc.name, retry, wait, tc.retry, tc.wait)
		}
		// The body is still readable by the caller after the check.
		if body, err := io.ReadAll(tc.resp.Body); err != nil || len(body) == 0 {
			t.Errorf("%s: body consumed (%v)", tc.name, err)
		}
	}
}
