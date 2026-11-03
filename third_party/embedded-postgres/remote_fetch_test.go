// SPDX-License-Identifier: MIT

package embeddedpostgres

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type checksumRoundTripper struct {
	statusCode int
	checksum   string
}

func (r checksumRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	body := "not-a-jar"
	status := http.StatusOK
	if strings.HasSuffix(req.URL.Path, ".sha256") {
		body = r.checksum
		status = r.statusCode
	}
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func TestRemoteFetchRequiresValidChecksumSidecar(t *testing.T) {
	// A missing sidecar is a 404, which is retried; the backoff is not what
	// this test measures.
	restoreSleep := fetchSleep
	fetchSleep = func(time.Duration) {}
	t.Cleanup(func() { fetchSleep = restoreSleep })
	for _, tc := range []struct {
		name       string
		statusCode int
		checksum   string
		want       string
	}{
		{name: "missing sidecar", statusCode: http.StatusNotFound, want: "HTTP 404"},
		{name: "mismatched sidecar", statusCode: http.StatusOK, checksum: strings.Repeat("0", 64), want: "checksums do not match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fetch := defaultRemoteFetchStrategy(
				"https://repo.example.test",
				func() (string, string, PostgresVersion) { return "linux", "amd64", V16 },
				func() (string, bool) { return t.TempDir() + "/postgres.txz", false },
				&http.Client{Transport: checksumRoundTripper{statusCode: tc.statusCode, checksum: tc.checksum}},
			)
			if err := fetch(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("fetch error = %v, want %q", err, tc.want)
			}
		})
	}
}

// A rate-limited or failing mirror is retried with bounded backoff, honoring
// Retry-After (capped); other statuses and transport errors fail at once.
func TestFetchRetriesRateLimitedMirrorWithBoundedBackoff(t *testing.T) {
	var slept []time.Duration
	restoreDelays, restoreSleep, restoreCap := fetchRetryDelays, fetchSleep, maxRetryAfter
	fetchRetryDelays = []time.Duration{time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond}
	fetchSleep = func(d time.Duration) { slept = append(slept, d) }
	maxRetryAfter = 5 * time.Second
	t.Cleanup(func() { fetchRetryDelays, fetchSleep, maxRetryAfter = restoreDelays, restoreSleep, restoreCap })

	statuses := []int{http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusOK}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		status := statuses[min(requests, len(statuses)-1)]
		requests++
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "120")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte("archive"))
	}))
	t.Cleanup(server.Close)
	data, err := fetchBoundedResponse(server.Client(), server.URL, 1024)
	if err != nil || string(data) != "archive" || requests != 3 {
		t.Fatalf("data %q err %v after %d requests", data, err, requests)
	}
	// Retry-After 120 s is capped at 5 s; the 503 without one takes the backoff.
	if len(slept) != 2 || slept[0] != 5*time.Second || slept[1] != 2*time.Millisecond {
		t.Fatalf("slept %v", slept)
	}

	statuses, requests, slept = []int{http.StatusTooManyRequests}, 0, nil
	if _, err := fetchBoundedResponse(server.Client(), server.URL, 1024); err == nil || !strings.Contains(err.Error(), "HTTP 429") || requests != 4 {
		t.Fatalf("persistent 429: err %v after %d requests", err, requests)
	}
	// A transient 404 for a pinned, published archive is retried (CI
	// 41695565837); a persistent one fails after the backoff; other statuses
	// fail at once.
	statuses, requests = []int{http.StatusNotFound, http.StatusOK}, 0
	if data, err := fetchBoundedResponse(server.Client(), server.URL, 1024); err != nil || string(data) != "archive" || requests != 2 {
		t.Fatalf("transient 404: data %q err %v after %d requests", data, err, requests)
	}
	statuses, requests = []int{http.StatusNotFound}, 0
	if _, err := fetchBoundedResponse(server.Client(), server.URL, 1024); err == nil || !strings.Contains(err.Error(), "HTTP 404") || requests != 4 {
		t.Fatalf("persistent 404: err %v after %d requests", err, requests)
	}
	statuses, requests = []int{http.StatusForbidden}, 0
	if _, err := fetchBoundedResponse(server.Client(), server.URL, 1024); err == nil || requests != 1 {
		t.Fatalf("403: err %v after %d requests", err, requests)
	}
	server.Close()
	requests = 0
	if _, err := fetchBoundedResponse(server.Client(), server.URL, 1024); err == nil || requests != 0 {
		t.Fatalf("an unreachable mirror: err %v after %d requests", err, requests)
	}
}
