package projections_test

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func externalCATestBaseURL(provider string) string {
	return fmt.Sprintf("https://%s.example.test", provider)
}

func externalCATestHTTPClient(t *testing.T, target string) *http.Client {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse external CA fake URL: %v", err)
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: externalCARewriteTransport{target: u, base: http.DefaultTransport},
	}
}

type externalCARewriteTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (t externalCARewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	u := *clone.URL
	u.Scheme = t.target.Scheme
	u.Host = t.target.Host
	clone.URL = &u
	clone.Host = t.target.Host
	return t.base.RoundTrip(clone)
}
