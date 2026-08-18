// SPDX-License-Identifier: MIT

package embeddedpostgres

import (
	"io"
	"net/http"
	"strings"
	"testing"
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
