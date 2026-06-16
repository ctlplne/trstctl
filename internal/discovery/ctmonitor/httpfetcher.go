package ctmonitor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/ctlog"
)

// maxCTResponse caps a single CT response body to keep a hostile or buggy log
// from exhausting memory.
const maxCTResponse = 64 << 20 // 64 MiB

// httpFetcher is the production Fetcher: it speaks RFC 6962 over HTTP and parses
// responses through the crypto boundary (ctlog).
type httpFetcher struct {
	client *http.Client
}

// NewHTTPFetcher returns a Fetcher that polls real CT logs over HTTP.
func NewHTTPFetcher() Fetcher {
	return &httpFetcher{client: &http.Client{Timeout: 30 * time.Second}}
}

// TreeSize fetches the signed tree head and returns the log's entry count.
func (f *httpFetcher) TreeSize(ctx context.Context, logURL string) (int64, error) {
	body, err := f.get(ctx, logURL, "/ct/v1/get-sth", nil)
	if err != nil {
		return 0, err
	}
	sth, err := ctlog.ParseSTH(body)
	if err != nil {
		return 0, err
	}
	return sth.TreeSize, nil
}

// Entries fetches and parses the log entries in [start, end). RFC 6962's
// get-entries end bound is inclusive, so the request asks for end-1.
func (f *httpFetcher) Entries(ctx context.Context, logURL string, start, end int64) ([]ctlog.Entry, error) {
	if end <= start {
		return nil, nil
	}
	q := url.Values{}
	q.Set("start", strconv.FormatInt(start, 10))
	q.Set("end", strconv.FormatInt(end-1, 10))
	body, err := f.get(ctx, logURL, "/ct/v1/get-entries", q)
	if err != nil {
		return nil, err
	}
	return ctlog.ParseEntries(start, body)
}

func (f *httpFetcher) get(ctx context.Context, base, path string, q url.Values) ([]byte, error) {
	u := strings.TrimRight(base, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("ctmonitor: build request: %w", err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ctmonitor: GET %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ctmonitor: GET %s: %s", path, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCTResponse))
	if err != nil {
		return nil, fmt.Errorf("ctmonitor: read %s: %w", path, err)
	}
	return body, nil
}
