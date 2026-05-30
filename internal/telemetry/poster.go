package telemetry

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPPoster returns a Poster that POSTs the payload as JSON to the endpoint
// using client (or a short-timeout default when client is nil). It reads and
// discards a small response body so connections can be reused, and treats any
// non-2xx status as an error. Telemetry is best-effort: callers ignore the
// error so reporting can never disrupt the control plane.
func HTTPPoster(client *http.Client) Poster {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return func(ctx context.Context, endpoint string, body []byte) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "certctl-telemetry")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("telemetry: endpoint returned %s", resp.Status)
		}
		return nil
	}
}
