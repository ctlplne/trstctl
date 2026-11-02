// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
)

// hostedAPIResponseLimit bounds a hosted rotator's response body.
const hostedAPIResponseLimit = 256 << 10

// hostedAPI is the hosted rotators' JSON REST call (A240): requests go through
// the operator's SSRF-guarded client to the configured endpoint, the caller's
// authenticate callback borrows the sealed credential only while the headers
// are set, and responses are read to a bound for the caller to wipe.
type hostedAPI struct {
	name     string
	endpoint string
	client   *http.Client
}

func newHostedAPI(name, endpoint string, allowInsecureLoopback bool, client *http.Client) (hostedAPI, error) {
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(endpoint, allowInsecureLoopback); err != nil {
		return hostedAPI{}, fmt.Errorf("dynsecret %s: endpoint: %w", name, err)
	}
	if client == nil {
		return hostedAPI{}, fmt.Errorf("dynsecret %s: an HTTP client is required", name)
	}
	return hostedAPI{name: name, endpoint: strings.TrimRight(endpoint, "/"), client: client}, nil
}

// call sends body (JSON, or none when nil) and returns the status and the
// response body.
func (h hostedAPI) call(ctx context.Context, method, path string, body []byte, authenticate func(http.Header) error) (int, []byte, error) {
	var payload io.Reader
	if body != nil {
		payload = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.endpoint+path, payload)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if authenticate != nil {
		if err := authenticate(req.Header); err != nil {
			return 0, nil, err
		}
	}
	resp, err := h.client.Do(req) // #nosec G704 -- the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918)
	if err != nil {
		return 0, nil, fmt.Errorf("dynsecret %s: %w", h.name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	response, err := io.ReadAll(io.LimitReader(resp.Body, hostedAPIResponseLimit))
	if err != nil {
		secret.Wipe(response)
		return 0, nil, fmt.Errorf("dynsecret %s: read the response: %w", h.name, err)
	}
	return resp.StatusCode, response, nil
}

// bearerValue authenticates as "Authorization: Bearer" with a credential the
// caller holds (a successor being verified).
func bearerValue(token []byte) func(http.Header) error {
	return func(header http.Header) error {
		header.Set("Authorization", "Bearer "+string(token))
		return nil
	}
}
