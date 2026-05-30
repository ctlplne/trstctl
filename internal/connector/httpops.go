package connector

import (
	"fmt"
	"net/http"
)

// httpOps is an Ops for API-based connectors: it performs HTTP requests through
// a given client and refuses the file, exec, and raw-send operations. The
// client carries the target's TLS trust and authentication (its transport).
type httpOps struct {
	client *http.Client
}

var (
	_ Ops       = (*httpOps)(nil)
	_ Requester = (*httpOps)(nil)
)

// NewHTTPOps returns an Ops (and Requester) that performs HTTP requests via
// client (the default client when nil). It is the production Ops for API
// connectors — F5 BIG-IP and the cloud certificate stores.
func NewHTTPOps(client *http.Client) Ops {
	if client == nil {
		client = http.DefaultClient
	}
	return &httpOps{client: client}
}

// Request performs the HTTP request.
func (h *httpOps) Request(req *http.Request) (*http.Response, error) {
	return h.client.Do(req)
}

// Send is not supported by an HTTP-only target.
func (h *httpOps) Send(string, []byte) error {
	return fmt.Errorf("connector: HTTP-only target does not support Send")
}

// WriteFile is not supported by an HTTP-only target.
func (h *httpOps) WriteFile(string, []byte) error {
	return fmt.Errorf("connector: HTTP-only target does not support WriteFile")
}

// Exec is not supported by an HTTP-only target.
func (h *httpOps) Exec(string, []string) error {
	return fmt.Errorf("connector: HTTP-only target does not support Exec")
}
