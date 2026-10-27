// SPDX-License-Identifier: BUSL-1.1

package pluginhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/tetratelabs/wazero/api"
)

// Per-call inputs and host-made HTTP calls (A193).
//
// A connector plugin deploying to an appliance needs what the first ABI did not
// give it: the certificate it is deploying, the target it is deploying to, and
// a way to call the appliance's API as an administrator. The first two are
// inputs the host hands the guest for one call. The third is a request the host
// makes FOR the guest, adding the credential itself, so the guest never holds
// the appliance password or token; whoever runs the call (the relay) also
// removes the credential from the response, because an appliance can echo it
// back. The certificate's private key is never an input the guest can read: a
// request names it by reference and the host splices it into the body.

const (
	// CapInputRead lets the guest read the call's named inputs.
	CapInputRead Capability = "input.read"
	// CapHTTP lets the guest ask the host to make an HTTP request. Constraints
	// are host[:port] authorities, matched like CapNetDial's.
	CapHTTP Capability = "net.http"
)

// Bounds on the HTTP ABI. A guest controls these sizes.
const (
	maxHTTPRequestBytes  = 1 << 20
	maxHTTPResponseBytes = 1 << 20
	maxInputNameBytes    = 256
)

// HTTPRequest is what a guest asks the host to send.
type HTTPRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	// Body is a literal body. BodyInput sends the named input's bytes instead,
	// and JSON sends a JSON document whose {"$input": "<name>"} values become
	// that input's text: the ways a guest sends a private key it cannot read.
	Body      string          `json:"body,omitempty"`
	BodyInput string          `json:"body_input,omitempty"`
	JSON      json.RawMessage `json:"json,omitempty"`
	// Auth asks the host to add the target's credential: "basic", "bearer" or
	// "header" (with AuthHeader naming the header). Empty sends none.
	Auth       string `json:"auth,omitempty"`
	AuthHeader string `json:"auth_header,omitempty"`
}

// HTTPResponse is what the host returns to the guest. Truncated reports a body
// cut to fit the guest's buffer.
type HTTPResponse struct {
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      string            `json:"body,omitempty"`
	Truncated bool              `json:"truncated,omitempty"`
}

// HTTPDoer makes a guest's request: it resolves input references, adds the
// credential, sends it, and returns the response with the credential removed.
type HTTPDoer func(ctx context.Context, req HTTPRequest) (HTTPResponse, error)

// Invocation is one call's inputs and services. ReadOnly is the test
// entrypoint's grant: no filesystem writes, and HTTP limited to GET and HEAD.
type Invocation struct {
	Inputs   map[string][]byte
	HTTP     HTTPDoer
	ReadOnly bool
}

type invocationKey struct{}

func invocationFrom(ctx context.Context) *Invocation {
	inv, _ := ctx.Value(invocationKey{}).(*Invocation)
	return inv
}

// InvokeWith calls fn with inv's inputs and services in reach of the guest's
// host functions for this call only.
func (h *Host) InvokeWith(ctx context.Context, p *Plugin, fn string, inv Invocation) (uint64, error) {
	return h.Invoke(context.WithValue(ctx, invocationKey{}, &inv), p, fn)
}

// errReadOnly marks an operation the read-only test grant refuses.
var errReadOnly = fmt.Errorf("%w: the test entrypoint runs read-only", errDenied)

// hostInputRead implements input_read(name_ptr, name_len, out_ptr, out_cap,
// out_len_ptr): the named input's bytes, as cap_read returns a file's.
func (s *sandbox) hostInputRead(ctx context.Context, m api.Module, namePtr, nameLen, outPtr, outCap, outLenPtr uint32) uint32 {
	name, ok := guestBytes(m, namePtr, nameLen, maxInputNameBytes)
	if !ok || outCap > maxReadBytes {
		return s.refuse(errBadGuestPointer)
	}
	inv := invocationFrom(ctx)
	if inv == nil {
		return s.refuse(errors.New("pluginhost: this call has no inputs"))
	}
	value, found := inv.Inputs[string(name)]
	if !found || len(value) > int(outCap) {
		return s.refuse(fmt.Errorf("pluginhost: input %q is absent or larger than the buffer", name))
	}
	return s.writeOut(m, value, outPtr, outLenPtr)
}

// hostHTTP implements cap_http(req_ptr, req_len, out_ptr, out_cap,
// out_len_ptr): the request is JSON (HTTPRequest), the response JSON
// (HTTPResponse) written to out_ptr with its length at out_len_ptr.
func (s *sandbox) hostHTTP(ctx context.Context, m api.Module, reqPtr, reqLen, outPtr, outCap, outLenPtr uint32) uint32 {
	raw, ok := guestBytes(m, reqPtr, reqLen, maxHTTPRequestBytes)
	if !ok || outCap > maxHTTPResponseBytes {
		return s.refuse(errBadGuestPointer)
	}
	var req HTTPRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return s.refuse(fmt.Errorf("pluginhost: http request: %w", err))
	}
	req.Method = strings.ToUpper(strings.TrimSpace(req.Method))
	if req.Method == "" {
		req.Method = "GET"
	}
	u, err := url.Parse(req.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return s.refuse(fmt.Errorf("pluginhost: http request URL must be an http(s) URL with a host and no credentials"))
	}
	authority := u.Host
	if u.Port() == "" {
		port := "443"
		if u.Scheme == "http" {
			port = "80"
		}
		authority = net.JoinHostPort(u.Hostname(), port)
	}
	if !s.grant.Allows(CapHTTP, authority) {
		return s.refuse(errDenied)
	}
	inv := invocationFrom(ctx)
	if inv == nil || inv.HTTP == nil {
		return s.refuse(errors.New("pluginhost: this call cannot make HTTP requests"))
	}
	if inv.ReadOnly && req.Method != "GET" && req.Method != "HEAD" {
		return s.refuse(errReadOnly)
	}
	resp, err := inv.HTTP(ctx, req)
	if err != nil {
		return s.refuse(err)
	}
	out, err := fitHTTPResponse(resp, int(outCap))
	if err != nil {
		return s.refuse(err)
	}
	atomic.AddInt64(&s.stats.requests, 1)
	return s.writeOut(m, out, outPtr, outLenPtr)
}

// fitHTTPResponse encodes resp within limit bytes, cutting the body (and
// saying so) when the whole response does not fit.
func fitHTTPResponse(resp HTTPResponse, limit int) ([]byte, error) {
	out, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	if len(out) <= limit {
		return out, nil
	}
	body := resp.Body
	resp.Truncated = true
	for len(body) > 0 {
		cut := len(body) - (len(out) - limit) - 1
		if cut < 0 {
			cut = 0
		}
		body = strings.ToValidUTF8(body[:cut], "")
		resp.Body = body
		if out, err = json.Marshal(resp); err != nil {
			return nil, err
		}
		if len(out) <= limit {
			return out, nil
		}
	}
	return nil, errors.New("pluginhost: the response does not fit the guest's buffer")
}

// writeOut copies data into guest memory at outPtr with its length at
// outLenPtr.
func (s *sandbox) writeOut(m api.Module, data []byte, outPtr, outLenPtr uint32) uint32 {
	n := len(data)
	if n > math.MaxUint32 {
		return s.refuse(errBadGuestPointer)
	}
	mem := m.Memory()
	if mem == nil || !mem.Write(outPtr, data) || !mem.WriteUint32Le(outLenPtr, uint32(n)) {
		return s.refuse(errBadGuestPointer)
	}
	return statusOK
}
