package connector

import (
	"io"
	"net/http"
	"strings"
	"sync"
)

// MemoryOps is an in-memory deployment target — the shared harness connector
// authors test against and the conformance suite drives. It records what a
// connector sent over the network, wrote to disk, executed, and requested over
// HTTP, so a test can assert the credential landed. It satisfies Ops and
// Requester.
type MemoryOps struct {
	mu       sync.Mutex
	sent     map[string][]byte
	files    map[string][]byte
	execs    [][]string
	requests map[string][]byte // "METHOD URL" -> request body
}

var (
	_ Ops       = (*MemoryOps)(nil)
	_ Requester = (*MemoryOps)(nil)
)

// NewMemoryOps returns an empty in-memory target.
func NewMemoryOps() *MemoryOps {
	return &MemoryOps{sent: map[string][]byte{}, files: map[string][]byte{}, requests: map[string][]byte{}}
}

// Request records an HTTP request (method, URL, and body) and returns a 200 OK
// with an empty body. It lets the conformance suite drive API connectors
// deterministically.
func (m *MemoryOps) Request(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	m.mu.Lock()
	m.requests[req.Method+" "+req.URL.String()] = clone(body)
	m.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// Send records payload delivered to target (PUT semantics: the latest wins).
func (m *MemoryOps) Send(target string, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent[target] = clone(payload)
	return nil
}

// WriteFile records data written at path (PUT semantics).
func (m *MemoryOps) WriteFile(path string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[path] = clone(data)
	return nil
}

// Exec records an activation command.
func (m *MemoryOps) Exec(name string, args []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.execs = append(m.execs, append([]string{name}, args...))
	return nil
}

// Sent returns the payload last delivered to target.
func (m *MemoryOps) Sent(target string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.sent[target]
	return clone(v), ok
}

// File returns the data last written at path.
func (m *MemoryOps) File(path string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.files[path]
	return clone(v), ok
}

// Files returns a copy of all written files.
func (m *MemoryOps) Files() map[string][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][]byte, len(m.files))
	for k, v := range m.files {
		out[k] = clone(v)
	}
	return out
}

// Targets returns the network targets sent to.
func (m *MemoryOps) Targets() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.sent))
	for k := range m.sent {
		out = append(out, k)
	}
	return out
}

// Execs returns the commands run, in order.
func (m *MemoryOps) Execs() [][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]string, len(m.execs))
	copy(out, m.execs)
	return out
}

// Requests returns the HTTP requests made, keyed by "METHOD URL".
func (m *MemoryOps) Requests() map[string][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][]byte, len(m.requests))
	for k, v := range m.requests {
		out[k] = clone(v)
	}
	return out
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
