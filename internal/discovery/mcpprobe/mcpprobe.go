// SPDX-License-Identifier: BUSL-1.1

// Package mcpprobe is P7's MCP network probe: it finds MCP servers on approved
// network ranges and records what authorization each requires. For each target it
// sends the MCP initialize request a client opens with and reads the answer:
//
//   - an initialize result (protocol version and server name) means an MCP server
//     that answers without any credential;
//   - a 401 naming OAuth protected resource metadata (RFC 9728), as the MCP
//     authorization specification requires, means an MCP server that requires
//     OAuth; the metadata's authorization servers and scopes are recorded;
//   - any other 401 or 403 means a server that requires some other authorization.
//
// The probe sends no credential and no cookie, never lists or calls a tool, ends any
// session the server opened, and records no credential value. It connects only to
// addresses inside the approved ranges, checked when each connection is dialed (so a
// name that resolves elsewhere, or a redirect, is refused), and TLS is verified with
// the transport the caller supplies: nothing is sent over a connection whose server
// identity did not verify.
package mcpprobe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/netsec"
)

// Auth is the authorization an MCP endpoint requires.
type Auth string

const (
	// AuthNone: the endpoint answered initialize without a credential.
	AuthNone Auth = "none"
	// AuthOAuth: the endpoint requires OAuth and names its protected resource metadata.
	AuthOAuth Auth = "oauth"
	// AuthOther: the endpoint refused the request without naming OAuth metadata.
	AuthOther Auth = "other"
)

// Observation is one MCP endpoint the probe found.
type Observation struct {
	Endpoint             string   `json:"endpoint"`
	Transport            string   `json:"transport"`
	Auth                 Auth     `json:"auth"`
	ResourceMetadataURL  string   `json:"resource_metadata_url,omitempty"`
	Resource             string   `json:"resource,omitempty"`
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
	ProtocolVersion      string   `json:"protocol_version,omitempty"`
	ServerName           string   `json:"server_name,omitempty"`
	ServerVersion        string   `json:"server_version,omitempty"`
}

// Fingerprint is a stable digest of what the probe observed: a rescan that finds
// the same thing has the same fingerprint, so its caller writes no new event.
func (o Observation) Fingerprint() string {
	c := o
	c.AuthorizationServers = sortedCopy(c.AuthorizationServers)
	c.ScopesSupported = sortedCopy(c.ScopesSupported)
	b, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return crypto.SHA256Hex(b)
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// ErrNotApproved refuses a connection to an address outside the approved ranges.
var ErrNotApproved = errors.New("mcpprobe: the address is outside the approved ranges")

// DefaultPaths are where an MCP server's Streamable HTTP endpoint usually lives.
var DefaultPaths = []string{"/mcp", "/"}

// protocolVersion is the MCP revision the probe's initialize request names.
const protocolVersion = "2025-06-18"

const (
	defaultTimeout = 5 * time.Second
	defaultMaxBody = 64 << 10
	maxListed      = 32
)

// Prober probes targets inside the approved ranges.
type Prober struct {
	// Approved are the ranges the probe may connect to; nothing else is dialed.
	Approved []netip.Prefix
	// Transport carries the TLS trust the probe verifies servers with (system roots
	// and any operator CA bundle). Its dialer is replaced by the approved-range
	// dialer. Nil uses an HTTP transport without TLS configuration.
	Transport *http.Transport
	// Paths are the endpoint paths tried on each target (DefaultPaths when empty).
	Paths []string
	// Timeout bounds each request; MaxBody bounds each response read.
	Timeout time.Duration
	MaxBody int64
	// Control is an extra dial check the caller enforces (a relay's declared
	// outbound destinations); it runs after the approved-range check.
	Control func(network, address string, c syscall.RawConn) error

	once   sync.Once
	client *http.Client
}

func (p *Prober) approved(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range p.Approved {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// dialControl refuses any connection whose remote address is outside the
// approved ranges; it runs on every dial, after name resolution.
func (p *Prober) dialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ErrNotApproved
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !p.approved(addr) {
		return fmt.Errorf("%w: %s", ErrNotApproved, host)
	}
	return nil
}

func (p *Prober) httpClient() *http.Client {
	p.once.Do(func() {
		timeout := p.Timeout
		if timeout <= 0 {
			timeout = defaultTimeout
		}
		// The SSRF guard admits the approved private ranges (never link-local or
		// metadata addresses); the probe's own check then refuses everything outside
		// the approved ranges, public addresses included.
		opts := netsec.SafeClientOptions{AllowPrivateCIDRs: p.Approved}
		var transport *http.Transport
		if p.Transport != nil {
			transport = p.Transport.Clone()
		} else {
			transport = netsec.SafeTransportWithOptions(opts)
		}
		guard := netsec.SafeDialControlWithOptions(opts)
		dialer := &net.Dialer{Timeout: timeout, Control: func(network, address string, c syscall.RawConn) error {
			if err := p.dialControl(network, address, c); err != nil {
				return err
			}
			if err := guard(network, address, c); err != nil {
				return err
			}
			if p.Control != nil {
				return p.Control(network, address, c)
			}
			return nil
		}}
		transport.DialContext = dialer.DialContext
		transport.Proxy = nil
		transport.DisableKeepAlives = true
		transport.ResponseHeaderTimeout = timeout
		// A redirect is never followed: the endpoint is where it answered.
		p.client = netsec.ClientFor(transport, timeout, func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse })
	})
	return p.client
}

// validateApproved refuses an approved range that does not mean what it says (a
// zero-bit prefix, or host bits set).
func (p *Prober) validateApproved() error {
	if len(p.Approved) == 0 {
		return fmt.Errorf("%w: no approved ranges", ErrNotApproved)
	}
	for _, prefix := range p.Approved {
		if err := netsec.ValidateEgressAllowPrefix(prefix); err != nil {
			return err
		}
	}
	return nil
}

func (p *Prober) maxBody() int64 {
	if p.MaxBody > 0 {
		return p.MaxBody
	}
	return defaultMaxBody
}

// Probe looks for an MCP endpoint at base (scheme://host:port). It reports whether
// one answered, and an error only when the target could not be probed at all.
func (p *Prober) Probe(ctx context.Context, base string) (Observation, bool, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return Observation{}, false, fmt.Errorf("mcpprobe: %q is not an http(s) origin", base)
	}
	if err := p.validateApproved(); err != nil {
		return Observation{}, false, err
	}
	if addr, err := netip.ParseAddr(u.Hostname()); err == nil && !p.approved(addr) {
		return Observation{}, false, fmt.Errorf("%w: %s", ErrNotApproved, u.Hostname())
	}
	paths := p.Paths
	if len(paths) == 0 {
		paths = DefaultPaths
	}
	var firstErr error
	for _, path := range paths {
		endpoint := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: path}).String()
		obs, found, err := p.probeEndpoint(ctx, endpoint)
		if found {
			return obs, true, nil
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return Observation{}, false, firstErr
}

const initializeRequest = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + protocolVersion +
	`","capabilities":{},"clientInfo":{"name":"trstctl-discovery","version":"1"}}}`

func (p *Prober) probeEndpoint(ctx context.Context, endpoint string) (Observation, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(initializeRequest))
	if err != nil {
		return Observation{}, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", protocolVersion)
	resp, err := p.httpClient().Do(req)
	if err != nil {
		return Observation{}, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	obs := Observation{Endpoint: endpoint, Transport: "streamable-http"}
	if session := resp.Header.Get("Mcp-Session-Id"); session != "" {
		defer p.endSession(ctx, endpoint, session)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		result, ok := readInitializeResult(resp, p.maxBody())
		if !ok {
			return Observation{}, false, nil
		}
		obs.Auth = AuthNone
		obs.ProtocolVersion, obs.ServerName, obs.ServerVersion = result.ProtocolVersion, result.ServerInfo.Name, result.ServerInfo.Version
		return obs, true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, p.maxBody()))
		metadataURL := resourceMetadataURL(resp.Header.Values("WWW-Authenticate"))
		if metadataURL == "" {
			if resp.StatusCode == http.StatusUnauthorized && strings.Contains(strings.ToLower(resp.Header.Get("WWW-Authenticate")), "bearer") {
				obs.Auth = AuthOther
				return obs, true, nil
			}
			return Observation{}, false, nil
		}
		obs.Auth, obs.ResourceMetadataURL = AuthOAuth, metadataURL
		if md, ok := p.fetchMetadata(ctx, metadataURL); ok {
			obs.Resource, obs.AuthorizationServers, obs.ScopesSupported = md.Resource, capped(md.AuthorizationServers), capped(md.ScopesSupported)
		}
		return obs, true, nil
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, p.maxBody()))
		return Observation{}, false, nil
	}
}

func capped(in []string) []string {
	if len(in) > maxListed {
		in = in[:maxListed]
	}
	return in
}

type initializeResult struct {
	ProtocolVersion string `json:"protocolVersion"`
	ServerInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
}

// readInitializeResult reads the JSON-RPC answer to the initialize request, as a
// JSON body or as the first matching message of an event stream.
func readInitializeResult(resp *http.Response, limit int64) (initializeResult, bool) {
	body := io.LimitReader(resp.Body, limit)
	parse := func(raw []byte) (initializeResult, bool) {
		var msg struct {
			JSONRPC string           `json:"jsonrpc"`
			ID      json.RawMessage  `json:"id"`
			Result  initializeResult `json:"result"`
		}
		if json.Unmarshal(raw, &msg) != nil || msg.JSONRPC != "2.0" || string(bytes.TrimSpace(msg.ID)) != "1" ||
			msg.Result.ProtocolVersion == "" || msg.Result.ServerInfo.Name == "" {
			return initializeResult{}, false
		}
		return msg.Result, true
	}
	if strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		scanner := bufio.NewScanner(body)
		scanner.Buffer(make([]byte, 0, 4096), int(limit))
		for scanner.Scan() {
			if data, ok := strings.CutPrefix(scanner.Text(), "data:"); ok {
				if result, ok := parse([]byte(strings.TrimSpace(data))); ok {
					return result, true
				}
			}
		}
		return initializeResult{}, false
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		return initializeResult{}, false
	}
	return parse(raw)
}

// resourceMetadataURL returns the resource_metadata parameter of a Bearer challenge.
func resourceMetadataURL(challenges []string) string {
	for _, challenge := range challenges {
		lower := strings.ToLower(challenge)
		i := strings.Index(lower, "resource_metadata=")
		if !strings.HasPrefix(strings.TrimSpace(lower), "bearer") || i < 0 {
			continue
		}
		value := challenge[i+len("resource_metadata="):]
		if strings.HasPrefix(value, `"`) {
			if end := strings.Index(value[1:], `"`); end >= 0 {
				value = value[1 : end+1]
			}
		} else if end := strings.IndexAny(value, ", "); end >= 0 {
			value = value[:end]
		}
		if u, err := url.Parse(value); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil {
			return u.String()
		}
	}
	return ""
}

type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// fetchMetadata reads the protected resource metadata, when it is served inside the
// approved ranges (the dialer refuses anything else).
func (p *Prober) fetchMetadata(ctx context.Context, metadataURL string) (protectedResourceMetadata, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return protectedResourceMetadata{}, false
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.httpClient().Do(req)
	if err != nil {
		return protectedResourceMetadata{}, false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return protectedResourceMetadata{}, false
	}
	var md protectedResourceMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, p.maxBody())).Decode(&md); err != nil {
		return protectedResourceMetadata{}, false
	}
	return md, true
}

// endSession ends a session the server opened for the probe's initialize request.
func (p *Prober) endSession(ctx context.Context, endpoint, session string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return
	}
	req.Header.Set("Mcp-Session-Id", session)
	req.Header.Set("MCP-Protocol-Version", protocolVersion)
	if resp, err := p.httpClient().Do(req); err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, p.maxBody()))
		_ = resp.Body.Close()
	}
}

// DefaultSchemes are the schemes ProbeTarget tries, in order.
var DefaultSchemes = []string{"https"}

// ProbeTarget probes one host:port, trying each scheme in order until an MCP
// endpoint answers.
func (p *Prober) ProbeTarget(ctx context.Context, hostport string, schemes []string) (Observation, bool, error) {
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		return Observation{}, false, fmt.Errorf("mcpprobe: target %q must be host:port", hostport)
	}
	if len(schemes) == 0 {
		schemes = DefaultSchemes
	}
	var firstErr error
	for _, scheme := range schemes {
		if scheme != "https" && scheme != "http" {
			return Observation{}, false, fmt.Errorf("mcpprobe: scheme %q is not http or https", scheme)
		}
		obs, found, err := p.Probe(ctx, scheme+"://"+hostport)
		if found {
			return obs, true, nil
		}
		if errors.Is(err, ErrNotApproved) {
			return Observation{}, false, err
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return Observation{}, false, firstErr
}

// Scan probes each host:port target with at most concurrency probes in flight
// (AN-7) and hands each MCP endpoint found to found, with its target. A target that
// cannot be probed does not stop the scan; outcome receives every target's result
// (found, nothing found, or the error). Scan returns the context's error when it is
// canceled.
func (p *Prober) Scan(ctx context.Context, targets, schemes []string, concurrency int, found func(target string, obs Observation), outcome func(target string, err error)) error {
	if concurrency <= 0 {
		concurrency = 4
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, target := range targets {
		select {
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			obs, ok, err := p.ProbeTarget(ctx, target, schemes)
			mu.Lock()
			defer mu.Unlock()
			if ok && found != nil {
				found(target, obs)
			}
			if outcome != nil {
				outcome(target, err)
			}
		}(target)
	}
	wg.Wait()
	return ctx.Err()
}
