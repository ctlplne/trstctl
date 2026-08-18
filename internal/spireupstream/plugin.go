// SPDX-License-Identifier: MPL-2.0

package spireupstream

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl"

	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	typesv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/netsec"
)

const defaultCommonName = "SPIRE Server CA"

// Config is the HCL plugin_data consumed by SPIRE Server.
type Config struct {
	Endpoint            string   `hcl:"endpoint"`
	CABundleFile        string   `hcl:"ca_bundle_file"`
	AllowPrivateCIDRs   []string `hcl:"allow_private_cidrs"`
	CAAuthorityID       string   `hcl:"ca_authority_id"`
	TokenFile           string   `hcl:"token_file"`
	CommonName          string   `hcl:"common_name"`
	TTLSeconds          int64    `hcl:"ttl_seconds"`
	MaxPathLen          int      `hcl:"max_path_len"`
	PermittedDNSDomains []string `hcl:"permitted_dns_domains"`
	ExtendedKeyUsages   []string `hcl:"extended_key_usages"`
	IdempotencyPrefix   string   `hcl:"idempotency_prefix"`
}

// Plugin implements SPIRE's UpstreamAuthority v1 interface by calling trstctl's
// served CA hierarchy endpoint. SPIRE owns the subordinate CA private key and sends
// only a CSR; trstctl signs that CSR through its normal API, idempotency, RBAC, audit,
// and isolated signer path.
type Plugin struct {
	upstreamauthorityv1.UnimplementedUpstreamAuthorityServer
	configv1.UnimplementedConfigServer

	mu     sync.RWMutex
	config *Config
	client *http.Client
}

// New constructs an unconfigured plugin.
func New() *Plugin {
	return &Plugin{}
}

// Configure receives SPIRE's plugin_data HCL and replaces the active config
// atomically.
func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	cfg := new(Config)
	if err := hcl.Decode(cfg, req.GetHclConfiguration()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode trstctl upstream-authority config: %v", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	client, err := upstreamHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.config = cfg
	p.client = client
	p.mu.Unlock()
	return &configv1.ConfigureResponse{}, nil
}

// MintX509CAAndSubscribe signs SPIRE's local CA CSR through trstctl and returns the
// signed SPIRE CA chain plus trstctl upstream roots in the SPIRE SDK shape.
func (p *Plugin) MintX509CAAndSubscribe(req *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	if len(req.GetCsr()) == 0 {
		return status.Error(codes.InvalidArgument, "CSR is required")
	}
	cfg, client, err := p.currentConfig()
	if err != nil {
		return err
	}
	ttl := cfg.TTLSeconds
	if req.GetPreferredTtl() > 0 {
		ttl = int64(req.GetPreferredTtl())
	}
	if ttl <= 0 {
		return status.Error(codes.InvalidArgument, "ttl_seconds must be configured or preferred_ttl must be positive")
	}
	certPEM, err := p.issueIntermediate(stream.Context(), cfg, client, req.GetCsr(), ttl)
	if err != nil {
		return err
	}
	certs, err := splitCertificatePEM(certPEM)
	if err != nil {
		return status.Errorf(codes.Internal, "parse trstctl certificate chain: %v", err)
	}
	if len(certs) < 2 {
		return status.Errorf(codes.Internal, "trstctl returned %d certificate(s); need signed SPIRE CA plus upstream root", len(certs))
	}
	chain := make([]*typesv1.X509Certificate, 0, len(certs)-1)
	for _, der := range certs[:len(certs)-1] {
		chain = append(chain, &typesv1.X509Certificate{Asn1: der})
	}
	roots := []*typesv1.X509Certificate{{Asn1: certs[len(certs)-1]}}
	return stream.Send(&upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       chain,
		UpstreamX509Roots: roots,
	})
}

// PublishJWTKeyAndSubscribe is optional in SPIRE's UpstreamAuthority contract. trstctl
// backs the X.509 CA chain for this plugin; JWT bundle publication is intentionally
// not claimed.
func (p *Plugin) PublishJWTKeyAndSubscribe(*upstreamauthorityv1.PublishJWTKeyRequest, upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	return status.Error(codes.Unimplemented, "trstctl upstream authority publishes X.509 roots only")
}

func (p *Plugin) issueIntermediate(ctx context.Context, cfg *Config, client *http.Client, csrDER []byte, ttl int64) ([]byte, error) {
	token, err := readTokenFile(cfg.TokenFile)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "read token file: %v", err)
	}
	defer zero(token)

	reqBody := struct {
		CSRPem string `json:"csr_pem"`
		Spec   struct {
			CommonName          string   `json:"common_name"`
			PermittedDNSDomains []string `json:"permitted_dns_domains,omitempty"`
			MaxPathLen          int      `json:"max_path_len"`
			ExtendedKeyUsages   []string `json:"extended_key_usages,omitempty"`
			TTLSeconds          int64    `json:"ttl_seconds"`
			SignatureAlgorithm  string   `json:"signature_algorithm,omitempty"`
		} `json:"spec"`
	}{}
	reqBody.CSRPem = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	reqBody.Spec.CommonName = cfg.CommonName
	reqBody.Spec.PermittedDNSDomains = append([]string(nil), cfg.PermittedDNSDomains...)
	reqBody.Spec.MaxPathLen = cfg.MaxPathLen
	reqBody.Spec.ExtendedKeyUsages = append([]string(nil), cfg.ExtendedKeyUsages...)
	reqBody.Spec.TTLSeconds = ttl
	reqBody.Spec.SignatureAlgorithm = "ecdsa-p256"
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode trstctl request: %v", err)
	}
	endpoint := cfg.Endpoint + "/api/v1/ca/authorities/" + url.PathEscape(cfg.CAAuthorityID) + "/intermediates/csr"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "build trstctl request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+string(token))
	httpReq.Header.Set("Idempotency-Key", idempotencyKey(cfg, csrDER))

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "call trstctl: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read trstctl response: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, status.Errorf(codes.Unavailable, "trstctl returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var issued struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.Unmarshal(body, &issued); err != nil {
		return nil, status.Errorf(codes.Internal, "decode trstctl response: %v", err)
	}
	if issued.CertificatePEM == "" {
		return nil, status.Error(codes.Internal, "trstctl response did not include certificate_pem")
	}
	return []byte(issued.CertificatePEM), nil
}

func (p *Plugin) currentConfig() (*Config, *http.Client, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, nil, status.Error(codes.FailedPrecondition, "plugin is not configured")
	}
	cp := *p.config
	cp.PermittedDNSDomains = append([]string(nil), p.config.PermittedDNSDomains...)
	cp.ExtendedKeyUsages = append([]string(nil), p.config.ExtendedKeyUsages...)
	cp.AllowPrivateCIDRs = append([]string(nil), p.config.AllowPrivateCIDRs...)
	client := p.client
	if client == nil {
		return nil, nil, status.Error(codes.FailedPrecondition, "plugin HTTP client is not configured")
	}
	return &cp, client, nil
}

func upstreamHTTPClient(cfg *Config) (*http.Client, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parse endpoint: %v", err)
	}

	opts := netsec.SafeClientOptions{}
	for _, raw := range cfg.AllowPrivateCIDRs {
		prefix, err := netsec.ParseEgressAllowPrefix(raw)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "allow_private_cidrs entry %q: %v", raw, err)
		}
		opts.AllowPrivateCIDRs = append(opts.AllowPrivateCIDRs, prefix)
	}

	const timeout = 30 * time.Second
	var client *http.Client
	if netsec.IsLoopbackHost(u.Hostname()) {
		client = netsec.InsecureLoopbackClient(timeout)
	} else {
		if err := netsec.ValidatePublicHTTPSURLWithOptions(cfg.Endpoint, opts); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "validate endpoint egress: %v", err)
		}
		client = netsec.SafeClientWithOptions(timeout, opts)
	}

	if cfg.CABundleFile != "" {
		caPEM, err := os.ReadFile(cfg.CABundleFile) // #nosec G304 -- operator-configured public CA bundle path (CWE-22)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "read ca_bundle_file: %v", err)
		}
		trusted, transportErr := mtls.HTTPTransport(caPEM)
		zero(caPEM)
		if transportErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "ca_bundle_file: %v", transportErr)
		}
		safe, ok := client.Transport.(*http.Transport)
		if !ok {
			return nil, status.Error(codes.Internal, "upstream transport does not expose the reviewed HTTP transport seam")
		}
		trusted.DialContext = safe.DialContext
		trusted.DialTLSContext = nil
		trusted.TLSHandshakeTimeout = safe.TLSHandshakeTimeout
		trusted.ResponseHeaderTimeout = safe.ResponseHeaderTimeout
		trusted.DisableKeepAlives = true
		client.Transport = trusted
	}

	client.Transport, err = netsec.BindTransportToOrigin(cfg.Endpoint, client.Transport)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "bind endpoint origin: %v", err)
	}
	return client, nil
}

func (c *Config) validate() error {
	c.Endpoint = strings.TrimRight(strings.TrimSpace(c.Endpoint), "/")
	if c.Endpoint == "" {
		return status.Error(codes.InvalidArgument, "endpoint is required")
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return status.Errorf(codes.InvalidArgument, "endpoint must be an absolute http(s) URL")
	}
	switch u.Scheme {
	case "https":
	case "http":
		// This endpoint is the trust domain's UPSTREAM AUTHORITY: whatever answers
		// it decides what the whole SPIFFE trust domain considers a valid root. Over
		// plaintext, anyone on the path becomes that authority. Loopback is allowed
		// because there is no network to be on-path of.
		if !netsec.IsLoopbackHost(u.Hostname()) {
			return status.Errorf(codes.InvalidArgument,
				"endpoint %q uses plaintext http to a non-loopback host; the upstream authority decides the trust domain's roots, so an on-path attacker could become it — use https", u.Host)
		}
	default:
		return status.Errorf(codes.InvalidArgument, "endpoint scheme %q is not supported", u.Scheme)
	}
	c.CABundleFile = strings.TrimSpace(c.CABundleFile)
	if c.CABundleFile != "" && u.Scheme != "https" {
		return status.Error(codes.InvalidArgument, "ca_bundle_file requires an https endpoint")
	}
	for i := range c.AllowPrivateCIDRs {
		c.AllowPrivateCIDRs[i] = strings.TrimSpace(c.AllowPrivateCIDRs[i])
	}
	c.CAAuthorityID = strings.TrimSpace(c.CAAuthorityID)
	if c.CAAuthorityID == "" {
		return status.Error(codes.InvalidArgument, "ca_authority_id is required")
	}
	c.TokenFile = strings.TrimSpace(c.TokenFile)
	if c.TokenFile == "" {
		return status.Error(codes.InvalidArgument, "token_file is required")
	}
	if c.CommonName == "" {
		c.CommonName = defaultCommonName
	}
	if c.TTLSeconds < 0 {
		return status.Error(codes.InvalidArgument, "ttl_seconds cannot be negative")
	}
	if c.IdempotencyPrefix == "" {
		c.IdempotencyPrefix = "spire-upstream"
	}
	return nil
}

func readTokenFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured upstream-authority plugin config path (CWE-22)
	if err != nil {
		return nil, err
	}
	token := bytes.TrimSpace(raw)
	out := append([]byte(nil), token...)
	zero(raw)
	return out, nil
}

func splitCertificatePEM(chainPEM []byte) ([][]byte, error) {
	var certs [][]byte
	for len(chainPEM) > 0 {
		var block *pem.Block
		block, chainPEM = pem.Decode(chainPEM)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certs = append(certs, append([]byte(nil), block.Bytes...))
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE PEM blocks found")
	}
	return certs, nil
}

func idempotencyKey(cfg *Config, csrDER []byte) string {
	h := fnv.New64a()
	_, _ = h.Write(csrDER)
	ca := strings.NewReplacer("/", "-", ":", "-", " ", "-").Replace(cfg.CAAuthorityID)
	return fmt.Sprintf("%s-%s-%016x", cfg.IdempotencyPrefix, ca, h.Sum64())
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
