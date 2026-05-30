// Package acm is the AWS Certificate Manager deployment connector (S5.11), the
// first cloud certificate store, built from the connector SDK (S5.5). A renewed
// credential is deployed by re-importing it into an ACM certificate
// (ImportCertificate with the existing CertificateArn), which is the in-place
// renewal path for an externally-issued certificate.
//
// Unlike the AWS Private CA *issuance* plugin (internal/ca/awspca), which models
// the operation behind a pure-Go seam and leaves SigV4 to the AWS SDK, a
// deployment connector must route every privileged operation through the
// capability-gated Sandbox (so it is conformance-tested and outbox-delivered
// like every other connector). It therefore speaks the ACM wire protocol
// directly — AWS JSON 1.1 over an HTTPS POST through sb.Request — and signs the
// request with Signature Version 4. The keyed MAC and digests route through the
// crypto boundary (internal/crypto; AN-3); the package imports no crypto/*.
// Credentials may be sourced from the platform's secret store; for a managed
// deployment the AWS SDK's own SigV4 signer can be injected behind the same
// Credentials seam.
//
// Key material is carried as []byte and PEM is treated as opaque (AN-8); the
// leaf/chain split is structural (encoding/pem), not a certificate parse.
package acm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"certctl.io/certctl/internal/connector"
	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/pluginhost"
)

const (
	service   = "acm"
	amzTarget = "CertificateManager.ImportCertificate"
	jsonType  = "application/x-amz-json-1.1"
)

// Credentials are the AWS access credentials used to sign requests. SessionToken
// is set for temporary (STS/role) credentials.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// Connector imports renewed certificates into AWS Certificate Manager.
type Connector struct {
	region   string
	endpoint string // base URL, no trailing slash
	host     string // host[:port] of endpoint, for the net.dial grant and signing
	creds    Credentials
	now      func() time.Time
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector.
type Option func(*Connector)

// WithEndpoint overrides the regional ACM endpoint (for tests, VPC endpoints, or
// GovCloud/China partitions).
func WithEndpoint(endpoint string) Option {
	return func(c *Connector) { c.setEndpoint(endpoint) }
}

// New returns an ACM connector for region, signing with creds. The endpoint
// defaults to the regional ACM service host.
func New(region string, creds Credentials, opts ...Option) *Connector {
	c := &Connector{region: region, creds: creds, now: time.Now}
	c.setEndpoint(fmt.Sprintf("https://acm.%s.amazonaws.com", region))
	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *Connector) setEndpoint(endpoint string) {
	c.endpoint = strings.TrimRight(endpoint, "/")
	if u, err := url.Parse(endpoint); err == nil {
		c.host = u.Host
	}
}

// Name identifies the connector.
func (c *Connector) Name() string { return "aws-acm" }

// Capabilities declares the least privilege the connector needs: reach the ACM
// endpoint over the network. No filesystem, no exec.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, c.host)
}

// Deploy imports the renewed certificate and key into the ACM certificate named
// by dep.Target (its ARN); an empty target imports a new certificate.
func (c *Connector) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	leaf, chain := splitLeafChain(dep.CertPEM)

	reqBody, err := json.Marshal(importRequest{
		Certificate:      base64.StdEncoding.EncodeToString(leaf),
		PrivateKey:       base64.StdEncoding.EncodeToString(dep.KeyPEM),
		CertificateChain: b64(chain),
		CertificateArn:   dep.Target,
	})
	if err != nil {
		return fmt.Errorf("acm: encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/", bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", jsonType)
	req.Header.Set("X-Amz-Target", amzTarget)
	c.signV4(req, reqBody, c.now().UTC())

	resp, err := sb.Request(req)
	if err != nil {
		return fmt.Errorf("acm: import certificate: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("acm: import certificate: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return nil
}

// importRequest is the ACM ImportCertificate body. Certificate, PrivateKey, and
// CertificateChain are blobs — base64-encoded in AWS JSON 1.1.
type importRequest struct {
	Certificate      string `json:"Certificate"`
	PrivateKey       string `json:"PrivateKey"`
	CertificateChain string `json:"CertificateChain,omitempty"`
	CertificateArn   string `json:"CertificateArn,omitempty"`
}

// signV4 adds AWS Signature Version 4 headers to req over body. Digests and the
// keyed MAC route through the crypto boundary (AN-3).
func (c *Connector) signV4(req *http.Request, body []byte, t time.Time) {
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if c.creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.creds.SessionToken)
	}

	signed := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if c.creds.SessionToken != "" {
		signed = append(signed, "x-amz-security-token")
	}
	sort.Strings(signed)

	var canonHeaders strings.Builder
	for _, h := range signed {
		v := strings.TrimSpace(req.Header.Get(h))
		if h == "host" {
			v = c.host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	signedHeaders := strings.Join(signed, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		"", // no query
		canonHeaders.String(),
		signedHeaders,
		crypto.SHA256Hex(body),
	}, "\n")

	credScope := dateStamp + "/" + c.region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		crypto.SHA256Hex([]byte(canonicalRequest)),
	}, "\n")

	kDate := crypto.HMACSHA256([]byte("AWS4"+c.creds.SecretAccessKey), []byte(dateStamp))
	kRegion := crypto.HMACSHA256(kDate, []byte(c.region))
	kService := crypto.HMACSHA256(kRegion, []byte(service))
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(crypto.HMACSHA256(kSigning, []byte(stringToSign)))

	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 "+
		"Credential="+c.creds.AccessKeyID+"/"+credScope+", "+
		"SignedHeaders="+signedHeaders+", "+
		"Signature="+signature)
}

// splitLeafChain separates the first PEM certificate block (the leaf) from the
// remaining blocks (the chain), which ACM requires as separate fields. The split
// is purely structural — no certificate parse, no crypto/*.
func splitLeafChain(certPEM []byte) (leaf, chain []byte) {
	rest := certPEM
	var blocks []*pem.Block
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		blocks = append(blocks, b)
	}
	if len(blocks) == 0 {
		return certPEM, nil // not PEM; treat the whole input as the leaf
	}
	leaf = pem.EncodeToMemory(blocks[0])
	for _, b := range blocks[1:] {
		chain = append(chain, pem.EncodeToMemory(b)...)
	}
	return leaf, chain
}

func b64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}
