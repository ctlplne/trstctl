// SPDX-License-Identifier: BUSL-1.1

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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	service          = "acm"
	amzTarget        = "CertificateManager.ImportCertificate"
	amzPreviewTarget = "CertificateManager.ListCertificates"
	jsonType         = "application/x-amz-json-1.1"
)

// Credentials are the AWS access credentials used to sign requests. SessionToken
// is set for temporary (STS/role) credentials.
//
// SecretAccessKey and SessionToken are authority-bearing AWS credential material;
// they are held as []byte, never string, so they can be wiped and are not freely
// copied by the GC (AN-8). AccessKeyID is a public handle.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey []byte
	SessionToken    []byte
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
	creds.SecretAccessKey = secrettext.Clone(creds.SecretAccessKey)
	creds.SessionToken = secrettext.Clone(creds.SessionToken)
	c := &Connector{region: region, creds: creds, now: time.Now}
	c.setEndpoint(fmt.Sprintf("https://acm.%s.amazonaws.com", region))
	for _, o := range opts {
		o(c)
	}
	return c
}

// Close destroys the request-signing credential copies owned by this one-shot
// target connector. Production factories defer it after every delivery.
func (c *Connector) Close() {
	secret.Wipe(c.creds.SecretAccessKey)
	secret.Wipe(c.creds.SessionToken)
	c.creds.SecretAccessKey = nil
	c.creds.SessionToken = nil
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
		Certificate:      secretjson.Base64Bytes(leaf),
		PrivateKey:       secretjson.Base64Bytes(dep.KeyPEM),
		CertificateChain: b64(chain),
		CertificateArn:   dep.Target,
	})
	if err != nil {
		return fmt.Errorf("acm: encode request: %w", err)
	}
	// reqBody carries the base64 private key on the wire — the transient edge copy
	// (the long-lived key stays []byte in dep.KeyPEM). Wipe it after the request so
	// the key does not linger in this buffer (AN-8).
	defer secret.Wipe(reqBody)

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
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return fmt.Errorf("acm: import certificate: status %d (response body redacted)", resp.StatusCode)
	}
	_ = secret.DrainBounded(resp.Body, 1<<20)
	return nil
}

// Preview authenticates to ACM with the same SigV4 credential and endpoint a
// deploy uses, but calls the read-only ListCertificates operation. POST is the
// AWS JSON transport verb here; X-Amz-Target is the effect boundary, and this
// method can never reach ImportCertificate.
func (c *Connector) Preview(ctx context.Context, sb connector.Sandbox, target string) (connector.Preview, error) {
	body := []byte("{}")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return connector.Preview{}, err
	}
	req.Header.Set("Content-Type", jsonType)
	req.Header.Set("X-Amz-Target", amzPreviewTarget)
	c.signV4(req, body, c.now().UTC())
	resp, err := sb.Request(req)
	if err != nil {
		return connector.Preview{}, fmt.Errorf("acm: preview certificate access: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return connector.Preview{}, fmt.Errorf("acm: preview certificate access: status %d (response body redacted)", resp.StatusCode)
	}
	_ = secret.DrainBounded(resp.Body, 1<<20)
	effect := "import a new externally issued certificate into AWS Certificate Manager"
	if strings.TrimSpace(target) != "" {
		effect = "re-import the renewed certificate into ACM resource " + target
	}
	return connector.Preview{Endpoint: c.endpoint, WouldMutate: []string{effect}, Detail: "AWS accepted an authenticated read-only ListCertificates request; no certificate was imported"}, nil
}

// importRequest is the ACM ImportCertificate body. Certificate, PrivateKey, and
// CertificateChain are blobs — base64-encoded in AWS JSON 1.1.
type importRequest struct {
	Certificate      secretjson.Base64Bytes `json:"Certificate"`
	PrivateKey       secretjson.Base64Bytes `json:"PrivateKey"`
	CertificateChain secretjson.Base64Bytes `json:"CertificateChain,omitempty"`
	CertificateArn   string                 `json:"CertificateArn,omitempty"`
}

// signV4 adds AWS Signature Version 4 headers to req over body. Digests and the
// keyed MAC route through the crypto boundary (AN-3).
func (c *Connector) signV4(req *http.Request, body []byte, t time.Time) {
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if len(c.creds.SessionToken) > 0 {
		req.Header.Set("X-Amz-Security-Token", secrettext.String(c.creds.SessionToken))
	}

	signed := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if len(c.creds.SessionToken) > 0 {
		signed = append(signed, "x-amz-security-token")
	}
	sort.Strings(signed)

	canonHeaders := make([]byte, 0, 256+len(c.creds.SessionToken))
	for _, h := range signed {
		canonHeaders = append(canonHeaders, h...)
		canonHeaders = append(canonHeaders, ':')
		switch h {
		case "host":
			canonHeaders = append(canonHeaders, c.host...)
		case "x-amz-security-token":
			// The session token already has one unavoidable string copy in the
			// HTTP header. Build the signed canonical copy directly from the
			// owned bytes so it never enters strings.Builder/String again.
			canonHeaders = append(canonHeaders, bytes.TrimSpace(c.creds.SessionToken)...)
		default:
			canonHeaders = append(canonHeaders, strings.TrimSpace(req.Header.Get(h))...)
		}
		canonHeaders = append(canonHeaders, '\n')
	}
	signedHeaders := strings.Join(signed, ";")

	canonicalRequest := make([]byte, 0, len(canonHeaders)+len(req.Method)+len(req.URL.EscapedPath())+len(signedHeaders)+96)
	canonicalRequest = append(canonicalRequest, req.Method...)
	canonicalRequest = append(canonicalRequest, '\n')
	canonicalRequest = append(canonicalRequest, req.URL.EscapedPath()...)
	canonicalRequest = append(canonicalRequest, '\n', '\n') // empty query string
	canonicalRequest = append(canonicalRequest, canonHeaders...)
	canonicalRequest = append(canonicalRequest, '\n')
	canonicalRequest = append(canonicalRequest, signedHeaders...)
	canonicalRequest = append(canonicalRequest, '\n')
	canonicalRequest = append(canonicalRequest, crypto.SHA256Hex(body)...)
	canonicalHash := crypto.SHA256Hex(canonicalRequest)
	secret.Wipe(canonicalRequest)
	secret.Wipe(canonHeaders)

	credScope := dateStamp + "/" + c.region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		canonicalHash,
	}, "\n")

	// The SigV4 derived key starts from "AWS4"||secret. Assemble it in a []byte so
	// the secret access key never lives in a GC-managed string (AN-8); wipe the
	// transient seed after the first HMAC.
	seed := make([]byte, 0, 4+len(c.creds.SecretAccessKey))
	seed = append(seed, "AWS4"...)
	seed = append(seed, c.creds.SecretAccessKey...)
	kDate := crypto.HMACSHA256(seed, []byte(dateStamp))
	secret.Wipe(seed)
	kRegion := crypto.HMACSHA256(kDate, []byte(c.region))
	secret.Wipe(kDate)
	kService := crypto.HMACSHA256(kRegion, []byte(service))
	secret.Wipe(kRegion)
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	secret.Wipe(kService)
	defer secret.Wipe(kSigning)
	signatureMAC := crypto.HMACSHA256(kSigning, []byte(stringToSign))
	signature := hex.EncodeToString(signatureMAC)
	secret.Wipe(signatureMAC)

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

func b64(b []byte) secretjson.Base64Bytes {
	return secretjson.Base64Bytes(b)
}
