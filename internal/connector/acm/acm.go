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
//
// Listener mode (A166-L2): ACM re-imports in place under one ARN and keeps no
// previous version, so an in-place target cannot roll back. A target that
// names the Elastic Load Balancing listener serving it (listener_arn) instead
// imports each deploy as a NEW ACM certificate tagged with its fingerprint and
// points the listener's default certificate at it. The predecessor stays in
// the account, so a rollback re-points the listener at it again (found by its
// tag, then confirmed by reading the certificate back), uploading nothing, and
// a readback reports the certificate the listener serves. The listener calls
// use the ELB v2 Query API, signed the same way for the elasticloadbalancing
// service.
package acm

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
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
	elbService       = "elasticloadbalancing"
	elbVersion       = "2015-12-01"
	formType         = "application/x-www-form-urlencoded; charset=utf-8"
	// FingerprintTag is the ACM tag a listener-mode import carries: the
	// certificate's fingerprint, which a rollback looks the predecessor up by.
	FingerprintTag = "trstctl-fingerprint"
	// maxRollbackCertificates bounds how many certificates a rollback reads
	// while looking for the predecessor.
	maxRollbackCertificates = 1000
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
	// listener is the ELB listener a listener-mode target serves through
	// (A166-L2); empty is the in-place target.
	listener    string
	elbEndpoint string
	elbHost     string
}

var (
	_ connector.Connector  = (*Connector)(nil)
	_ connector.Rollbacker = (*Connector)(nil)
	_ connector.Readbacker = (*Connector)(nil)
)

// Option configures a Connector.
type Option func(*Connector)

// WithEndpoint overrides the regional ACM endpoint (for tests, VPC endpoints, or
// GovCloud/China partitions).
func WithEndpoint(endpoint string) Option {
	return func(c *Connector) { c.setEndpoint(endpoint) }
}

// WithListener makes the target a listener-mode target (A166-L2): each deploy
// imports a new certificate and points the ELB listener listenerARN at it.
func WithListener(listenerARN string) Option {
	return func(c *Connector) { c.listener = strings.TrimSpace(listenerARN) }
}

// ValidateListenerARN checks that arn names an Elastic Load Balancing (v2)
// listener, the only thing a listener-mode target may re-point.
func ValidateListenerARN(arn string) error {
	parts := strings.SplitN(strings.TrimSpace(arn), ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || !strings.HasPrefix(parts[1], "aws") || parts[2] != "elasticloadbalancing" ||
		parts[3] == "" || parts[4] == "" || !strings.HasPrefix(parts[5], "listener/") || strings.ContainsAny(arn, " \t\r\n") {
		return fmt.Errorf("connector: aws-acm listener_arn must be an Elastic Load Balancing listener ARN (arn:aws:elasticloadbalancing:<region>:<account>:listener/...)")
	}
	return nil
}

// WithELBEndpoint overrides the regional Elastic Load Balancing endpoint.
func WithELBEndpoint(endpoint string) Option {
	return func(c *Connector) {
		if strings.TrimSpace(endpoint) != "" {
			c.setELBEndpoint(endpoint)
		}
	}
}

// New returns an ACM connector for region, signing with creds. The endpoint
// defaults to the regional ACM service host.
func New(region string, creds Credentials, opts ...Option) *Connector {
	creds.SecretAccessKey = secrettext.Clone(creds.SecretAccessKey)
	creds.SessionToken = secrettext.Clone(creds.SessionToken)
	c := &Connector{region: region, creds: creds, now: time.Now}
	c.setEndpoint(fmt.Sprintf("https://acm.%s.amazonaws.com", region))
	c.setELBEndpoint(fmt.Sprintf("https://elasticloadbalancing.%s.amazonaws.com", region))
	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *Connector) setELBEndpoint(endpoint string) {
	c.elbEndpoint = strings.TrimRight(endpoint, "/")
	if u, err := url.Parse(endpoint); err == nil {
		c.elbHost = u.Host
	}
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
// endpoint over the network, and the ELB endpoint for a listener-mode target.
// No filesystem, no exec.
func (c *Connector) Capabilities() pluginhost.Grant {
	grant := pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, c.host)
	if c.listener != "" {
		grant = grant.WithPathPrefix(pluginhost.CapNetDial, c.elbHost)
	}
	return grant
}

// Deploy imports the renewed certificate and key into the ACM certificate named
// by dep.Target (its ARN); an empty target imports a new certificate.
func (c *Connector) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	if c.listener != "" {
		return c.deployToListener(ctx, sb, dep)
	}
	_, err := c.importCertificate(ctx, sb, dep, dep.Target, nil)
	return err
}

// importCertificate imports dep under arn (a re-import), or as a new
// certificate carrying tags when arn is empty, and returns the ARN ACM
// answered.
func (c *Connector) importCertificate(ctx context.Context, sb connector.Sandbox, dep connector.Deployment, arn string, tags []tag) (string, error) {
	leaf, chain := splitLeafChain(dep.CertPEM)

	reqBody, err := json.Marshal(importRequest{
		Certificate:      secretjson.Base64Bytes(leaf),
		PrivateKey:       secretjson.Base64Bytes(dep.KeyPEM),
		CertificateChain: b64(chain),
		CertificateArn:   arn,
		Tags:             tags,
	})
	if err != nil {
		return "", fmt.Errorf("acm: encode request: %w", err)
	}
	// reqBody carries the base64 private key on the wire — the transient edge copy
	// (the long-lived key stays []byte in dep.KeyPEM). Wipe it after the request so
	// the key does not linger in this buffer (AN-8).
	defer secret.Wipe(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", jsonType)
	req.Header.Set("X-Amz-Target", amzTarget)
	c.signV4(req, reqBody, c.now().UTC())

	resp, err := sb.Request(req)
	if err != nil {
		return "", fmt.Errorf("acm: import certificate: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return "", fmt.Errorf("acm: import certificate: status %d (response body redacted)", resp.StatusCode)
	}
	var out struct {
		CertificateArn string `json:"CertificateArn"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil && arn == "" {
		return "", fmt.Errorf("acm: decode import answer: %w", err)
	}
	_ = secret.DrainBounded(resp.Body, 1<<20)
	if arn == "" && strings.TrimSpace(out.CertificateArn) == "" {
		return "", errors.New("acm: the import answered no certificate ARN")
	}
	return out.CertificateArn, nil
}

// deployToListener imports dep as a new certificate tagged with its
// fingerprint and points the listener's default certificate at it (A166-L2).
// The predecessor stays in the account for a rollback.
func (c *Connector) deployToListener(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	fingerprint := strings.TrimSpace(dep.Fingerprint)
	if fingerprint == "" {
		fingerprint = connector.CertificateFingerprint(dep.CertPEM)
	}
	arn, err := c.importCertificate(ctx, sb, dep, "", []tag{{Key: FingerprintTag, Value: fingerprint}})
	if err != nil {
		return err
	}
	if err := c.pointListener(ctx, sb, arn); err != nil {
		return fmt.Errorf("acm: point listener at the new certificate %s: %w", arn, err)
	}
	return nil
}

// Rollback points a listener-mode target's listener back at the
// predecessor's certificate, which a listener-mode deploy left in the account
// (A166-L2). The predecessor is looked up by its fingerprint tag and confirmed
// by reading the certificate back, since anyone with tag rights could move a
// tag. Nothing is uploaded. An in-place target re-imports under one ARN and
// keeps no predecessor: ErrRollbackNotConfigured.
func (c *Connector) Rollback(ctx context.Context, sb connector.Sandbox, rb connector.Rollback) error {
	if c.listener == "" {
		return connector.ErrRollbackNotConfigured
	}
	want := strings.ToLower(strings.TrimSpace(rb.PredecessorFingerprint))
	if want == "" {
		return connector.ErrNoPredecessorInstalled
	}
	var next string
	for read := 0; read < maxRollbackCertificates; {
		var page struct {
			CertificateSummaryList []struct {
				CertificateArn string `json:"CertificateArn"`
			} `json:"CertificateSummaryList"`
			NextToken string `json:"NextToken"`
		}
		in := map[string]any{"MaxItems": 100}
		if next != "" {
			in["NextToken"] = next
		}
		if err := c.callACM(ctx, sb, amzPreviewTarget, in, &page); err != nil {
			return err
		}
		for _, summary := range page.CertificateSummaryList {
			read++
			var tags struct {
				Tags []tag `json:"Tags"`
			}
			if err := c.callACM(ctx, sb, "CertificateManager.ListTagsForCertificate", map[string]string{"CertificateArn": summary.CertificateArn}, &tags); err != nil {
				return err
			}
			tagged := false
			for _, t := range tags.Tags {
				tagged = tagged || t.Key == FingerprintTag && strings.EqualFold(t.Value, want)
			}
			if !tagged {
				continue
			}
			fingerprint, err := c.certificateFingerprint(ctx, sb, summary.CertificateArn)
			if err != nil {
				return err
			}
			if fingerprint != want {
				continue
			}
			if err := c.pointListener(ctx, sb, summary.CertificateArn); err != nil {
				return fmt.Errorf("acm: point listener back at the predecessor %s: %w", summary.CertificateArn, err)
			}
			return nil
		}
		if next = page.NextToken; next == "" {
			break
		}
	}
	return connector.ErrNoPredecessorInstalled
}

// Readback reports the certificate a listener-mode target's listener serves
// by default, read from ACM. An in-place target has no listener to ask:
// ErrReadbackNotConfigured.
func (c *Connector) Readback(ctx context.Context, sb connector.Sandbox, _ string) (connector.Installed, error) {
	if c.listener == "" {
		return connector.Installed{}, connector.ErrReadbackNotConfigured
	}
	var described struct {
		Listeners []struct {
			ListenerArn  string `xml:"ListenerArn"`
			Certificates []struct {
				CertificateArn string `xml:"CertificateArn"`
			} `xml:"Certificates>member"`
		} `xml:"DescribeListenersResult>Listeners>member"`
	}
	if err := c.callELB(ctx, sb, url.Values{"Action": {"DescribeListeners"}, "ListenerArns.member.1": {c.listener}}, &described); err != nil {
		return connector.Installed{}, err
	}
	if len(described.Listeners) != 1 || described.Listeners[0].ListenerArn != c.listener {
		return connector.Installed{}, errors.New("acm: the load balancer did not describe the configured listener")
	}
	if len(described.Listeners[0].Certificates) == 0 || described.Listeners[0].Certificates[0].CertificateArn == "" {
		return connector.Installed{ObjectName: c.listener}, nil
	}
	arn := described.Listeners[0].Certificates[0].CertificateArn
	fingerprint, err := c.certificateFingerprint(ctx, sb, arn)
	if err != nil {
		return connector.Installed{}, err
	}
	return connector.Installed{Fingerprint: fingerprint, ObjectName: arn, Bound: true}, nil
}

// certificateFingerprint reads an ACM certificate back and fingerprints it.
func (c *Connector) certificateFingerprint(ctx context.Context, sb connector.Sandbox, arn string) (string, error) {
	var got struct {
		Certificate string `json:"Certificate"`
	}
	if err := c.callACM(ctx, sb, "CertificateManager.GetCertificate", map[string]string{"CertificateArn": arn}, &got); err != nil {
		return "", err
	}
	if strings.TrimSpace(got.Certificate) == "" {
		return "", fmt.Errorf("acm: certificate %s has no certificate body", arn)
	}
	return connector.CertificateFingerprint([]byte(got.Certificate)), nil
}

// pointListener makes arn the listener's default certificate.
func (c *Connector) pointListener(ctx context.Context, sb connector.Sandbox, arn string) error {
	var modified struct {
		Listeners []struct {
			ListenerArn string `xml:"ListenerArn"`
		} `xml:"ModifyListenerResult>Listeners>member"`
	}
	if err := c.callELB(ctx, sb, url.Values{"Action": {"ModifyListener"}, "ListenerArn": {c.listener},
		"Certificates.member.1.CertificateArn": {arn}}, &modified); err != nil {
		return err
	}
	if len(modified.Listeners) != 1 || modified.Listeners[0].ListenerArn != c.listener {
		return errors.New("acm: the load balancer did not confirm the listener change")
	}
	return nil
}

// callACM makes one read-only ACM JSON 1.1 call (no key material) and decodes
// its bounded answer.
func (c *Connector) callACM(ctx context.Context, sb connector.Sandbox, target string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", jsonType)
	req.Header.Set("X-Amz-Target", target)
	c.signV4(req, body, c.now().UTC())
	resp, err := sb.Request(req)
	if err != nil {
		return fmt.Errorf("acm: %s: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return fmt.Errorf("acm: %s: status %d (response body redacted)", target, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out); err != nil {
		return fmt.Errorf("acm: decode %s: %w", target, err)
	}
	return nil
}

// callELB makes one Elastic Load Balancing v2 Query API call and decodes its
// bounded XML answer.
func (c *Connector) callELB(ctx context.Context, sb connector.Sandbox, form url.Values, out any) error {
	form.Set("Version", elbVersion)
	body := []byte(form.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.elbEndpoint+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", formType)
	c.signV4For(req, body, c.now().UTC(), elbService, c.elbHost, false)
	resp, err := sb.Request(req)
	if err != nil {
		return fmt.Errorf("acm: elastic load balancing %s: %w", form.Get("Action"), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return fmt.Errorf("acm: elastic load balancing %s: status %d (response body redacted)", form.Get("Action"), resp.StatusCode)
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return fmt.Errorf("acm: decode elastic load balancing %s: %w", form.Get("Action"), err)
	}
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
	Tags             []tag                  `json:"Tags,omitempty"`
}

// tag is one ACM tag.
type tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

// signV4 signs an ACM JSON 1.1 request.
func (c *Connector) signV4(req *http.Request, body []byte, t time.Time) {
	c.signV4For(req, body, t, service, c.host, true)
}

// signV4For adds AWS Signature Version 4 headers to req over body, for the
// named service at host; a JSON 1.1 request also signs its X-Amz-Target.
// Digests and the keyed MAC route through the crypto boundary (AN-3).
func (c *Connector) signV4For(req *http.Request, body []byte, t time.Time, svc, host string, signsTarget bool) {
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if len(c.creds.SessionToken) > 0 {
		req.Header.Set("X-Amz-Security-Token", secrettext.String(c.creds.SessionToken))
	}

	signed := []string{"content-type", "host", "x-amz-date"}
	if signsTarget {
		signed = append(signed, "x-amz-target")
	}
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
			canonHeaders = append(canonHeaders, host...)
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

	credScope := dateStamp + "/" + c.region + "/" + svc + "/aws4_request"
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
	kService := crypto.HMACSHA256(kRegion, []byte(svc))
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
