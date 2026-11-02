// SPDX-License-Identifier: BUSL-1.1

package authmethod

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/netsec"
)

// AWSIdentity is the non-secret identity returned by STS GetCallerIdentity.
type AWSIdentity struct {
	Account string
	ARN     string
	UserID  string
}

// STSCallerIdentityClient verifies an AWS-signed credential by asking STS who
// signed it. Production uses HTTPSignedSTSClient; tests can inject an emulator.
type STSCallerIdentityClient interface {
	GetCallerIdentity(ctx context.Context, credential []byte) (AWSIdentity, error)
}

// AWSIAMMethod authenticates a workload through AWS IAM by verifying a signed
// sts:GetCallerIdentity request. The credential is the signed request, not the
// AWS secret access key, so trstctl never needs to parse or store that key.
type AWSIAMMethod struct {
	TenantID        string
	Client          STSCallerIdentityClient
	AllowedAccounts map[string]bool
	AllowedARNs     map[string]bool
	Scopes          []string
}

// Name implements Method.
func (AWSIAMMethod) Name() string { return "aws-iam" }

// Authenticate implements Method.
func (a AWSIAMMethod) Authenticate(ctx context.Context, credential []byte) (string, []string, error) {
	if a.Client == nil {
		return "", nil, fmt.Errorf("aws-iam: STS client is not configured")
	}
	id, err := a.Client.GetCallerIdentity(ctx, credential)
	if err != nil {
		return "", nil, fmt.Errorf("aws-iam: sts GetCallerIdentity: %w", err)
	}
	if id.Account == "" || id.ARN == "" {
		return "", nil, fmt.Errorf("aws-iam: STS response missing account or ARN")
	}
	if len(a.AllowedAccounts) > 0 && !a.AllowedAccounts[id.Account] {
		return "", nil, fmt.Errorf("aws-iam: account is not allowed")
	}
	if len(a.AllowedARNs) > 0 && !a.AllowedARNs[id.ARN] {
		return "", nil, fmt.Errorf("aws-iam: ARN is not allowed")
	}
	return id.ARN, append([]string(nil), a.Scopes...), nil
}

// AWSSignedGetCallerIdentityRequest is the JSON credential a workload submits for
// AWS IAM login. It is the exact signed STS request: method, URL, headers, and body.
// The AWS secret access key is never present; only the SigV4 signature is.
type AWSSignedGetCallerIdentityRequest struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers,omitempty"`
	Body    string              `json:"body,omitempty"`
}

// HTTPSignedSTSClient verifies signed STS requests over HTTP. Endpoint defaults to
// https://sts.amazonaws.com/ and also acts as an SSRF guard: submitted request URLs
// must target the configured STS host.
type HTTPSignedSTSClient struct {
	Endpoint   string
	HTTPClient *http.Client
}

// GetCallerIdentity implements STSCallerIdentityClient.
func (c HTTPSignedSTSClient) GetCallerIdentity(ctx context.Context, credential []byte) (AWSIdentity, error) {
	var signed AWSSignedGetCallerIdentityRequest
	if err := json.Unmarshal(credential, &signed); err != nil {
		return AWSIdentity{}, fmt.Errorf("parse signed STS request: %w", err)
	}
	method := strings.ToUpper(strings.TrimSpace(signed.Method))
	if method == "" {
		method = http.MethodPost
	}
	if method != http.MethodPost && method != http.MethodGet {
		return AWSIdentity{}, fmt.Errorf("STS method %q is not allowed", method)
	}
	u, err := url.Parse(strings.TrimSpace(signed.URL))
	if err != nil {
		return AWSIdentity{}, fmt.Errorf("parse STS URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return AWSIdentity{}, fmt.Errorf("STS URL must be http or https")
	}
	endpoint := strings.TrimSpace(c.Endpoint)
	if endpoint == "" {
		endpoint = "https://sts.amazonaws.com/"
	}
	allowed, err := url.Parse(endpoint)
	if err != nil {
		return AWSIdentity{}, fmt.Errorf("parse configured STS endpoint: %w", err)
	}
	if (allowed.Scheme != "https" && allowed.Scheme != "http") || allowed.Host == "" || allowed.User != nil {
		return AWSIdentity{}, fmt.Errorf("configured STS endpoint must be an absolute http(s) URL without user info")
	}
	if !strings.EqualFold(u.Scheme, allowed.Scheme) {
		return AWSIdentity{}, fmt.Errorf("STS URL scheme %q is not the configured endpoint scheme", u.Scheme)
	}
	if !sameHost(u, allowed) {
		return AWSIdentity{}, fmt.Errorf("STS URL host %q is not the configured endpoint host", u.Host)
	}
	if !isGetCallerIdentityRequest(u, signed.Body) {
		return AWSIdentity{}, fmt.Errorf("signed STS request is not GetCallerIdentity")
	}
	if !hasAWSSignature(signed.Headers, u.Query()) {
		return AWSIdentity{}, fmt.Errorf("signed STS request is missing SigV4 authorization")
	}
	// The request sent upstream is rebuilt from operator configuration alone: the
	// configured scheme and host, the root path STS serves, and only the signed
	// STS parameters, each in the shape AWS signs. A submitted URL can't add a
	// parameter, a path or a host (CWE-918).
	query, err := signedSTSQuery(u)
	if err != nil {
		return AWSIdentity{}, err
	}
	target := url.URL{Scheme: allowed.Scheme, Host: allowed.Host, Path: "/", RawQuery: query.Encode()}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader([]byte(signed.Body)))
	if err != nil {
		return AWSIdentity{}, err
	}
	for k, vals := range signed.Headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("Content-Type") == "" && method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	client := c.HTTPClient
	if client == nil {
		client = netsec.HardenedClient(30 * time.Second)
	}
	closedClient := *client
	closedClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	// The URL is rebuilt above from the configured endpoint and the signed STS
	// parameters, and redirects are disabled: request fields can't select the peer.
	resp, err := closedClient.Do(req)
	if err != nil {
		return AWSIdentity{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return AWSIdentity{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return AWSIdentity{}, fmt.Errorf("STS returned status %d", resp.StatusCode)
	}
	id, err := parseAWSIdentity(data)
	if err != nil {
		return AWSIdentity{}, err
	}
	return id, nil
}

// stsQueryParameters are the only query parameters a signed GetCallerIdentity
// request may carry, each with the shape AWS signs.
var stsQueryParameters = map[string]*regexp.Regexp{
	"Action":               regexp.MustCompile(`^GetCallerIdentity$`),
	"Version":              regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`),
	"X-Amz-Algorithm":      regexp.MustCompile(`^AWS4-HMAC-SHA256$`),
	"X-Amz-Credential":     regexp.MustCompile(`^[A-Z0-9]{16,128}/[0-9]{8}/[a-z0-9-]{1,32}/sts/aws4_request$`),
	"X-Amz-Date":           regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`),
	"X-Amz-Expires":        regexp.MustCompile(`^[0-9]{1,6}$`),
	"X-Amz-SignedHeaders":  regexp.MustCompile(`^[a-z0-9-]+(;[a-z0-9-]+)*$`),
	"X-Amz-Signature":      regexp.MustCompile(`^[0-9a-f]{64}$`),
	"X-Amz-Security-Token": regexp.MustCompile(`^[A-Za-z0-9+/=]+$`),
}

// signedSTSQuery copies the submitted query's signed STS parameters into a new
// query, refusing any other parameter, a repeated one, a malformed value, or a
// path other than the root.
func signedSTSQuery(u *url.URL) (url.Values, error) {
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("STS URL path must be /")
	}
	submitted := u.Query()
	query := url.Values{}
	for name, pattern := range stsQueryParameters {
		values := submitted[name]
		if len(values) == 0 {
			continue
		}
		value := values[0]
		if len(values) != 1 || len(value) > 8192 || !pattern.MatchString(value) {
			return nil, fmt.Errorf("STS URL parameter %s is repeated or malformed", name)
		}
		query.Set(name, value)
	}
	for name := range submitted {
		if _, ok := stsQueryParameters[name]; !ok {
			return nil, fmt.Errorf("STS URL carries a parameter STS doesn't sign for GetCallerIdentity")
		}
	}
	return query, nil
}

func sameHost(a, b *url.URL) bool {
	return strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch u.Scheme {
	case "http":
		return "80"
	default:
		return "443"
	}
}

func isGetCallerIdentityRequest(u *url.URL, body string) bool {
	if strings.EqualFold(u.Query().Get("Action"), "GetCallerIdentity") {
		return true
	}
	vals, err := url.ParseQuery(body)
	return err == nil && strings.EqualFold(vals.Get("Action"), "GetCallerIdentity")
}

func hasAWSSignature(headers map[string][]string, q url.Values) bool {
	if q.Get("X-Amz-Signature") != "" {
		return true
	}
	for k, vals := range headers {
		if !strings.EqualFold(k, "Authorization") {
			continue
		}
		for _, v := range vals {
			if strings.HasPrefix(v, "AWS4-HMAC-SHA256 ") {
				return true
			}
		}
	}
	return false
}

func parseAWSIdentity(data []byte) (AWSIdentity, error) {
	var x struct {
		Result struct {
			UserID  string `xml:"UserId"`
			Account string `xml:"Account"`
			ARN     string `xml:"Arn"`
		} `xml:"GetCallerIdentityResult"`
	}
	if err := xml.Unmarshal(data, &x); err == nil && x.Result.Account != "" && x.Result.ARN != "" {
		return AWSIdentity{Account: x.Result.Account, ARN: x.Result.ARN, UserID: x.Result.UserID}, nil
	}
	var j struct {
		UserID  string `json:"UserId"`
		Account string `json:"Account"`
		ARN     string `json:"Arn"`
	}
	if err := json.Unmarshal(data, &j); err != nil {
		return AWSIdentity{}, fmt.Errorf("parse STS identity: %w", err)
	}
	if j.Account == "" || j.ARN == "" {
		return AWSIdentity{}, fmt.Errorf("STS identity missing account or ARN")
	}
	return AWSIdentity{Account: j.Account, ARN: j.ARN, UserID: j.UserID}, nil
}
