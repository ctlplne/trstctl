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
	"strings"
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
	if !sameHost(u, allowed) {
		return AWSIdentity{}, fmt.Errorf("STS URL host %q is not the configured endpoint host", u.Host)
	}
	if !isGetCallerIdentityRequest(u, signed.Body) {
		return AWSIdentity{}, fmt.Errorf("signed STS request is not GetCallerIdentity")
	}
	if !hasAWSSignature(signed.Headers, u.Query()) {
		return AWSIdentity{}, fmt.Errorf("signed STS request is missing SigV4 authorization")
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader([]byte(signed.Body)))
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
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
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
