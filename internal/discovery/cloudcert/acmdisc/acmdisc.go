// Package acmdisc enumerates certificates from AWS Certificate Manager through
// its read-only ListCertificates and GetCertificate operations (F49). It signs
// requests with AWS Signature Version 4 — digests and the keyed MAC routed
// through the crypto boundary (AN-3) — and never invokes a mutating operation.
package acmdisc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
)

const (
	service = "acm"
	amzJSON = "application/x-amz-json-1.1"
)

// Config configures the ACM enumerator.
type Config struct {
	Region          string
	Endpoint        string // e.g. https://acm.us-east-1.amazonaws.com
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	HTTPClient      *http.Client
	Now             func() time.Time
	Retry           cloudcert.RetryPolicy
}

// Enumerator is a read-only ACM certificate source.
type Enumerator struct {
	cfg  Config
	host string
}

// New builds an ACM enumerator.
func New(cfg Config) (*Enumerator, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("acmdisc: endpoint required")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("acmdisc: bad endpoint: %w", err)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.Retry.Max == 0 && cfg.Retry.Base == 0 {
		cfg.Retry = cloudcert.DefaultRetry()
	}
	return &Enumerator{cfg: cfg, host: u.Host}, nil
}

// Name identifies the provider.
func (e *Enumerator) Name() string { return "aws-acm" }

// Enumerate lists every certificate and fetches its PEM, parsing each through
// the crypto boundary.
func (e *Enumerator) Enumerate(ctx context.Context) ([]cloudcert.Found, error) {
	arns, err := e.listARNs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]cloudcert.Found, 0, len(arns))
	for _, arn := range arns {
		pemBytes, err := e.getCertificate(ctx, arn)
		if err != nil {
			return nil, err
		}
		info, err := certinfo.Inspect(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("acmdisc: inspect %s: %w", arn, err)
		}
		out = append(out, cloudcert.Found{Provider: e.Name(), ResourceID: arn, Location: e.cfg.Region, Cert: info})
	}
	return out, nil
}

func (e *Enumerator) listARNs(ctx context.Context) ([]string, error) {
	var arns []string
	next := ""
	for {
		payload := map[string]any{"MaxItems": 100}
		if next != "" {
			payload["NextToken"] = next
		}
		raw, err := e.call(ctx, "CertificateManager.ListCertificates", payload)
		if err != nil {
			return nil, err
		}
		var resp struct {
			CertificateSummaryList []struct {
				CertificateArn string `json:"CertificateArn"`
			} `json:"CertificateSummaryList"`
			NextToken string `json:"NextToken"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("acmdisc: parse list: %w", err)
		}
		for _, s := range resp.CertificateSummaryList {
			arns = append(arns, s.CertificateArn)
		}
		if resp.NextToken == "" {
			break
		}
		next = resp.NextToken
	}
	return arns, nil
}

func (e *Enumerator) getCertificate(ctx context.Context, arn string) ([]byte, error) {
	raw, err := e.call(ctx, "CertificateManager.GetCertificate", map[string]any{"CertificateArn": arn})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Certificate string `json:"Certificate"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("acmdisc: parse get: %w", err)
	}
	if resp.Certificate == "" {
		return nil, fmt.Errorf("acmdisc: empty certificate for %s", arn)
	}
	return []byte(resp.Certificate), nil
}

// call signs and sends one AWS JSON 1.1 operation, with bounded rate-limit
// retries.
func (e *Enumerator) call(ctx context.Context, target string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.Endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", amzJSON)
	req.Header.Set("X-Amz-Target", target)
	e.signV4(req, body, e.cfg.Now().UTC())
	return cloudcert.Fetch(ctx, e.cfg.HTTPClient, req, body, e.cfg.Retry)
}

// signV4 adds AWS Signature Version 4 headers. Digests and the keyed MAC route
// through the crypto boundary (AN-3).
func (e *Enumerator) signV4(req *http.Request, body []byte, t time.Time) {
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if e.cfg.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", e.cfg.SessionToken)
	}

	signed := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if e.cfg.SessionToken != "" {
		signed = append(signed, "x-amz-security-token")
	}
	sort.Strings(signed)

	var canonHeaders strings.Builder
	for _, h := range signed {
		v := strings.TrimSpace(req.Header.Get(h))
		if h == "host" {
			v = e.host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	signedHeaders := strings.Join(signed, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		"",
		canonHeaders.String(),
		signedHeaders,
		crypto.SHA256Hex(body),
	}, "\n")

	credScope := dateStamp + "/" + e.cfg.Region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		crypto.SHA256Hex([]byte(canonicalRequest)),
	}, "\n")

	kDate := crypto.HMACSHA256([]byte("AWS4"+e.cfg.SecretAccessKey), []byte(dateStamp))
	kRegion := crypto.HMACSHA256(kDate, []byte(e.cfg.Region))
	kService := crypto.HMACSHA256(kRegion, []byte(service))
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(crypto.HMACSHA256(kSigning, []byte(stringToSign)))

	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 "+
		"Credential="+e.cfg.AccessKeyID+"/"+credScope+", "+
		"SignedHeaders="+signedHeaders+", "+
		"Signature="+signature)
}
