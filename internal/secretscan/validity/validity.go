// SPDX-License-Identifier: BUSL-1.1

// Package validity checks whether a leaked secret still works, on the host
// where the scan found it (P14). A check reads the value from the scanned file
// while the scan's temporary tree still exists, calls only the provider's
// read-only identity endpoint, and keeps nothing but the verdict: for AWS the
// request is SigV4-signed, so the secret itself never leaves the host — only a
// signature over one GetCallerIdentity call does. Every provider endpoint a
// check may call is declared; a check aimed anywhere else is refused before it
// is sent, and a per-provider rate bounds how fast checks are made.
package validity

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Verdicts a check records on a finding.
const (
	StateValid     = "valid"
	StateInvalid   = "invalid"
	StateUnknown   = "unknown"
	StateUnchecked = "unchecked"
)

// ProviderAWS is AWS access key pairs.
const ProviderAWS = "aws"

// DefaultAWSEndpoint is the declared AWS identity endpoint.
const DefaultAWSEndpoint = "https://sts.amazonaws.com"

// DefaultAWSRate is how many AWS checks a second a checker makes.
const DefaultAWSRate = 5

// Result is a check's verdict. Detail names the account for a valid key, the
// provider's refusal for an invalid one, and why for the rest; it never holds
// any part of the secret.
type Result struct {
	Provider  string    `json:"provider"`
	State     string    `json:"state"`
	Detail    string    `json:"detail,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// Config declares what a checker may call.
type Config struct {
	// Endpoints maps a provider to the base URL its checks call; a provider
	// with no entry uses its public default.
	Endpoints map[string]string
	// Allowlist is the validity checks' declared outbound destinations
	// (scheme://host[:port]). Empty declares each provider's public default;
	// a check whose endpoint is not declared is refused before it is sent.
	Allowlist []string
	// Rates maps a provider to checks per second (default per provider).
	Rates map[string]float64
	// Wait bounds how long one check waits for its rate; past it the check
	// is recorded unchecked rather than exceeding the provider's limit.
	Wait   time.Duration
	Client *http.Client
	Now    func() time.Time
}

// Checker runs validity checks.
type Checker struct {
	cfg     Config
	mu      sync.Mutex
	buckets map[string]*bucket
}

// New builds a checker. A nil client cannot check anything.
func New(cfg Config) *Checker {
	if cfg.Wait <= 0 {
		cfg.Wait = 2 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Checker{cfg: cfg, buckets: map[string]*bucket{}}
}

func (c *Checker) endpoint(provider string) string {
	if e := strings.TrimSpace(c.cfg.Endpoints[provider]); e != "" {
		return strings.TrimRight(e, "/")
	}
	if provider == ProviderAWS {
		return DefaultAWSEndpoint
	}
	return ""
}

// Declared reports whether target's scheme, host and port are in the
// declared outbound allowlist.
func (c *Checker) Declared(target string) bool {
	t, err := url.Parse(target)
	if err != nil || t.Host == "" {
		return false
	}
	allow := c.cfg.Allowlist
	if len(allow) == 0 {
		allow = []string{DefaultAWSEndpoint}
	}
	for _, entry := range allow {
		d, err := url.Parse(strings.TrimSpace(entry))
		if err == nil && d.Host != "" && d.Scheme == t.Scheme && strings.EqualFold(d.Host, t.Host) {
			return true
		}
	}
	return false
}

type bucket struct {
	rate   float64
	tokens float64
	last   time.Time
}

// take waits for one token of the provider's rate, at most cfg.Wait.
func (c *Checker) take(ctx context.Context, provider string) bool {
	rate := c.cfg.Rates[provider]
	if rate <= 0 {
		rate = DefaultAWSRate
	}
	deadline := c.cfg.Now().Add(c.cfg.Wait)
	for {
		c.mu.Lock()
		b := c.buckets[provider]
		now := c.cfg.Now()
		if b == nil {
			b = &bucket{rate: rate, tokens: 1, last: now}
			c.buckets[provider] = b
		}
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		if b.tokens > 1 {
			b.tokens = 1
		}
		b.last = now
		if b.tokens >= 1 {
			b.tokens--
			c.mu.Unlock()
			return true
		}
		wait := time.Duration((1 - b.tokens) / b.rate * float64(time.Second))
		c.mu.Unlock()
		if now.Add(wait).After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(wait):
		}
	}
}

var (
	awsKeyID = regexp.MustCompile(`\bAKIA[A-Z0-9]{16}\b`)
	// An AWS secret access key is 40 characters of base64 without padding,
	// so an = before it (KEY=...) is a boundary, not part of it.
	awsSecretKey = regexp.MustCompile(`(?:^|[^A-Za-z0-9/+])([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+]|$)`)
)

// maxCheckedFile bounds what a check reads from the scanned tree.
const maxCheckedFile = 4 << 20

// readNear returns the lines around line (1-based) of a file inside root.
func readNear(root, file string, line, span int) ([]byte, error) {
	full := file
	if !filepath.IsAbs(full) {
		full = filepath.Join(root, file)
	}
	full = filepath.Clean(full)
	rel, err := filepath.Rel(filepath.Clean(root), full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, errors.New("validity: the finding's file is outside the scanned tree")
	}
	f, err := os.Open(full) // #nosec G304 -- confined to the scan's own temporary tree above (CWE-22)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxCheckedFile))
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(data, []byte("\n"))
	from, to := line-1-span, line+span
	if from < 0 {
		from = 0
	}
	if to > len(lines) {
		to = len(lines)
	}
	if from >= to {
		secret.Wipe(data)
		return nil, errors.New("validity: the finding's line is not in the file")
	}
	near := bytes.Join(lines[from:to], []byte("\n"))
	out := append([]byte(nil), near...)
	secret.Wipe(data)
	return out, nil
}

// AWSPair finds an access key ID and the 40-character secret beside it in
// text, the way credential files, environment files and messages hold them.
func AWSPair(text []byte) (string, []byte, bool) {
	id := awsKeyID.Find(text)
	if id == nil {
		return "", nil, false
	}
	for _, m := range awsSecretKey.FindAllSubmatch(text, -1) {
		candidate := m[1]
		if bytes.Contains(candidate, id) || !bytes.ContainsAny(candidate, "abcdefghijklmnopqrstuvwxyz") {
			continue
		}
		return string(id), append([]byte(nil), candidate...), true
	}
	return "", nil, false
}

// CheckAWSFinding checks the AWS key pair at a finding's file and line, read
// from the scanned tree at root.
func (c *Checker) CheckAWSFinding(ctx context.Context, root, file string, line int) Result {
	near, err := readNear(root, file, line, 3)
	if err != nil {
		return c.result(ProviderAWS, StateUnchecked, "the finding's line could not be read")
	}
	defer secret.Wipe(near)
	keyID, secretKey, ok := AWSPair(near)
	if !ok {
		return c.result(ProviderAWS, StateUnchecked, "no secret access key beside the access key ID")
	}
	defer secret.Wipe(secretKey)
	return c.CheckAWS(ctx, keyID, secretKey)
}

// CheckAWS calls STS GetCallerIdentity, SigV4-signed with the pair, at the
// declared AWS endpoint.
func (c *Checker) CheckAWS(ctx context.Context, keyID string, secretKey []byte) Result {
	target := c.endpoint(ProviderAWS) + "/"
	if !c.Declared(target) {
		return c.result(ProviderAWS, StateUnchecked, "refused: the AWS endpoint is not in the validity checks' outbound allowlist")
	}
	if c.cfg.Client == nil {
		return c.result(ProviderAWS, StateUnchecked, "no client for validity checks")
	}
	if !c.take(ctx, ProviderAWS) {
		return c.result(ProviderAWS, StateUnchecked, "rate limited: the AWS check budget was spent")
	}
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return c.result(ProviderAWS, StateUnchecked, "the check could not be built")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	signAWS(req, body, keyID, secretKey, "us-east-1", "sts", c.cfg.Now().UTC())
	resp, err := c.cfg.Client.Do(req)
	if err != nil {
		return c.result(ProviderAWS, StateUnknown, "AWS could not be reached")
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var answer struct {
		Account string `xml:"GetCallerIdentityResult>Account"`
		Arn     string `xml:"GetCallerIdentityResult>Arn"`
		Code    string `xml:"Error>Code"`
	}
	_ = xml.Unmarshal(raw, &answer)
	switch {
	case resp.StatusCode == http.StatusOK && answer.Account != "":
		return c.result(ProviderAWS, StateValid, "account "+answer.Account+" ("+answer.Arn+")")
	case resp.StatusCode == http.StatusForbidden && (answer.Code == "InvalidClientTokenId" || answer.Code == "SignatureDoesNotMatch"):
		return c.result(ProviderAWS, StateInvalid, "AWS refused the key: "+answer.Code)
	default:
		return c.result(ProviderAWS, StateUnknown, "AWS answered "+http.StatusText(resp.StatusCode))
	}
}

func (c *Checker) result(provider, state, detail string) Result {
	return Result{Provider: provider, State: state, Detail: detail, CheckedAt: c.cfg.Now().UTC()}
}

// signAWS signs a request with SigV4 (AWS's signature version 4).
func signAWS(req *http.Request, body []byte, keyID string, secretKey []byte, region, service string, t time.Time) {
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	host := req.URL.Host
	canonicalRequest := strings.Join([]string{req.Method, req.URL.EscapedPath(), "",
		"content-type:" + req.Header.Get("Content-Type") + "\nhost:" + host + "\nx-amz-date:" + amzDate + "\n",
		"content-type;host;x-amz-date", crypto.SHA256Hex(body)}, "\n")
	scope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, crypto.SHA256Hex([]byte(canonicalRequest))}, "\n")
	seed := append([]byte("AWS4"), secretKey...)
	kDate := crypto.HMACSHA256(seed, []byte(dateStamp))
	secret.Wipe(seed)
	kRegion := crypto.HMACSHA256(kDate, []byte(region))
	secret.Wipe(kDate)
	kService := crypto.HMACSHA256(kRegion, []byte(service))
	secret.Wipe(kRegion)
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	secret.Wipe(kService)
	signature := hex.EncodeToString(crypto.HMACSHA256(kSigning, []byte(stringToSign)))
	secret.Wipe(kSigning)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+keyID+"/"+scope+", SignedHeaders=content-type;host;x-amz-date, Signature="+signature)
}
