// SPDX-License-Identifier: BUSL-1.1

// Package awselb reads one AWS account and Region's load-balancer listener TLS
// policies (X4) through the read-only Elastic Load Balancing v2 Query API:
// DescribeLoadBalancers, DescribeListeners and DescribeSSLPolicies. Each
// HTTPS or TLS listener comes back with its security policy's protocol
// versions and cipher suites. It changes nothing.
package awselb

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/discovery/lbtls"
	"trstctl.com/trstctl/internal/netsec"
)

const (
	apiVersion = "2015-12-01"
	service    = "elasticloadbalancing"
	maxBody    = 4 << 20
	// maxPages bounds any one paged list.
	maxPages = 1000
)

// Config is one account and Region's read-only access.
type Config struct {
	Region          string
	Endpoint        string // default https://elasticloadbalancing.<region>.amazonaws.com
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	HTTPClient      *http.Client
	Now             func() time.Time
}

// Reader reads one account and Region's listeners.
type Reader struct {
	cfg  Config
	host string
}

// New builds a reader.
func New(cfg Config) (*Reader, error) {
	if strings.TrimSpace(cfg.Region) == "" {
		return nil, fmt.Errorf("awselb: region is required")
	}
	if strings.TrimSpace(cfg.AccessKeyID) == "" || cfg.SecretAccessKey == "" {
		return nil, fmt.Errorf("awselb: credentials are required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://elasticloadbalancing." + cfg.Region + ".amazonaws.com"
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("awselb: bad endpoint")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.HardenedClient(30 * time.Second)
	}
	return &Reader{cfg: cfg, host: u.Host}, nil
}

type loadBalancer struct {
	ARN  string `xml:"LoadBalancerArn"`
	Name string `xml:"LoadBalancerName"`
}

type listener struct {
	ARN       string `xml:"ListenerArn"`
	Port      int    `xml:"Port"`
	Protocol  string `xml:"Protocol"`
	SslPolicy string `xml:"SslPolicy"`
}

type sslPolicy struct {
	Name      string   `xml:"Name"`
	Protocols []string `xml:"SslProtocols>member"`
	Ciphers   []struct {
		Name     string `xml:"Name"`
		Priority int    `xml:"Priority"`
	} `xml:"Ciphers>member"`
}

// Listeners lists every HTTPS and TLS listener in the Region with its
// security policy's versions and ciphers, in listener ARN order, at most
// lbtls.MaxListeners. A listener whose policy is not described is an error:
// a partial answer would hide the weakest policy.
func (r *Reader) Listeners(ctx context.Context) ([]lbtls.Listener, error) {
	var lbs []loadBalancer
	if err := r.paged(ctx, url.Values{"Action": {"DescribeLoadBalancers"}, "PageSize": {"400"}}, func(raw []byte) (string, error) {
		var page struct {
			LoadBalancers []loadBalancer `xml:"DescribeLoadBalancersResult>LoadBalancers>member"`
			NextMarker    string         `xml:"DescribeLoadBalancersResult>NextMarker"`
		}
		if err := xml.Unmarshal(raw, &page); err != nil {
			return "", err
		}
		lbs = append(lbs, page.LoadBalancers...)
		return page.NextMarker, nil
	}); err != nil {
		return nil, err
	}
	type found struct {
		lb loadBalancer
		l  listener
	}
	var tlsListeners []found
	policyNames := map[string]bool{}
	for _, lb := range lbs {
		if err := r.paged(ctx, url.Values{"Action": {"DescribeListeners"}, "LoadBalancerArn": {lb.ARN}, "PageSize": {"400"}}, func(raw []byte) (string, error) {
			var page struct {
				Listeners  []listener `xml:"DescribeListenersResult>Listeners>member"`
				NextMarker string     `xml:"DescribeListenersResult>NextMarker"`
			}
			if err := xml.Unmarshal(raw, &page); err != nil {
				return "", err
			}
			for _, l := range page.Listeners {
				if (l.Protocol == "HTTPS" || l.Protocol == "TLS") && l.SslPolicy != "" && len(tlsListeners) < lbtls.MaxListeners {
					tlsListeners = append(tlsListeners, found{lb: lb, l: l})
					policyNames[l.SslPolicy] = true
				}
			}
			return page.NextMarker, nil
		}); err != nil {
			return nil, err
		}
	}
	policies, err := r.policies(ctx, policyNames)
	if err != nil {
		return nil, err
	}
	out := make([]lbtls.Listener, 0, len(tlsListeners))
	for _, f := range tlsListeners {
		p, ok := policies[f.l.SslPolicy]
		if !ok {
			return nil, fmt.Errorf("awselb: security policy %q of listener %s was not described", f.l.SslPolicy, f.l.ARN)
		}
		out = append(out, lbtls.Listener{LoadBalancer: f.lb.Name, Ref: f.l.ARN, Port: f.l.Port, Protocol: f.l.Protocol,
			Policy: p.Name, Protocols: lbtls.SortProtocols(p.Protocols), Ciphers: cipherNames(p)})
	}
	lbtls.SortListeners(out)
	return out, nil
}

// policies describes the named security policies, 20 names a call.
func (r *Reader) policies(ctx context.Context, names map[string]bool) (map[string]sslPolicy, error) {
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	out := map[string]sslPolicy{}
	for start := 0; start < len(sorted); start += 20 {
		end := min(start+20, len(sorted))
		params := url.Values{"Action": {"DescribeSSLPolicies"}}
		for i, n := range sorted[start:end] {
			params.Set("Names.member."+strconv.Itoa(i+1), n)
		}
		if err := r.paged(ctx, params, func(raw []byte) (string, error) {
			var page struct {
				Policies   []sslPolicy `xml:"DescribeSSLPoliciesResult>SslPolicies>member"`
				NextMarker string      `xml:"DescribeSSLPoliciesResult>NextMarker"`
			}
			if err := xml.Unmarshal(raw, &page); err != nil {
				return "", err
			}
			for _, p := range page.Policies {
				out[p.Name] = p
			}
			return page.NextMarker, nil
		}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func cipherNames(p sslPolicy) []string {
	ciphers := append(p.Ciphers[:0:0], p.Ciphers...)
	sort.SliceStable(ciphers, func(i, j int) bool { return ciphers[i].Priority < ciphers[j].Priority })
	out := make([]string, 0, len(ciphers))
	for _, c := range ciphers {
		out = append(out, c.Name)
	}
	return out
}

// paged runs one Query action across its Marker pages.
func (r *Reader) paged(ctx context.Context, params url.Values, page func([]byte) (string, error)) error {
	marker := ""
	for i := 0; i < maxPages; i++ {
		p := url.Values{}
		for k, v := range params {
			p[k] = append([]string(nil), v...)
		}
		if marker != "" {
			p.Set("Marker", marker)
		}
		raw, err := r.call(ctx, p)
		if err != nil {
			return err
		}
		next, err := page(raw)
		if err != nil {
			return fmt.Errorf("awselb: %s: decode response: %w", params.Get("Action"), err)
		}
		if next == "" {
			return nil
		}
		marker = next
	}
	return fmt.Errorf("awselb: %s: more than %d pages", params.Get("Action"), maxPages)
}

func (r *Reader) call(ctx context.Context, params url.Values) ([]byte, error) {
	params.Set("Version", apiVersion)
	body := []byte(params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(r.cfg.Endpoint, "/")+"/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	r.signV4(req, body, r.cfg.Now().UTC())
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("awselb: %s: %w", params.Get("Action"), err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("awselb: %s: read response: %w", params.Get("Action"), err)
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Code string `xml:"Error>Code"`
		}
		_ = xml.Unmarshal(raw, &e)
		return nil, fmt.Errorf("awselb: %s: status %d %s (response body redacted)", params.Get("Action"), resp.StatusCode, e.Code)
	}
	return raw, nil
}

// signV4 adds AWS Signature Version 4 headers through the crypto boundary.
func (r *Reader) signV4(req *http.Request, body []byte, t time.Time) {
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if r.cfg.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", r.cfg.SessionToken)
	}
	signed := []string{"content-type", "host", "x-amz-date"}
	if r.cfg.SessionToken != "" {
		signed = append(signed, "x-amz-security-token")
	}
	sort.Strings(signed)
	var canonHeaders strings.Builder
	for _, h := range signed {
		v := strings.TrimSpace(req.Header.Get(h))
		if h == "host" {
			v = r.host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	signedHeaders := strings.Join(signed, ";")
	canonicalRequest := strings.Join([]string{
		req.Method, req.URL.EscapedPath(), "", canonHeaders.String(), signedHeaders, crypto.SHA256Hex(body),
	}, "\n")
	credScope := dateStamp + "/" + r.cfg.Region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, credScope, crypto.SHA256Hex([]byte(canonicalRequest))}, "\n")
	kDate := crypto.HMACSHA256([]byte("AWS4"+r.cfg.SecretAccessKey), []byte(dateStamp))
	kRegion := crypto.HMACSHA256(kDate, []byte(r.cfg.Region))
	kService := crypto.HMACSHA256(kRegion, []byte(service))
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(crypto.HMACSHA256(kSigning, []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+r.cfg.AccessKeyID+"/"+credScope+
		", SignedHeaders="+signedHeaders+", Signature="+signature)
}
