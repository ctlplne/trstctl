// SPDX-License-Identifier: BUSL-1.1

// Package awsiamkeys enumerates an AWS account's IAM user access keys (M3):
// each key's user, status, creation date and when and where it was last used.
// It calls only the read-only IAM operations ListUsers, ListAccessKeys and
// GetAccessKeyLastUsed, signed with AWS Signature Version 4 (digests and the
// keyed MAC through the crypto boundary, AN-3). Access key IDs are identifiers;
// no secret access key is ever requested or returned.
package awsiamkeys

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
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/netsec"
)

const (
	service    = "iam"
	apiVersion = "2010-05-08"
	// IAM is global: its endpoint and signing region are fixed.
	defaultEndpoint = "https://iam.amazonaws.com"
	signingRegion   = "us-east-1"
	maxBody         = 4 << 20
	// MaxKeys bounds one enumeration.
	MaxKeys = 10000
)

// StaleAfter is how long unused a key is before it is flagged.
const StaleAfter = 90 * 24 * time.Hour

// Config configures the IAM reader.
type Config struct {
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	HTTPClient      *http.Client
	Now             func() time.Time
}

// Key is one IAM user access key.
type Key struct {
	User            string
	AccessKeyID     string
	Status          string
	Created         time.Time
	LastUsed        *time.Time
	LastUsedService string
	LastUsedRegion  string
}

// Unused is how long the key has gone unused at now: since its last use, or
// since it was created when it was never used.
func (k Key) Unused(now time.Time) time.Duration {
	since := k.Created
	if k.LastUsed != nil {
		since = *k.LastUsed
	}
	if since.IsZero() || now.Before(since) {
		return 0
	}
	return now.Sub(since)
}

// Stale reports an active key unused for StaleAfter.
func (k Key) Stale(now time.Time) bool {
	return strings.EqualFold(k.Status, "Active") && k.Unused(now) >= StaleAfter
}

// Reader reads one account's IAM access keys.
type Reader struct {
	cfg  Config
	host string
}

// New builds a reader.
func New(cfg Config) (*Reader, error) {
	if strings.TrimSpace(cfg.AccessKeyID) == "" || cfg.SecretAccessKey == "" {
		return nil, fmt.Errorf("awsiamkeys: credentials are required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = defaultEndpoint
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("awsiamkeys: bad endpoint")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.HardenedClient(30 * time.Second)
	}
	return &Reader{cfg: cfg, host: u.Host}, nil
}

// Keys lists every user's access keys with their last use, users in name
// order, at most MaxKeys.
func (r *Reader) Keys(ctx context.Context) ([]Key, error) {
	var users []string
	marker := ""
	for {
		params := url.Values{"Action": {"ListUsers"}, "MaxItems": {"1000"}}
		if marker != "" {
			params.Set("Marker", marker)
		}
		var page listUsersResponse
		if err := r.call(ctx, params, &page); err != nil {
			return nil, err
		}
		for _, u := range page.Users {
			users = append(users, u.UserName)
		}
		if !page.IsTruncated || page.Marker == "" {
			break
		}
		marker = page.Marker
	}
	sort.Strings(users)
	var keys []Key
	for _, user := range users {
		var listed listAccessKeysResponse
		if err := r.call(ctx, url.Values{"Action": {"ListAccessKeys"}, "UserName": {user}, "MaxItems": {"100"}}, &listed); err != nil {
			return nil, err
		}
		for _, m := range listed.Keys {
			created, _ := time.Parse(time.RFC3339, m.CreateDate)
			key := Key{User: user, AccessKeyID: m.AccessKeyID, Status: m.Status, Created: created.UTC()}
			var used getAccessKeyLastUsedResponse
			if err := r.call(ctx, url.Values{"Action": {"GetAccessKeyLastUsed"}, "AccessKeyId": {m.AccessKeyID}}, &used); err != nil {
				return nil, err
			}
			if at, err := time.Parse(time.RFC3339, used.LastUsedDate); err == nil && !at.IsZero() {
				at = at.UTC()
				key.LastUsed = &at
			}
			if svc := used.ServiceName; svc != "" && svc != "N/A" {
				key.LastUsedService = svc
			}
			if region := used.Region; region != "" && region != "N/A" {
				key.LastUsedRegion = region
			}
			keys = append(keys, key)
			if len(keys) >= MaxKeys {
				return keys, nil
			}
		}
	}
	return keys, nil
}

type listUsersResponse struct {
	Users []struct {
		UserName string `xml:"UserName"`
	} `xml:"ListUsersResult>Users>member"`
	IsTruncated bool   `xml:"ListUsersResult>IsTruncated"`
	Marker      string `xml:"ListUsersResult>Marker"`
}

type listAccessKeysResponse struct {
	Keys []struct {
		AccessKeyID string `xml:"AccessKeyId"`
		Status      string `xml:"Status"`
		CreateDate  string `xml:"CreateDate"`
	} `xml:"ListAccessKeysResult>AccessKeyMetadata>member"`
}

type getAccessKeyLastUsedResponse struct {
	LastUsedDate string `xml:"GetAccessKeyLastUsedResult>AccessKeyLastUsed>LastUsedDate"`
	ServiceName  string `xml:"GetAccessKeyLastUsedResult>AccessKeyLastUsed>ServiceName"`
	Region       string `xml:"GetAccessKeyLastUsedResult>AccessKeyLastUsed>Region"`
}

func (r *Reader) call(ctx context.Context, params url.Values, out any) error {
	params.Set("Version", apiVersion)
	body := []byte(params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(r.cfg.Endpoint, "/")+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	r.signV4(req, body, r.cfg.Now().UTC())
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("awsiamkeys: %s: %w", params.Get("Action"), err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("awsiamkeys: %s: read response: %w", params.Get("Action"), err)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("awsiamkeys: %s: status %d (response body redacted)", params.Get("Action"), resp.StatusCode)
	}
	if err := xml.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("awsiamkeys: %s: decode response: %w", params.Get("Action"), err)
	}
	return nil
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
	credScope := dateStamp + "/" + signingRegion + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, credScope, crypto.SHA256Hex([]byte(canonicalRequest))}, "\n")
	kDate := crypto.HMACSHA256([]byte("AWS4"+r.cfg.SecretAccessKey), []byte(dateStamp))
	kRegion := crypto.HMACSHA256(kDate, []byte(signingRegion))
	kService := crypto.HMACSHA256(kRegion, []byte(service))
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(crypto.HMACSHA256(kSigning, []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+r.cfg.AccessKeyID+"/"+credScope+
		", SignedHeaders="+signedHeaders+", Signature="+signature)
}
