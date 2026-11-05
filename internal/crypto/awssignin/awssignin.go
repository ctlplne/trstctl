// SPDX-License-Identifier: BUSL-1.1
// Package awssignin signs gateway requests without placing credential material
// in immutable HTTP header strings. It does not issue or revoke authority.
package awssignin

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Credentials is borrowed byte-backed STS material, never retained by Sign.
type Credentials struct{ AccessKeyID, SecretAccessKey, SessionToken []byte }

// Sign sets public signing metadata and returns two secret-bearing header lines
// for direct byte serialization. The caller locks and wipes the returned bytes.
func Sign(request *http.Request, body []byte, credential Credentials, region, service string, now time.Time) ([]byte, error) {
	if request == nil || request.URL == nil || request.URL.Host == "" || len(body) > 1<<20 || len(request.URL.RawQuery) > 64<<10 || len(credential.AccessKeyID) == 0 || len(credential.AccessKeyID) > 256 || len(credential.SecretAccessKey) == 0 || len(credential.SecretAccessKey) > 1024 || len(credential.SessionToken) == 0 || len(credential.SessionToken) > 32<<10 || !publicScope(region) || !publicScope(service) {
		return nil, errors.New("awssignin: invalid bounded signing input")
	}
	for _, field := range [][]byte{credential.AccessKeyID, credential.SecretAccessKey, credential.SessionToken} {
		if bytes.ContainsAny(field, "\r\n") {
			return nil, errors.New("awssignin: invalid credential framing")
		}
	}
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return nil, errors.New("awssignin: malformed query")
	}
	for name := range query {
		switch strings.ToLower(name) {
		case "x-amz-algorithm", "x-amz-credential", "x-amz-date", "x-amz-expires", "x-amz-security-token", "x-amz-signature", "x-amz-signedheaders":
			query.Del(name)
		}
	}
	pairs := []string{}
	for name, values := range query {
		for _, value := range values {
			pairs = append(pairs, encode([]byte(name), true)+"="+encode([]byte(value), true))
		}
	}
	slices.Sort(pairs)
	canonicalQuery := strings.Join(pairs, "&")
	request.URL.RawQuery = canonicalQuery
	request.Header.Del("Authorization")
	request.Header.Del("X-Amz-Security-Token")
	timestamp := now.UTC().Format("20060102T150405Z")
	date := now.UTC().Format("20060102")
	request.Header.Set("X-Amz-Date", timestamp)
	payloadHash := crypto.SHA256Hex(body)
	request.Header.Set("X-Amz-Content-Sha256", payloadHash)
	names := []string{"host", "x-amz-security-token"}
	if request.ContentLength > 0 {
		names = append(names, "content-length")
	}
	for name := range request.Header {
		lower := strings.ToLower(name)
		if lower == "content-type" || strings.HasPrefix(lower, "x-amz-") {
			names = append(names, lower)
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	var canonical bytes.Buffer
	defer func() { secret.Wipe(canonical.Bytes()) }()
	canonical.WriteString(request.Method)
	canonical.WriteByte('\n')
	path := request.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if service != "s3" {
		path = encode([]byte(path), false)
	}
	canonical.WriteString(path)
	canonical.WriteByte('\n')
	canonical.WriteString(canonicalQuery)
	canonical.WriteByte('\n')
	for _, name := range names {
		canonical.WriteString(name)
		canonical.WriteByte(':')
		switch name {
		case "host":
			canonical.WriteString(request.URL.Host)
		case "content-length":
			canonical.WriteString(strconv.FormatInt(request.ContentLength, 10))
		case "x-amz-security-token":
			canonical.Write(credential.SessionToken)
		default:
			values := request.Header.Values(name)
			for i, value := range values {
				if i > 0 {
					canonical.WriteByte(',')
				}
				canonical.WriteString(strings.Join(strings.Fields(value), " "))
			}
		}
		canonical.WriteByte('\n')
	}
	signed := strings.Join(names, ";")
	canonical.WriteByte('\n')
	canonical.WriteString(signed)
	canonical.WriteByte('\n')
	canonical.WriteString(payloadHash)
	scope := date + "/" + region + "/" + service + "/aws4_request"
	text := []byte("AWS4-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + crypto.SHA256Hex(canonical.Bytes()))
	defer secret.Wipe(text)
	seed := append([]byte("AWS4"), credential.SecretAccessKey...)
	defer secret.Wipe(seed)
	dateKey := crypto.HMACSHA256(seed, []byte(date))
	defer secret.Wipe(dateKey)
	regionKey := crypto.HMACSHA256(dateKey, []byte(region))
	defer secret.Wipe(regionKey)
	serviceKey := crypto.HMACSHA256(regionKey, []byte(service))
	defer secret.Wipe(serviceKey)
	signingKey := crypto.HMACSHA256(serviceKey, []byte("aws4_request"))
	defer secret.Wipe(signingKey)
	signature := crypto.HMACSHA256(signingKey, text)
	defer secret.Wipe(signature)
	header := []byte("Authorization: AWS4-HMAC-SHA256 Credential=")
	header = append(header, credential.AccessKeyID...)
	header = append(header, '/')
	header = append(header, scope...)
	header = append(header, ", SignedHeaders="...)
	header = append(header, signed...)
	header = append(header, ", Signature="...)
	header = hex.AppendEncode(header, signature)
	header = append(header, "\r\nX-Amz-Security-Token: "...)
	header = append(header, credential.SessionToken...)
	return header, nil
}

func publicScope(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if c < 'a' || c > 'z' {
			if c < '0' || c > '9' {
				if c != '-' {
					return false
				}
			}
		}
	}
	return true
}

func encode(value []byte, slash bool) string {
	const digits = "0123456789ABCDEF"
	var out strings.Builder
	for _, b := range value {
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '.' || b == '_' || b == '~' || b == '/' && !slash {
			out.WriteByte(b)
		} else {
			out.WriteByte('%')
			out.WriteByte(digits[b>>4])
			out.WriteByte(digits[b&15])
		}
	}
	return out.String()
}
