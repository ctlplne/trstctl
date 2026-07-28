// SPDX-License-Identifier: MPL-2.0

package cloudauth

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const awsSTSVersion = "2011-06-15"

// AWSExchangeRequest is the thin AWS STS AssumeRoleWithWebIdentity encoder
// input. WebIdentityToken stays mutable bytes throughout the request build.
type AWSExchangeRequest struct {
	Endpoint         string
	RoleARN          string
	RoleSessionName  string
	WebIdentityToken []byte
	DurationSeconds  int
}

// ExchangeAWSWebIdentity posts one bounded, byte-native AWS STS query request
// and returns the temporary SigV4 material. It does no retries and no caching;
// the outbox owns retries while Minter owns refresh-before-expiry caching.
func ExchangeAWSWebIdentity(ctx context.Context, doer cloudhttp.Doer, in AWSExchangeRequest) (Material, error) {
	if in.Endpoint == "" || in.RoleARN == "" || in.RoleSessionName == "" || len(in.WebIdentityToken) == 0 {
		return Material{}, errors.New("cloudauth: AWS endpoint, role ARN, session name, and web identity token are required")
	}
	if doer == nil {
		return Material{}, errors.New("cloudauth: reviewed AWS HTTP client is required")
	}
	duration := in.DurationSeconds
	if duration == 0 {
		duration = 900
	}
	if duration < 900 || duration > 43200 {
		return Material{}, errors.New("cloudauth: AWS session duration must be between 900 and 43200 seconds")
	}
	body := make([]byte, 0, len(in.WebIdentityToken)+len(in.RoleARN)+len(in.RoleSessionName)+160)
	body = appendForm(body, "Action", []byte("AssumeRoleWithWebIdentity"))
	body = appendForm(body, "Version", []byte(awsSTSVersion))
	body = appendForm(body, "RoleArn", []byte(in.RoleARN))
	body = appendForm(body, "RoleSessionName", []byte(in.RoleSessionName))
	body = appendForm(body, "DurationSeconds", []byte(strconv.Itoa(duration)))
	body = appendForm(body, "WebIdentityToken", in.WebIdentityToken)
	defer secret.Wipe(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.Endpoint, bytes.NewReader(body))
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: build AWS STS request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	raw, err := cloudhttp.Bytes(doer, req, cloudhttp.WithTimeout(30*time.Second))
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: AWS STS exchange: %w", err)
	}
	defer secret.Wipe(raw)
	material, err := parseAWSAssumeRoleResponse(raw)
	if err != nil {
		return Material{}, err
	}
	return material, nil
}

func appendForm(dst []byte, name string, value []byte) []byte {
	if len(dst) > 0 {
		dst = append(dst, '&')
	}
	dst = append(dst, name...)
	dst = append(dst, '=')
	return appendFormEscaped(dst, value)
}

func appendFormEscaped(dst, value []byte) []byte {
	const hex = "0123456789ABCDEF"
	for _, b := range value {
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9',
			b == '-', b == '_', b == '.', b == '~':
			dst = append(dst, b)
		case b == ' ':
			dst = append(dst, '+')
		default:
			dst = append(dst, '%', hex[b>>4], hex[b&0x0f])
		}
	}
	return dst
}

type secretText []byte

func (s *secretText) UnmarshalText(text []byte) error {
	*s = append((*s)[:0], text...)
	return nil
}

type awsAssumeRoleResponse struct {
	Result struct {
		Credentials struct {
			AccessKeyID     string     `xml:"AccessKeyId"`
			SecretAccessKey secretText `xml:"SecretAccessKey"`
			SessionToken    secretText `xml:"SessionToken"`
			Expiration      string     `xml:"Expiration"`
		} `xml:"Credentials"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
}

func parseAWSAssumeRoleResponse(raw []byte) (Material, error) {
	var decoded awsAssumeRoleResponse
	if err := xml.Unmarshal(raw, &decoded); err != nil {
		return Material{}, errors.New("cloudauth: AWS STS returned malformed XML")
	}
	credentials := decoded.Result.Credentials
	defer secret.Wipe(credentials.SecretAccessKey)
	defer secret.Wipe(credentials.SessionToken)
	expiresAt, err := time.Parse(time.RFC3339, credentials.Expiration)
	if err != nil {
		return Material{}, errors.New("cloudauth: AWS STS returned an invalid expiration")
	}
	if credentials.AccessKeyID == "" || len(credentials.SecretAccessKey) == 0 || len(credentials.SessionToken) == 0 {
		return Material{}, errors.New("cloudauth: AWS STS returned incomplete credentials")
	}
	return Material{
		Identifier: credentials.AccessKeyID,
		Primary:    append([]byte(nil), credentials.SecretAccessKey...),
		Secondary:  append([]byte(nil), credentials.SessionToken...),
		ExpiresAt:  expiresAt.UTC(),
	}, nil
}
