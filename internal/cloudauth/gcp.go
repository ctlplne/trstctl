// SPDX-License-Identifier: MPL-2.0

package cloudauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	gcpCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
	gcpTokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	gcpAccessTokenType    = "urn:ietf:params:oauth:token-type:access_token"   // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	gcpJWTTokenType       = "urn:ietf:params:oauth:token-type:jwt"            // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
)

// GCPExchangeRequest is the thin RFC 8693 and optional service-account
// impersonation encoder input. SubjectToken remains mutable authority bytes.
type GCPExchangeRequest struct {
	STSEndpoint           string
	Audience              string
	SubjectToken          []byte
	ServiceAccount        string
	ImpersonationEndpoint string
	ImpersonationDoer     cloudhttp.Doer
}

// ExchangeGCPWorkloadIdentity exchanges one validated workload proof at GCP
// STS, then optionally narrows it to a service-account access token. It performs
// no retry and no caching; the bounded outbox and shared Minter own those jobs.
func ExchangeGCPWorkloadIdentity(ctx context.Context, doer cloudhttp.Doer, in GCPExchangeRequest) (Material, error) {
	if doer == nil {
		return Material{}, errors.New("cloudauth: reviewed GCP HTTP client is required")
	}
	if in.STSEndpoint == "" || in.Audience == "" || len(in.SubjectToken) == 0 {
		return Material{}, errors.New("cloudauth: GCP STS endpoint, audience, and subject token are required")
	}
	if (in.ServiceAccount == "") != (in.ImpersonationEndpoint == "") {
		return Material{}, errors.New("cloudauth: GCP service account and impersonation endpoint must be configured together")
	}

	body := make([]byte, 0, len(in.SubjectToken)+len(in.Audience)+320)
	body = appendForm(body, "grant_type", []byte(gcpTokenExchangeGrant))
	body = appendForm(body, "audience", []byte(in.Audience))
	body = appendForm(body, "requested_token_type", []byte(gcpAccessTokenType))
	body = appendForm(body, "subject_token_type", []byte(gcpJWTTokenType))
	body = appendForm(body, "subject_token", in.SubjectToken)
	body = appendForm(body, "scope", []byte(gcpCloudPlatformScope))
	defer secret.Wipe(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.STSEndpoint, bytes.NewReader(body))
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: build GCP STS request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	raw, err := cloudhttp.Bytes(doer, req, cloudhttp.WithTimeout(30*time.Second))
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: GCP STS exchange: %w", err)
	}
	defer secret.Wipe(raw)
	material, err := parseGCPSTSResponse(raw, time.Now().UTC())
	if err != nil {
		return Material{}, err
	}
	if in.ServiceAccount == "" {
		return material, nil
	}
	defer secret.Wipe(material.Primary)

	stsToken, err := secret.NewFrom(material.Primary)
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: lock GCP STS token: %w", err)
	}
	defer stsToken.Destroy()
	impersonationDoer := in.ImpersonationDoer
	if impersonationDoer == nil {
		impersonationDoer = doer
	}
	return exchangeGCPServiceAccount(ctx, impersonationDoer, in.ImpersonationEndpoint, stsToken.Bytes())
}

type gcpSTSResponse struct {
	AccessToken secretjson.StringBytes `json:"access_token"`
	TokenType   string                 `json:"token_type"`
	ExpiresIn   int64                  `json:"expires_in"`
}

func parseGCPSTSResponse(raw []byte, now time.Time) (Material, error) {
	var decoded gcpSTSResponse
	// The closure matters: `defer secret.Wipe(decoded.AccessToken)` would
	// evaluate the field NOW, while it is still nil, and wipe nothing — the
	// decoder then allocates a fresh backing array that is never zeroed, so the
	// access token survives in the heap for the process lifetime (AN-8).
	defer func() { secret.Wipe(decoded.AccessToken) }()
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return Material{}, errors.New("cloudauth: GCP STS returned malformed JSON")
	}
	if len(decoded.AccessToken) == 0 || decoded.TokenType != "Bearer" ||
		decoded.ExpiresIn < 1 || decoded.ExpiresIn > 43200 {
		return Material{}, errors.New("cloudauth: GCP STS returned incomplete credentials")
	}
	return Material{
		Identifier: "gcp",
		Primary:    append([]byte(nil), decoded.AccessToken...),
		ExpiresAt:  now.UTC().Add(time.Duration(decoded.ExpiresIn) * time.Second),
	}, nil
}

func exchangeGCPServiceAccount(ctx context.Context, doer cloudhttp.Doer, endpoint string, stsToken []byte) (Material, error) {
	body, err := json.Marshal(struct {
		Scope    []string `json:"scope"`
		Lifetime string   `json:"lifetime"`
	}{
		Scope: []string{gcpCloudPlatformScope}, Lifetime: "900s",
	})
	if err != nil {
		return Material{}, errors.New("cloudauth: encode GCP impersonation request")
	}
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: build GCP impersonation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", stsToken))
	raw, err := cloudhttp.Bytes(doer, req, cloudhttp.WithTimeout(30*time.Second))
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: GCP service-account impersonation: %w", err)
	}
	defer secret.Wipe(raw)

	var decoded struct {
		AccessToken secretjson.StringBytes `json:"accessToken"`
		ExpireTime  string                 `json:"expireTime"`
	}
	// Closure: the field is nil until the JSON below is decoded, so a bare defer
	// would capture that nil and wipe nothing (AN-8).
	defer func() { secret.Wipe(decoded.AccessToken) }()
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return Material{}, errors.New("cloudauth: GCP impersonation returned malformed JSON")
	}
	expiresAt, err := time.Parse(time.RFC3339, decoded.ExpireTime)
	if err != nil || len(decoded.AccessToken) == 0 {
		return Material{}, errors.New("cloudauth: GCP impersonation returned incomplete credentials")
	}
	return Material{
		Identifier: "gcp",
		Primary:    append([]byte(nil), decoded.AccessToken...),
		ExpiresAt:  expiresAt.UTC(),
	}, nil
}
