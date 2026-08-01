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
)

const azureJWTBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)

// AzureExchangeRequest is the thin Entra federated-credential encoder input.
// SubjectToken is the already-validated OIDC proof accepted by the Entra app's
// federated-credential binding. It stays mutable authority bytes.
type AzureExchangeRequest struct {
	Endpoint     string
	ClientID     string
	Scope        string
	SubjectToken []byte
}

// ExchangeAzureFederatedCredential exchanges one validated OIDC proof through
// the Entra OAuth client-credentials endpoint. It performs no retry and no
// caching; the bounded outbox and shared Minter own those jobs.
func ExchangeAzureFederatedCredential(ctx context.Context, doer cloudhttp.Doer, in AzureExchangeRequest) (Material, error) {
	if doer == nil {
		return Material{}, errors.New("cloudauth: reviewed Azure HTTP client is required")
	}
	if in.Endpoint == "" || in.ClientID == "" || in.Scope == "" || len(in.SubjectToken) == 0 {
		return Material{}, errors.New("cloudauth: Azure endpoint, client ID, scope, and subject token are required")
	}

	body := make([]byte, 0, len(in.SubjectToken)+len(in.ClientID)+len(in.Scope)+240)
	body = appendForm(body, "grant_type", []byte("client_credentials"))
	body = appendForm(body, "client_id", []byte(in.ClientID))
	body = appendForm(body, "scope", []byte(in.Scope))
	body = appendForm(body, "client_assertion_type", []byte(azureJWTBearerAssertionType))
	body = appendForm(body, "client_assertion", in.SubjectToken)
	defer secret.Wipe(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.Endpoint, bytes.NewReader(body))
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: build Azure token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	raw, err := cloudhttp.Bytes(doer, req, cloudhttp.WithTimeout(30*time.Second))
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: Azure token exchange: %w", err)
	}
	defer secret.Wipe(raw)
	return parseAzureTokenResponse(raw, time.Now().UTC())
}

type azureTokenResponse struct {
	AccessToken secretjson.StringBytes `json:"access_token"`
	TokenType   string                 `json:"token_type"`
	ExpiresIn   int64                  `json:"expires_in"`
}

func parseAzureTokenResponse(raw []byte, now time.Time) (Material, error) {
	var decoded azureTokenResponse
	defer secret.Wipe(decoded.AccessToken)
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return Material{}, errors.New("cloudauth: Azure token endpoint returned malformed JSON")
	}
	if len(decoded.AccessToken) == 0 || decoded.TokenType != "Bearer" ||
		decoded.ExpiresIn < 1 || decoded.ExpiresIn > 86400 {
		return Material{}, errors.New("cloudauth: Azure token endpoint returned incomplete credentials")
	}
	return Material{
		Identifier: "azure",
		Primary:    append([]byte(nil), decoded.AccessToken...),
		ExpiresAt:  now.UTC().Add(time.Duration(decoded.ExpiresIn) * time.Second),
	}, nil
}
