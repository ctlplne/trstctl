// SPDX-License-Identifier: BUSL-1.1

package acmekey

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// Requesting a certificate profile on the upstream order (A56,
// draft-ietf-acme-profiles).
//
// x/crypto/acme's AuthorizeOrder cannot carry a "profile" member, and its JWS
// encoder is not exported, so a profile-bearing newOrder is posted here with
// the same account key, nonce discipline and flattened JWS encoding the library
// uses. Everything after order creation (authorizations, finalize, fetch) goes
// back through the library, which only needs the order's URLs. The profile is
// requested only when the directory advertises it in meta.profiles, so a
// misspelled name fails before any order exists.

// WithProfile asks the authority to issue every order under the named
// draft-ietf-acme-profiles profile. Empty clears the request.
func (d *Driver) WithProfile(name string) *Driver {
	if d != nil {
		d.profile = strings.TrimSpace(name)
	}
	return d
}

// Profile reports the requested profile name.
func (d *Driver) Profile() string {
	if d == nil {
		return ""
	}
	return d.profile
}

// ErrProfileNotOffered is returned when the directory does not advertise the
// requested profile. No order is created.
var ErrProfileNotOffered = errors.New("acmekey: the authority does not offer the requested certificate profile")

type directoryProfiles struct {
	Meta struct {
		Profiles map[string]string `json:"profiles"`
	} `json:"meta"`
}

// offeredProfiles reads meta.profiles from the directory document.
func (d *Driver) offeredProfiles(ctx context.Context) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.client.DirectoryURL, nil)
	if err != nil {
		return nil, err
	}
	client, err := d.httpClient()
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("acmekey: directory returned status %d", res.StatusCode)
	}
	var dir directoryProfiles
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&dir); err != nil {
		return nil, fmt.Errorf("acmekey: decode directory: %w", err)
	}
	return dir.Meta.Profiles, nil
}

// httpClient is the client the authority was constructed with. A driver built
// without one cannot place a profile order: the production constructor always
// supplies the external-CA egress client, and a nil here is a wiring error,
// not a reason to reach for a process-wide default.
func (d *Driver) httpClient() (*http.Client, error) {
	if d.client == nil || d.client.HTTPClient == nil {
		return nil, errors.New("acmekey: the authority client has no HTTP client for profile orders")
	}
	return d.client.HTTPClient, nil
}

// authorizeOrder creates the order, with the requested profile when one is
// set. The returned Order carries the URLs the rest of the flow needs.
func (d *Driver) authorizeOrder(ctx context.Context, dnsNames []string) (*acme.Order, error) {
	if d.profile == "" {
		return d.client.AuthorizeOrder(ctx, acme.DomainIDs(dnsNames...))
	}
	offered, err := d.offeredProfiles(ctx)
	if err != nil {
		return nil, err
	}
	if _, ok := offered[d.profile]; !ok {
		return nil, fmt.Errorf("%w: %q", ErrProfileNotOffered, d.profile)
	}
	dir, err := d.client.Discover(ctx)
	if err != nil {
		return nil, err
	}
	type wireID struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	ids := make([]wireID, 0, len(dnsNames))
	for _, name := range dnsNames {
		ids = append(ids, wireID{Type: "dns", Value: name})
	}
	payload, err := json.Marshal(struct {
		Identifiers []wireID `json:"identifiers"`
		Profile     string   `json:"profile"`
	}{ids, d.profile})
	if err != nil {
		return nil, err
	}
	res, err := d.postJWS(ctx, dir, dir.OrderURL, payload)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusCreated {
		return nil, acmeProblem(res)
	}
	var wire struct {
		Status         string   `json:"status"`
		Expires        string   `json:"expires"`
		Identifiers    []wireID `json:"identifiers"`
		Authorizations []string `json:"authorizations"`
		Finalize       string   `json:"finalize"`
		Certificate    string   `json:"certificate"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&wire); err != nil {
		return nil, fmt.Errorf("acmekey: decode order: %w", err)
	}
	order := &acme.Order{URI: res.Header.Get("Location"), Status: wire.Status,
		AuthzURLs: wire.Authorizations, FinalizeURL: wire.Finalize, CertURL: wire.Certificate}
	if wire.Expires != "" {
		if expires, err := time.Parse(time.RFC3339, wire.Expires); err == nil {
			order.Expires = expires
		}
	}
	for _, id := range wire.Identifiers {
		order.Identifiers = append(order.Identifiers, acme.AuthzID{Type: id.Type, Value: id.Value})
	}
	if order.URI == "" || order.FinalizeURL == "" {
		return nil, errors.New("acmekey: order response carries no location or finalize URL")
	}
	return order, nil
}

// acmeProblem turns a non-2xx response into an error naming the RFC 7807
// problem type and detail, without echoing anything else from the body.
func acmeProblem(res *http.Response) error {
	var problem struct {
		Type   string `json:"type"`
		Detail string `json:"detail"`
	}
	_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&problem)
	if problem.Type == "" {
		return fmt.Errorf("acmekey: newOrder with profile returned status %d", res.StatusCode)
	}
	return fmt.Errorf("acmekey: newOrder with profile refused: %s: %s", problem.Type, problem.Detail)
}

// postJWS posts one RFC 8555 flattened JWS to url under the registered
// account (kid), fetching a fresh nonce first.
func (d *Driver) postJWS(ctx context.Context, dir acme.Directory, url string, payload []byte) (*http.Response, error) {
	kid := string(d.client.KID)
	if kid == "" {
		return nil, errors.New("acmekey: the account is not registered")
	}
	nonce, err := d.freshNonce(ctx, dir.NonceURL)
	if err != nil {
		return nil, err
	}
	alg, err := jwsAlgorithm(d.client.Key)
	if err != nil {
		return nil, err
	}
	protected, err := json.Marshal(struct {
		Alg   string `json:"alg"`
		Kid   string `json:"kid"`
		Nonce string `json:"nonce"`
		URL   string `json:"url"`
	}{alg, kid, nonce, url})
	if err != nil {
		return nil, err
	}
	protectedB64 := base64.RawURLEncoding.EncodeToString(protected)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(protectedB64 + "." + payloadB64))
	signature, err := d.client.Key.Sign(rand.Reader, digest[:], stdcrypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("acmekey: sign newOrder: %w", err)
	}
	if alg == "ES256" {
		signature, err = ecdsaDERToRaw(signature, 32)
		if err != nil {
			return nil, err
		}
	}
	body, err := json.Marshal(struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}{protectedB64, payloadB64, base64.RawURLEncoding.EncodeToString(signature)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")
	if d.client.UserAgent != "" {
		req.Header.Set("User-Agent", d.client.UserAgent)
	}
	client, err := d.httpClient()
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

func (d *Driver) freshNonce(ctx context.Context, nonceURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, nonceURL, nil)
	if err != nil {
		return "", err
	}
	client, err := d.httpClient()
	if err != nil {
		return "", err
	}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	_ = res.Body.Close()
	nonce := res.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", errors.New("acmekey: the authority returned no replay nonce")
	}
	return nonce, nil
}

// jwsAlgorithm names the JWS algorithm for the account key: ES256 for a P-256
// ECDSA key (the isolated signer's account key) and RS256 for an RSA key, both
// signed over a SHA-256 digest.
func jwsAlgorithm(key stdcrypto.Signer) (string, error) {
	if key == nil {
		return "", errors.New("acmekey: the client has no account key")
	}
	switch pub := key.Public().(type) {
	case *ecdsa.PublicKey:
		if pub.Curve.Params().BitSize != 256 {
			return "", fmt.Errorf("acmekey: profile orders support P-256 account keys, not %s", pub.Curve.Params().Name)
		}
		return "ES256", nil
	case *rsa.PublicKey:
		return "RS256", nil
	default:
		return "", errors.New("acmekey: unsupported account key type for a profile order")
	}
}

// ecdsaDERToRaw converts an ASN.1 DER ECDSA signature to the fixed-width
// R||S form JWS requires.
func ecdsaDERToRaw(der []byte, size int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("acmekey: decode ECDSA signature: %w", err)
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}
