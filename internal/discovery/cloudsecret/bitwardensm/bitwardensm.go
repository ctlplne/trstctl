// SPDX-License-Identifier: BUSL-1.1

// Package bitwardensm inventories the secrets a Bitwarden Secrets Manager
// machine account can read (OD-13): each secret's name, projects and dates.
// Secrets Manager stores names, values and notes encrypted on the client, so
// the machine account's access token is both its credential and the key
// that opens the organization key: the run signs in at the identity service,
// opens the encrypted payload it returns, and decrypts names with the
// organization key (internal/crypto/bwsm). The listing carries no values; with
// content inspection the values are fetched in batches, decrypted,
// inspected and wiped. Keys are destroyed when the run ends.
package bitwardensm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto/bwsm"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/netsec"
)

// ProviderName is the discovery provider identifier.
const ProviderName = "bitwarden-secrets-manager"

const (
	defaultAPIURL      = "https://api.bitwarden.com"
	defaultIdentityURL = "https://identity.bitwarden.com"
	valueBatch         = 50
)

// Config configures one Secrets Manager inventory. AccessToken is the
// machine account's access token; BaseURL is the API and IdentityURL the
// identity service (both default to Bitwarden's cloud; a self-hosted server
// serves them under /api and /identity).
type Config struct {
	BaseURL        string
	IdentityURL    string
	AccessToken    cloudcert.TokenProvider
	NamePrefix     string
	InspectContent bool
	// GenericHighEntropy adds the opt-in generic high-entropy rule to
	// content inspection (A172-L4); it has no effect without
	// InspectContent.
	GenericHighEntropy bool
	HTTPClient         *http.Client
	Retry              cloudcert.RetryPolicy
}

// Enumerator is a read-only Secrets Manager source.
type Enumerator struct {
	cfg  Config
	host string
}

// New builds a Secrets Manager enumerator.
func New(cfg Config) (*Enumerator, error) {
	if cfg.AccessToken == nil {
		return nil, errors.New("bitwarden-secrets-manager: token_ref (the machine account's access token) is required")
	}
	var host string
	for _, target := range []*string{&cfg.BaseURL, &cfg.IdentityURL} {
		*target = strings.TrimRight(strings.TrimSpace(*target), "/")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultAPIURL
	}
	if cfg.IdentityURL == "" {
		cfg.IdentityURL = defaultIdentityURL
	}
	for i, raw := range []string{cfg.BaseURL, cfg.IdentityURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("bitwarden-secrets-manager: bad endpoint %q", raw)
		}
		if i == 0 {
			host = u.Host
		}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.SafeClient(30 * time.Second)
	}
	if cfg.Retry.Max == 0 && cfg.Retry.Base == 0 {
		cfg.Retry = cloudcert.DefaultRetry()
	}
	return &Enumerator{cfg: cfg, host: host}, nil
}

// Name identifies the provider.
func (e *Enumerator) Name() string { return ProviderName }

type session struct {
	bearer string
	org    string
	key    *bwsm.Key
}

type projectRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type listedSecret struct {
	ID           string       `json:"id"`
	Key          string       `json:"key"`
	CreationDate string       `json:"creationDate"`
	RevisionDate string       `json:"revisionDate"`
	Projects     []projectRef `json:"projects"`
}

// Enumerate lists every secret the machine account can read as a metadata
// finding and, with content inspection, inspects each value.
func (e *Enumerator) Enumerate(ctx context.Context) ([]cloudsecret.Found, error) {
	s, err := e.signIn(ctx)
	if err != nil {
		return nil, err
	}
	defer s.key.Destroy()
	raw, err := e.call(ctx, s, http.MethodGet, "/organizations/"+url.PathEscape(s.org)+"/secrets", nil)
	if err != nil {
		return nil, fmt.Errorf("bitwarden-secrets-manager: list secrets: %w", err)
	}
	var listing struct {
		Secrets  []listedSecret `json:"secrets"`
		Projects []projectRef   `json:"projects"`
	}
	if err := json.Unmarshal(raw, &listing); err != nil {
		return nil, fmt.Errorf("bitwarden-secrets-manager: parse secrets: %w", err)
	}
	projectNames := map[string]string{}
	for _, p := range listing.Projects {
		projectNames[p.ID] = e.openName(s.key, p.Name)
	}
	type entry struct {
		id, name, resource, location string
	}
	var out []cloudsecret.Found
	var selected []entry
	sort.Slice(listing.Secrets, func(i, j int) bool { return listing.Secrets[i].ID < listing.Secrets[j].ID })
	for _, item := range listing.Secrets {
		name := e.openName(s.key, item.Key)
		if e.cfg.NamePrefix != "" && !strings.HasPrefix(name, e.cfg.NamePrefix) {
			continue
		}
		var projectIDs, names []string
		for _, p := range item.Projects {
			projectIDs = append(projectIDs, p.ID)
			if n := projectNames[p.ID]; n != "" {
				names = append(names, n)
			} else {
				names = append(names, e.openName(s.key, p.Name))
			}
		}
		location := s.org
		if len(projectIDs) > 0 {
			location = s.org + "/" + projectIDs[0]
		}
		resource := "bitwarden-sm://" + e.host + "/organizations/" + s.org + "/secrets/" + item.ID
		out = append(out, cloudsecret.MetadataFound(ProviderName, resource, name, location, resource, map[string]string{
			"secret_name": name, "resource_id": resource, "secret_id": item.ID, "organization": s.org,
			"projects": strings.Join(projectIDs, ","), "project_names": strings.Join(names, ","),
			"created_at": item.CreationDate, "updated_at": item.RevisionDate, "content_inspected": "false",
		}))
		selected = append(selected, entry{id: item.ID, name: name, resource: resource, location: location})
	}
	if !e.cfg.InspectContent {
		return out, nil
	}
	for start := 0; start < len(selected); start += valueBatch {
		batch := selected[start:min(start+valueBatch, len(selected))]
		ids := make([]string, 0, len(batch))
		for _, b := range batch {
			ids = append(ids, b.id)
		}
		values, err := e.values(ctx, s, ids)
		if err != nil {
			return nil, err
		}
		for _, b := range batch {
			value := values[b.id]
			if len(value) == 0 {
				continue
			}
			found, err := cloudsecret.InspectSecret(ProviderName, cloudsecret.Secret{
				GenericHighEntropy: e.cfg.GenericHighEntropy,
				Name:               b.name, ResourceID: b.resource, Location: b.location, Provenance: b.resource, Value: value,
				Fields: []cloudsecret.SecretField{{Name: b.name, Value: value}},
				Metadata: map[string]string{
					"secret_name": b.name, "resource_id": b.resource, "secret_id": b.id, "content_inspected": "true",
				},
			})
			if err != nil {
				wipeValues(values)
				return nil, err
			}
			out = append(out, found...)
		}
		wipeValues(values)
	}
	return out, nil
}

func wipeValues(values map[string][]byte) {
	for _, v := range values {
		secret.Wipe(v)
	}
}

// openName decrypts a name; a name that does not open under the key is
// reported as such rather than failing the run.
func (e *Enumerator) openName(key *bwsm.Key, encrypted string) string {
	if encrypted == "" {
		return ""
	}
	plain, err := key.Decrypt(encrypted)
	if err != nil {
		return "(name does not decrypt)"
	}
	defer secret.Wipe(plain)
	return string(plain)
}

// values fetches and decrypts a batch of values by secret ID; the caller
// wipes them.
func (e *Enumerator) values(ctx context.Context, s *session, ids []string) (map[string][]byte, error) {
	request, err := json.Marshal(map[string][]string{"ids": ids})
	if err != nil {
		return nil, err
	}
	raw, err := e.call(ctx, s, http.MethodPost, "/secrets/get-by-ids", request)
	if err != nil {
		return nil, fmt.Errorf("bitwarden-secrets-manager: get secrets by id: %w", err)
	}
	var resp struct {
		Data []struct {
			ID    string `json:"id"`
			Value string `json:"value"`
		} `json:"data"`
	}
	err = json.Unmarshal(raw, &resp)
	secret.Wipe(raw)
	if err != nil {
		return nil, fmt.Errorf("bitwarden-secrets-manager: parse secret values: %w", err)
	}
	out := make(map[string][]byte, len(resp.Data))
	for _, item := range resp.Data {
		if item.Value == "" {
			continue
		}
		plain, err := s.key.Decrypt(item.Value)
		if err != nil {
			wipeValues(out)
			return nil, fmt.Errorf("bitwarden-secrets-manager: value of %s does not decrypt under the organization key", item.ID)
		}
		out[item.ID] = plain
	}
	return out, nil
}

// signIn exchanges the access token at the identity service for a bearer
// token and the encrypted payload, opens the payload with the token's key
// to get the organization key, and reads the organization from the bearer
// token's organization claim.
func (e *Enumerator) signIn(ctx context.Context) (*session, error) {
	rawToken, err := e.cfg.AccessToken.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("bitwarden-secrets-manager: access token: %w", err)
	}
	token, err := bwsm.ParseAccessToken([]byte(rawToken))
	if err != nil {
		return nil, fmt.Errorf("bitwarden-secrets-manager: %w", err)
	}
	defer token.Destroy()
	form := url.Values{"scope": {"api.secrets"}, "client_id": {token.ID}, "grant_type": {"client_credentials"}}
	encoded := appendFormEscaped([]byte(form.Encode()+"&client_secret="), token.ClientSecret.Bytes())
	defer secret.Wipe(encoded)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.IdentityURL+"/connect/token", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/json")
	raw, err := cloudcert.Fetch(ctx, e.cfg.HTTPClient, req, encoded, e.cfg.Retry)
	if err != nil {
		return nil, fmt.Errorf("bitwarden-secrets-manager: sign in: %w", statusOnly(err))
	}
	defer secret.Wipe(raw)
	var resp struct {
		AccessToken      string `json:"access_token"`
		EncryptedPayload string `json:"encrypted_payload"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || resp.AccessToken == "" || resp.EncryptedPayload == "" {
		return nil, errors.New("bitwarden-secrets-manager: sign in returned no access token or encrypted payload")
	}
	org, err := organizationClaim(resp.AccessToken)
	if err != nil {
		return nil, err
	}
	tokenKey, err := token.TokenKey()
	if err != nil {
		return nil, err
	}
	defer tokenKey.Destroy()
	payload, err := tokenKey.Decrypt(resp.EncryptedPayload)
	if err != nil {
		return nil, errors.New("bitwarden-secrets-manager: the encrypted payload does not open with the access token's key")
	}
	defer secret.Wipe(payload)
	var body struct {
		EncryptionKey secretB64 `json:"encryptionKey"`
	}
	err = json.Unmarshal(payload, &body)
	defer secret.Wipe(body.EncryptionKey)
	if err != nil || len(body.EncryptionKey) == 0 {
		return nil, errors.New("bitwarden-secrets-manager: the payload carries no organization key")
	}
	key, err := bwsm.KeyFromBytes(body.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("bitwarden-secrets-manager: organization key: %w", err)
	}
	return &session{bearer: resp.AccessToken, org: org, key: key}, nil
}

// appendFormEscaped form-encodes src onto dst byte by byte, so the client
// secret never becomes a Go string.
func appendFormEscaped(dst, src []byte) []byte {
	const hexDigits = "0123456789ABCDEF"
	for _, c := range src {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == '.', c == '_', c == '~':
			dst = append(dst, c)
		default:
			dst = append(dst, '%', hexDigits[c>>4], hexDigits[c&15])
		}
	}
	return dst
}

// secretB64 decodes a base64 JSON string into bytes the caller wipes.
type secretB64 []byte

func (b *secretB64) UnmarshalJSON(raw []byte) error {
	raw = bytes.Trim(raw, `"`)
	out := make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
	n, err := base64.StdEncoding.Decode(out, raw)
	if err != nil {
		secret.Wipe(out)
		return err
	}
	*b = out[:n]
	return nil
}

// organizationClaim reads the organization claim of the bearer token (a JWT
// the identity service just issued over TLS; the API checks its signature).
func organizationClaim(bearer string) (string, error) {
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return "", errors.New("bitwarden-secrets-manager: the access token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", errors.New("bitwarden-secrets-manager: the access token's claims do not decode")
	}
	var claims struct {
		Organization json.RawMessage `json:"organization"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", errors.New("bitwarden-secrets-manager: the access token's claims do not parse")
	}
	var org string
	if err := json.Unmarshal(claims.Organization, &org); err != nil {
		var orgs []string
		if json.Unmarshal(claims.Organization, &orgs) != nil || len(orgs) != 1 {
			return "", errors.New("bitwarden-secrets-manager: the access token names no single organization")
		}
		org = orgs[0]
	}
	id, err := uuid.Parse(org)
	if err != nil {
		return "", errors.New("bitwarden-secrets-manager: the organization claim is not a UUID")
	}
	return id.String(), nil
}

// statusOnly keeps a refused request's status but not its body.
func statusOnly(err error) error {
	msg := err.Error()
	if strings.HasPrefix(msg, "cloudcert: status ") {
		if i := strings.Index(msg[len("cloudcert: status "):], ":"); i > 0 {
			return errors.New(msg[:len("cloudcert: status ")+i])
		}
	}
	return err
}

func (e *Enumerator) call(ctx context.Context, s *session, method, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, e.cfg.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.bearer)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return cloudcert.Fetch(ctx, e.cfg.HTTPClient, req, body, e.cfg.Retry)
}
