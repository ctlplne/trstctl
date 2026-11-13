// SPDX-License-Identifier: BUSL-1.1

// Package conjur inventories the variables of a CyberArk Conjur (Open
// Source) account (OD-13): each variable's ID, owner, policy, annotations
// and how many versions it holds. Conjur's resource listing never carries a
// value, so a metadata-only run never receives one; with content inspection
// each variable that holds a value is read once, inspected and wiped. A
// host or user signs in with its API key for a short-lived access token.
package conjur

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
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/netsec"
)

// ProviderName is the discovery provider identifier.
const ProviderName = "conjur"

const (
	pageSize = 100
	maxPages = 100
)

// Config configures one Conjur inventory. BaseURL is the Conjur server
// (required: Conjur is self-hosted), Account the Conjur account and Login the
// role that signs in ("host/<id>" or a user name) with its API key.
// PathPrefix narrows the inventory to variable IDs under a policy path.
type Config struct {
	BaseURL        string
	Account        string
	Login          string
	APIKey         cloudcert.TokenProvider
	PathPrefix     string
	NamePrefix     string
	InspectContent bool
	// GenericHighEntropy adds the opt-in generic high-entropy rule to
	// content inspection (A172-L4); it has no effect without
	// InspectContent.
	GenericHighEntropy bool
	HTTPClient         *http.Client
	Retry              cloudcert.RetryPolicy
}

// Enumerator is a read-only Conjur variable source.
type Enumerator struct {
	cfg  Config
	host string
}

// New builds a Conjur enumerator.
func New(cfg Config) (*Enumerator, error) {
	cfg.Account, cfg.Login = strings.TrimSpace(cfg.Account), strings.TrimSpace(cfg.Login)
	if cfg.Account == "" || cfg.Login == "" || cfg.APIKey == nil {
		return nil, errors.New("conjur: account, login and api_key_ref are required")
	}
	if strings.ContainsAny(cfg.Account, "/:?#") {
		return nil, fmt.Errorf("conjur: account %q must not contain / : ? or #", cfg.Account)
	}
	cfg.PathPrefix = strings.Trim(strings.TrimSpace(cfg.PathPrefix), "/")
	for _, part := range strings.Split(cfg.PathPrefix, "/") {
		if cfg.PathPrefix != "" && (part == "" || part == "." || part == "..") {
			return nil, fmt.Errorf("conjur: path_prefix %q is not a clean policy path", cfg.PathPrefix)
		}
	}
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if cfg.BaseURL == "" {
		return nil, errors.New("conjur: endpoint is required (the Conjur server URL)")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("conjur: bad endpoint %q", cfg.BaseURL)
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.SafeClient(30 * time.Second)
	}
	if cfg.Retry.Max == 0 && cfg.Retry.Base == 0 {
		cfg.Retry = cloudcert.DefaultRetry()
	}
	return &Enumerator{cfg: cfg, host: u.Host}, nil
}

// Name identifies the provider.
func (e *Enumerator) Name() string { return ProviderName }

type annotation struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type secretVersion struct {
	Version   int64  `json:"version"`
	ExpiresAt string `json:"expires_at"`
}

type resource struct {
	ID          string          `json:"id"`
	Owner       string          `json:"owner"`
	Policy      string          `json:"policy"`
	CreatedAt   string          `json:"created_at"`
	Annotations []annotation    `json:"annotations"`
	Secrets     []secretVersion `json:"secrets"`
}

// Enumerate lists every variable in scope as a metadata finding and, with
// content inspection, inspects the current value of each that holds one.
func (e *Enumerator) Enumerate(ctx context.Context) ([]cloudsecret.Found, error) {
	token, err := e.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(token)
	variables, err := e.variables(ctx, token)
	if err != nil {
		return nil, err
	}
	var out []cloudsecret.Found
	for _, v := range variables {
		path := strings.TrimPrefix(v.ID, e.cfg.Account+":variable:")
		if e.cfg.NamePrefix != "" && !strings.HasPrefix(lastSegment(path), e.cfg.NamePrefix) {
			continue
		}
		resourceID := "conjur://" + e.host + "/" + e.cfg.Account + "/variable/" + path
		latest := int64(0)
		for _, s := range v.Secrets {
			if s.Version > latest {
				latest = s.Version
			}
		}
		meta := map[string]string{
			"secret_name": path, "resource_id": resourceID, "account": e.cfg.Account, "owner": v.Owner,
			"policy": v.Policy, "versions": strconv.Itoa(len(v.Secrets)), "latest_version": strconv.FormatInt(latest, 10),
			"created_at": v.CreatedAt, "content_inspected": "false",
		}
		names := make([]string, 0, len(v.Annotations))
		for _, a := range v.Annotations {
			names = append(names, a.Name)
			if a.Name == "conjur/kind" || a.Name == "conjur/mime_type" {
				meta[strings.ReplaceAll(a.Name, "/", "_")] = a.Value
			}
		}
		sort.Strings(names)
		meta["annotations"] = strings.Join(names, ",")
		if e.cfg.InspectContent && len(v.Secrets) == 0 {
			meta["content_unavailable_reason"] = "no value: the variable holds no version"
		}
		out = append(out, cloudsecret.MetadataFound(ProviderName, resourceID, path, e.cfg.Account, resourceID, meta))
		if !e.cfg.InspectContent || len(v.Secrets) == 0 {
			continue
		}
		found, err := e.inspect(ctx, token, path, resourceID)
		if err != nil {
			return nil, err
		}
		out = append(out, found...)
	}
	return out, nil
}

func lastSegment(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// inspect reads one variable's current value, inspects it and wipes it.
func (e *Enumerator) inspect(ctx context.Context, token []byte, path, resourceID string) ([]cloudsecret.Found, error) {
	value, err := e.get(ctx, token, "/secrets/"+url.PathEscape(e.cfg.Account)+"/variable/"+escapeIdentifier(path), "")
	if err != nil {
		return nil, fmt.Errorf("conjur: read variable %s: %w", path, err)
	}
	defer secret.Wipe(value)
	return cloudsecret.InspectSecret(ProviderName, cloudsecret.Secret{
		GenericHighEntropy: e.cfg.GenericHighEntropy,
		Name:               path, ResourceID: resourceID, Location: e.cfg.Account, Provenance: resourceID, Value: value,
		Fields: []cloudsecret.SecretField{{Name: lastSegment(path), Value: value}},
		Metadata: map[string]string{
			"secret_name": path, "resource_id": resourceID, "account": e.cfg.Account, "content_inspected": "true",
		},
	})
}

// escapeIdentifier escapes each segment of a variable ID; the slashes
// between segments stay, as Conjur's route takes the identifier as a path.
func escapeIdentifier(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// variables lists the account's variables the role can see, page by page.
func (e *Enumerator) variables(ctx context.Context, token []byte) ([]resource, error) {
	var out []resource
	for page := 0; page < maxPages; page++ {
		q := url.Values{"kind": {"variable"}, "limit": {strconv.Itoa(pageSize)}, "offset": {strconv.Itoa(page * pageSize)}}
		if e.cfg.PathPrefix != "" {
			q.Set("search", e.cfg.PathPrefix)
		}
		raw, err := e.get(ctx, token, "/resources/"+url.PathEscape(e.cfg.Account)+"?"+q.Encode(), "application/json")
		if err != nil {
			return nil, fmt.Errorf("conjur: list variables: %w", err)
		}
		var batch []resource
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, fmt.Errorf("conjur: parse variables: %w", err)
		}
		for _, r := range batch {
			path := strings.TrimPrefix(r.ID, e.cfg.Account+":variable:")
			if path == r.ID {
				continue // not one of this account's variables
			}
			if e.cfg.PathPrefix != "" && path != e.cfg.PathPrefix && !strings.HasPrefix(path, e.cfg.PathPrefix+"/") {
				continue // search matches anywhere in the ID; keep only the subtree
			}
			out = append(out, r)
		}
		if len(batch) < pageSize {
			sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
			return out, nil
		}
	}
	return nil, fmt.Errorf("conjur: more than %d variables; narrow path_prefix", pageSize*maxPages)
}

// authenticate exchanges the API key for an access token, which Conjur
// returns base64-encoded when asked to; it is the value of every later
// request's Authorization header and is wiped after the run.
func (e *Enumerator) authenticate(ctx context.Context) ([]byte, error) {
	apiKey, err := e.cfg.APIKey.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("conjur: api key: %w", err)
	}
	body := []byte(strings.TrimSpace(apiKey))
	defer secret.Wipe(body)
	target := e.cfg.BaseURL + "/authn/" + url.PathEscape(e.cfg.Account) + "/" + url.PathEscape(e.cfg.Login) + "/authenticate"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Accept-Encoding", "base64")
	raw, err := cloudcert.Fetch(ctx, e.cfg.HTTPClient, req, body, e.cfg.Retry)
	if err != nil {
		return nil, fmt.Errorf("conjur: authenticate %s: %w", e.cfg.Login, statusOnly(err))
	}
	token := bytes.TrimSpace(raw)
	if len(token) == 0 {
		return nil, errors.New("conjur: authenticate returned no token")
	}
	if bytes.HasPrefix(token, []byte("{")) {
		// A server that ignored Accept-Encoding returned the raw token JSON.
		encoded := make([]byte, base64.StdEncoding.EncodedLen(len(token)))
		base64.StdEncoding.Encode(encoded, token)
		secret.Wipe(raw)
		return encoded, nil
	}
	out := append([]byte(nil), token...)
	secret.Wipe(raw)
	return out, nil
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

func (e *Enumerator) get(ctx context.Context, token []byte, path, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.cfg.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", `Token token="`+string(token)+`"`)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	return cloudcert.Fetch(ctx, e.cfg.HTTPClient, req, nil, e.cfg.Retry)
}
