// SPDX-License-Identifier: BUSL-1.1

// Package gcpsakeys reads a Google Cloud project's user-managed
// service-account keys with their age and last authentication (M3-L1), the
// GCP counterpart of awsiamkeys: a key nobody has authenticated with in 90
// days stands out.
package gcpsakeys

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	defaultEndpoint         = "https://iam.googleapis.com"
	defaultActivityEndpoint = "https://policyanalyzer.googleapis.com"
	maxBody                 = 4 << 20
	// MaxKeys bounds one enumeration.
	MaxKeys = 10000
	// maxPages bounds every paged listing.
	maxPages = 1000
)

// StaleAfter is how long a key goes without authenticating before it is
// flagged, as for AWS access keys.
const StaleAfter = 90 * 24 * time.Hour

// Config configures the reader. Token is the bearer token of an identity
// that may list the project's service accounts and keys (iam.serviceAccounts.list,
// iam.serviceAccountKeys.list) and query Policy Analyzer's activity
// (policyanalyzer.serviceAccountKeyLastAuthenticationActivities.query).
type Config struct {
	Endpoint           string
	ActivityEndpoint   string
	Project            string
	Token              []byte
	HTTPClient         *http.Client
	ActivityHTTPClient *http.Client
	Now                func() time.Time
}

// Key is one user-managed service-account key.
type Key struct {
	ServiceAccount string
	KeyID          string
	// Disabled is the key's or its service account's.
	Disabled bool
	Created  time.Time
	Expires  *time.Time
	// LastAuthenticated is the key's last authentication Policy Analyzer
	// observed; nil when it observed none. LastUseKnown is false when
	// Policy Analyzer could not be read, so a missing use is not taken for
	// non-use.
	LastAuthenticated *time.Time
	LastUseKnown      bool
}

// Status reads as IAM would: Active, Disabled, or Expired.
func (k Key) Status(now time.Time) string {
	switch {
	case k.Disabled:
		return "Disabled"
	case k.Expires != nil && !now.Before(*k.Expires):
		return "Expired"
	default:
		return "Active"
	}
}

// Unused is how long the key has gone without authenticating at now: since
// its last authentication, or since it was created when it never did.
func (k Key) Unused(now time.Time) time.Duration {
	since := k.Created
	if k.LastAuthenticated != nil {
		since = *k.LastAuthenticated
	}
	if since.IsZero() || now.Before(since) {
		return 0
	}
	return now.Sub(since)
}

// Stale reports an active key that has not authenticated for StaleAfter,
// once its last use is known.
func (k Key) Stale(now time.Time) bool {
	return k.Status(now) == "Active" && k.LastUseKnown && k.Unused(now) >= StaleAfter
}

// Result is one enumeration. LastUseError says why the keys' last
// authentication could not be read; the keys are still listed.
type Result struct {
	Keys         []Key
	LastUseError error
}

// Reader reads one project's service-account keys.
type Reader struct {
	cfg   Config
	token *secret.Buffer
}

// New builds a reader.
func New(cfg Config) (*Reader, error) {
	if strings.TrimSpace(cfg.Project) == "" || len(cfg.Token) == 0 {
		return nil, errors.New("gcpsakeys: project and token are required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = defaultEndpoint
	}
	if cfg.ActivityEndpoint == "" {
		cfg.ActivityEndpoint = defaultActivityEndpoint
	}
	for _, e := range []string{cfg.Endpoint, cfg.ActivityEndpoint} {
		if u, err := url.Parse(e); err != nil || u.Host == "" {
			return nil, errors.New("gcpsakeys: bad endpoint")
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.HardenedClient(30 * time.Second)
	}
	if cfg.ActivityHTTPClient == nil {
		cfg.ActivityHTTPClient = cfg.HTTPClient
	}
	token, err := secret.NewFrom(cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("gcpsakeys: lock token: %w", err)
	}
	return &Reader{cfg: cfg, token: token}, nil
}

// Close wipes the token.
func (r *Reader) Close() {
	if r.token != nil {
		r.token.Destroy()
		r.token = nil
	}
}

type serviceAccountsPage struct {
	Accounts []struct {
		Email    string `json:"email"`
		Disabled bool   `json:"disabled"`
	} `json:"accounts"`
	NextPageToken string `json:"nextPageToken"`
}

type keysPage struct {
	Keys []struct {
		Name            string    `json:"name"`
		ValidAfterTime  time.Time `json:"validAfterTime"`
		ValidBeforeTime time.Time `json:"validBeforeTime"`
		Disabled        bool      `json:"disabled"`
	} `json:"keys"`
}

type activitiesPage struct {
	Activities []struct {
		FullResourceName string `json:"fullResourceName"`
		Activity         struct {
			LastAuthenticatedTime time.Time `json:"lastAuthenticatedTime"`
		} `json:"activity"`
	} `json:"activities"`
	NextPageToken string `json:"nextPageToken"`
}

// Keys lists every service account's user-managed keys, accounts in email
// order, at most MaxKeys, with each key's last authentication.
func (r *Reader) Keys(ctx context.Context) (Result, error) {
	project := url.PathEscape(strings.TrimSpace(r.cfg.Project))
	var emails []string
	disabled := map[string]bool{}
	for page, token := 0, ""; ; page++ {
		if page == maxPages {
			return Result{}, errors.New("gcpsakeys: too many service account pages")
		}
		q := url.Values{"pageSize": {"100"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var out serviceAccountsPage
		if err := r.get(ctx, r.cfg.HTTPClient, r.cfg.Endpoint, "/v1/projects/"+project+"/serviceAccounts?"+q.Encode(), &out); err != nil {
			return Result{}, fmt.Errorf("gcpsakeys: list service accounts: %w", err)
		}
		for _, a := range out.Accounts {
			if a.Email == "" {
				continue
			}
			emails = append(emails, a.Email)
			disabled[a.Email] = a.Disabled
		}
		if token = out.NextPageToken; token == "" {
			break
		}
	}
	sort.Strings(emails)
	var keys []Key
	for _, email := range emails {
		var out keysPage
		if err := r.get(ctx, r.cfg.HTTPClient, r.cfg.Endpoint, "/v1/projects/"+project+"/serviceAccounts/"+url.PathEscape(email)+"/keys?keyTypes=USER_MANAGED", &out); err != nil {
			return Result{}, fmt.Errorf("gcpsakeys: list keys of %s: %w", email, err)
		}
		for _, k := range out.Keys {
			id := path.Base(k.Name)
			if id == "" || id == "." || id == "/" {
				continue
			}
			key := Key{ServiceAccount: email, KeyID: id, Disabled: k.Disabled || disabled[email], Created: k.ValidAfterTime.UTC()}
			if !k.ValidBeforeTime.IsZero() {
				expires := k.ValidBeforeTime.UTC()
				key.Expires = &expires
			}
			keys = append(keys, key)
			if len(keys) > MaxKeys {
				return Result{}, fmt.Errorf("gcpsakeys: more than %d keys", MaxKeys)
			}
		}
	}
	last, err := r.lastAuthentications(ctx, project)
	if err != nil {
		return Result{Keys: keys, LastUseError: err}, nil
	}
	for i := range keys {
		keys[i].LastUseKnown = true
		if t, ok := last[keys[i].KeyID]; ok {
			at := t
			keys[i].LastAuthenticated = &at
		}
	}
	return Result{Keys: keys}, nil
}

// lastAuthentications reads Policy Analyzer's last authentication per key ID.
func (r *Reader) lastAuthentications(ctx context.Context, project string) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	for page, token := 0, ""; ; page++ {
		if page == maxPages {
			return nil, errors.New("gcpsakeys: too many activity pages")
		}
		q := url.Values{"pageSize": {"1000"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var resp activitiesPage
		p := "/v1/projects/" + project + "/locations/global/activityTypes/serviceAccountKeyLastAuthentication/activities:query?" + q.Encode()
		if err := r.get(ctx, r.cfg.ActivityHTTPClient, r.cfg.ActivityEndpoint, p, &resp); err != nil {
			return nil, fmt.Errorf("gcpsakeys: read key last authentication: %w", err)
		}
		for _, a := range resp.Activities {
			id := path.Base(a.FullResourceName)
			if id == "" || a.Activity.LastAuthenticatedTime.IsZero() {
				continue
			}
			if prev, ok := out[id]; !ok || a.Activity.LastAuthenticatedTime.After(prev) {
				out[id] = a.Activity.LastAuthenticatedTime.UTC()
			}
		}
		if token = resp.NextPageToken; token == "" {
			return out, nil
		}
	}
}

// StatusError is a Google API answer other than 200, without its body.
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("status %d", e.Code) }

func (r *Reader) get(ctx context.Context, client *http.Client, endpoint, p string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+p, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", r.token.Bytes()))
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxBody {
		return errors.New("response too large")
	}
	if resp.StatusCode != http.StatusOK {
		return &StatusError{Code: resp.StatusCode}
	}
	return json.NewDecoder(bytes.NewReader(body)).Decode(out)
}
