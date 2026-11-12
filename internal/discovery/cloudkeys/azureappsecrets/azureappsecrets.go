// SPDX-License-Identifier: BUSL-1.1

// Package azureappsecrets reads a Microsoft Entra tenant's app-registration
// client secrets with their age, expiry and last sign-in (M3-L2), the Azure
// counterpart of awsiamkeys: a secret nobody has signed in with in 90 days
// stands out.
package azureappsecrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	defaultEndpoint = "https://graph.microsoft.com"
	maxBody         = 4 << 20
	// MaxSecrets bounds one enumeration.
	MaxSecrets = 10000
	maxPages   = 1000
)

// StaleAfter is how long a secret goes without signing in before it is
// flagged, as for AWS access keys.
const StaleAfter = 90 * 24 * time.Hour

// Config configures the reader. Token is a Microsoft Graph token allowed to
// read applications (Application.Read.All) and app credential sign-in
// activity (AuditLog.Read.All, a premium directory feature).
type Config struct {
	Endpoint   string
	Token      []byte
	HTTPClient *http.Client
	Now        func() time.Time
}

// Secret is one app registration's client secret. Its value and hint are
// never read.
type Secret struct {
	Application string
	AppID       string
	KeyID       string
	Name        string
	Created     time.Time
	Expires     *time.Time
	// LastSignIn is the secret's last sign-in Entra recorded; nil when it
	// recorded none. LastUseKnown is false when the sign-in activity could
	// not be read, so a missing use is not taken for non-use.
	LastSignIn   *time.Time
	LastUseKnown bool
}

// Status is Active or Expired.
func (s Secret) Status(now time.Time) string {
	if s.Expires != nil && !now.Before(*s.Expires) {
		return "Expired"
	}
	return "Active"
}

// Unused is how long the secret has gone without a sign-in at now: since its
// last sign-in, or since it was created when it never signed in.
func (s Secret) Unused(now time.Time) time.Duration {
	since := s.Created
	if s.LastSignIn != nil {
		since = *s.LastSignIn
	}
	if since.IsZero() || now.Before(since) {
		return 0
	}
	return now.Sub(since)
}

// Stale reports an active secret that has not signed in for StaleAfter,
// once its last use is known.
func (s Secret) Stale(now time.Time) bool {
	return s.Status(now) == "Active" && s.LastUseKnown && s.Unused(now) >= StaleAfter
}

// Result is one enumeration. LastUseError says why the secrets' last
// sign-in could not be read; the secrets are still listed.
type Result struct {
	Secrets      []Secret
	LastUseError error
}

// Reader reads one tenant's app-registration secrets.
type Reader struct {
	cfg   Config
	host  string
	token *secret.Buffer
}

// New builds a reader.
func New(cfg Config) (*Reader, error) {
	if len(cfg.Token) == 0 {
		return nil, errors.New("azureappsecrets: a token is required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = defaultEndpoint
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" {
		return nil, errors.New("azureappsecrets: bad endpoint")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.HardenedClient(30 * time.Second)
	}
	token, err := secret.NewFrom(cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("azureappsecrets: lock token: %w", err)
	}
	return &Reader{cfg: cfg, host: u.Host, token: token}, nil
}

// Close wipes the token.
func (r *Reader) Close() {
	if r.token != nil {
		r.token.Destroy()
		r.token = nil
	}
}

type applicationsPage struct {
	Value []struct {
		ID                  string `json:"id"`
		AppID               string `json:"appId"`
		DisplayName         string `json:"displayName"`
		PasswordCredentials []struct {
			KeyID         string    `json:"keyId"`
			DisplayName   string    `json:"displayName"`
			StartDateTime time.Time `json:"startDateTime"`
			EndDateTime   time.Time `json:"endDateTime"`
		} `json:"passwordCredentials"`
	} `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

type signInsPage struct {
	Value []struct {
		KeyID          string `json:"keyId"`
		SignInActivity struct {
			LastSignInDateTime time.Time `json:"lastSignInDateTime"`
		} `json:"signInActivity"`
	} `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

// Secrets lists every app registration's client secrets, applications in
// name order, at most MaxSecrets, with each secret's last sign-in.
func (r *Reader) Secrets(ctx context.Context) (Result, error) {
	var out []Secret
	next := "/v1.0/applications?$select=id,appId,displayName,passwordCredentials&$top=100"
	for page := 0; next != ""; page++ {
		if page == maxPages {
			return Result{}, errors.New("azureappsecrets: too many application pages")
		}
		var resp applicationsPage
		if err := r.get(ctx, next, &resp); err != nil {
			return Result{}, fmt.Errorf("azureappsecrets: list applications: %w", err)
		}
		for _, app := range resp.Value {
			for _, c := range app.PasswordCredentials {
				if c.KeyID == "" {
					continue
				}
				s := Secret{Application: app.DisplayName, AppID: app.AppID, KeyID: c.KeyID, Name: c.DisplayName, Created: c.StartDateTime.UTC()}
				if !c.EndDateTime.IsZero() {
					expires := c.EndDateTime.UTC()
					s.Expires = &expires
				}
				out = append(out, s)
				if len(out) > MaxSecrets {
					return Result{}, fmt.Errorf("azureappsecrets: more than %d secrets", MaxSecrets)
				}
			}
		}
		var err error
		if next, err = r.nextPath(resp.NextLink); err != nil {
			return Result{}, err
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Application != out[j].Application {
			return out[i].Application < out[j].Application
		}
		return out[i].KeyID < out[j].KeyID
	})
	last, err := r.lastSignIns(ctx)
	if err != nil {
		return Result{Secrets: out, LastUseError: err}, nil
	}
	for i := range out {
		out[i].LastUseKnown = true
		if t, ok := last[out[i].KeyID]; ok {
			at := t
			out[i].LastSignIn = &at
		}
	}
	return Result{Secrets: out}, nil
}

// lastSignIns reads Entra's last sign-in per credential key ID.
func (r *Reader) lastSignIns(ctx context.Context) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	next := "/beta/reports/appCredentialSignInActivities?$top=1000"
	for page := 0; next != ""; page++ {
		if page == maxPages {
			return nil, errors.New("azureappsecrets: too many sign-in activity pages")
		}
		var resp signInsPage
		if err := r.get(ctx, next, &resp); err != nil {
			return nil, fmt.Errorf("azureappsecrets: read credential sign-in activity: %w", err)
		}
		for _, a := range resp.Value {
			t := a.SignInActivity.LastSignInDateTime
			if a.KeyID == "" || t.IsZero() {
				continue
			}
			if prev, ok := out[a.KeyID]; !ok || t.After(prev) {
				out[a.KeyID] = t.UTC()
			}
		}
		var err error
		if next, err = r.nextPath(resp.NextLink); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// nextPath follows an @odata.nextLink only on the endpoint's own host, so a
// response cannot send the token elsewhere.
func (r *Reader) nextPath(link string) (string, error) {
	if link == "" {
		return "", nil
	}
	u, err := url.Parse(link)
	if err != nil || (u.Host != "" && u.Host != r.host) {
		return "", errors.New("azureappsecrets: a next page link leaves the Graph endpoint")
	}
	return u.RequestURI(), nil
}

// StatusError is a Graph answer other than 200, without its body.
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("status %d", e.Code) }

func (r *Reader) get(ctx context.Context, p string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(r.cfg.Endpoint, "/")+p, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", r.token.Bytes()))
	req.Header.Set("Accept", "application/json")
	resp, err := r.cfg.HTTPClient.Do(req)
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
