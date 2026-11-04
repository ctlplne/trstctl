// SPDX-License-Identifier: BUSL-1.1

// Package kvdisable disables one Azure Key Vault certificate version (N2). Key
// Vault cannot revoke a certificate — only its issuing CA can — so this is the
// strongest action trstctl can take there: the version stops being served to
// the applications that read it from the vault, while the certificate stays
// valid until it expires or its CA revokes it. Every caller labels the result
// "disabled, not revoked". Discovery (kvdisc) never writes to a vault; this is
// the one explicit write, with its own write-capable credential.
package kvdisable

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/netsec"
)

const defaultAPIVersion = "7.4"

// Config names the vault and the write credential.
type Config struct {
	Token      cloudcert.TokenProvider
	HTTPClient *http.Client
	APIVersion string
}

// Target is one certificate version, by its Key Vault id
// (https://<vault>/certificates/<name>/<version>).
type Target struct {
	VaultURL string
	Name     string
	Version  string
}

// ParseCertificateID reads a Key Vault certificate id. Only an exact version is
// a target: disabling "the certificate" would disable whatever version is
// current when the call lands.
func ParseCertificateID(id string) (Target, error) {
	u, err := url.Parse(strings.TrimSpace(id))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return Target{}, errors.New("kvdisable: a Key Vault certificate id is https://<vault>/certificates/<name>/<version>")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "certificates" || !validSegment(parts[1]) || !validSegment(parts[2]) {
		return Target{}, errors.New("kvdisable: a Key Vault certificate id names one certificate version")
	}
	return Target{VaultURL: "https://" + strings.ToLower(u.Host), Name: parts[1], Version: parts[2]}, nil
}

func validSegment(s string) bool {
	if s == "" || len(s) > 127 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// Result is what the vault says after the write: the version read back.
type Result struct {
	Enabled bool
	Updated time.Time
}

type attributes struct {
	Enabled *bool  `json:"enabled,omitempty"`
	Updated *int64 `json:"updated,omitempty"`
}

type bundle struct {
	ID         string     `json:"id"`
	Attributes attributes `json:"attributes"`
}

// Disable disables one certificate version and reads it back; it succeeds only
// when the vault reports that exact version disabled.
func Disable(ctx context.Context, cfg Config, t Target) (Result, error) {
	if cfg.Token == nil {
		return Result{}, errors.New("kvdisable: a write credential is required")
	}
	if cfg.APIVersion == "" {
		cfg.APIVersion = defaultAPIVersion
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.HardenedClient(30 * time.Second)
	}
	path := t.VaultURL + "/certificates/" + url.PathEscape(t.Name) + "/" + url.PathEscape(t.Version) + "?api-version=" + cfg.APIVersion
	disabled := false
	body, err := json.Marshal(map[string]any{"attributes": attributes{Enabled: &disabled}})
	if err != nil {
		return Result{}, err
	}
	var patched bundle
	if err := call(ctx, cfg, http.MethodPatch, path, body, &patched); err != nil {
		return Result{}, err
	}
	var read bundle
	if err := call(ctx, cfg, http.MethodGet, path, nil, &read); err != nil {
		return Result{}, err
	}
	if read.Attributes.Enabled == nil || *read.Attributes.Enabled {
		return Result{}, errors.New("kvdisable: the vault does not read the certificate version back as disabled")
	}
	if !strings.HasSuffix(strings.TrimRight(read.ID, "/"), "/certificates/"+t.Name+"/"+t.Version) {
		return Result{}, errors.New("kvdisable: the vault answered for another certificate version")
	}
	out := Result{Enabled: false}
	if read.Attributes.Updated != nil {
		out.Updated = time.Unix(*read.Attributes.Updated, 0).UTC()
	}
	return out, nil
}

func call(ctx context.Context, cfg Config, method, target string, body []byte, out any) error {
	token, err := cfg.Token.Token(ctx)
	if err != nil {
		return fmt.Errorf("kvdisable: token: %w", err)
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("kvdisable: %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		// The vault's error body can echo request details; report the status only.
		return fmt.Errorf("kvdisable: %s returned HTTP %d", method, resp.StatusCode)
	}
	return json.Unmarshal(raw, out)
}
