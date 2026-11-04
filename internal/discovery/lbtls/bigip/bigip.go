// SPDX-License-Identifier: BUSL-1.1

// Package bigip reads an F5 BIG-IP's virtual servers and the client SSL
// profiles they present (X4) through read-only iControl REST GETs:
// /mgmt/tm/ltm/virtual?expandSubcollections=true and
// /mgmt/tm/ltm/profile/client-ssl. A virtual server allows the versions its
// client SSL profile's options leave enabled — no-tlsv1, no-tlsv1.1,
// no-tlsv1.2 and no-tlsv1.3 each turn one off. The profile's cipher string can
// narrow them further; a TLS scan of the virtual address shows what actually
// negotiates. It changes nothing.
package bigip

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/discovery/lbtls"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	maxBody  = 8 << 20
	maxPages = 1000
)

// Config is one BIG-IP's read-only access: a user and password (basic
// authentication) or an iControl REST token.
type Config struct {
	BaseURL            string
	Username, Password string
	Token              string
	HTTPClient         *http.Client
}

// Reader reads one BIG-IP.
type Reader struct {
	cfg  Config
	base *url.URL
}

// New builds a reader.
func New(cfg Config) (*Reader, error) {
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/"))
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") || base.User != nil {
		return nil, fmt.Errorf("bigip: base URL must be an http(s) URL without credentials")
	}
	if cfg.Token == "" && (cfg.Username == "" || cfg.Password == "") {
		return nil, fmt.Errorf("bigip: a token or a user and password is required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.HardenedClient(30 * time.Second)
	}
	return &Reader{cfg: cfg, base: base}, nil
}

type profile struct {
	FullPath    string `json:"fullPath"`
	TMOptions   string `json:"tmOptions"`
	Ciphers     string `json:"ciphers"`
	CipherGroup string `json:"cipherGroup"`
}

type virtual struct {
	FullPath          string `json:"fullPath"`
	Destination       string `json:"destination"`
	ProfilesReference struct {
		Items []struct {
			FullPath string `json:"fullPath"`
			Context  string `json:"context"`
		} `json:"items"`
	} `json:"profilesReference"`
}

// Listeners lists every virtual server that presents a client SSL profile,
// one entry per virtual server and profile, in reference order, at most
// lbtls.MaxListeners.
func (r *Reader) Listeners(ctx context.Context) ([]lbtls.Listener, error) {
	profiles := map[string]profile{}
	if err := r.paged(ctx, "/mgmt/tm/ltm/profile/client-ssl", func(raw []byte) (string, error) {
		var page struct {
			Items    []profile `json:"items"`
			NextLink string    `json:"nextLink"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return "", err
		}
		for _, p := range page.Items {
			profiles[p.FullPath] = p
		}
		return page.NextLink, nil
	}); err != nil {
		return nil, err
	}
	var out []lbtls.Listener
	if err := r.paged(ctx, "/mgmt/tm/ltm/virtual?expandSubcollections=true", func(raw []byte) (string, error) {
		var page struct {
			Items    []virtual `json:"items"`
			NextLink string    `json:"nextLink"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return "", err
		}
		for _, v := range page.Items {
			for _, ref := range v.ProfilesReference.Items {
				p, ok := profiles[ref.FullPath]
				if !ok || ref.Context == "serverside" || len(out) >= lbtls.MaxListeners {
					continue
				}
				out = append(out, lbtls.Listener{LoadBalancer: v.FullPath, Ref: v.FullPath + "@" + p.FullPath,
					Port: destinationPort(v.Destination), Protocol: "clientside", Policy: p.FullPath,
					Protocols: AllowedProtocols(p.TMOptions), Ciphers: cipherString(p)})
			}
		}
		return page.NextLink, nil
	}); err != nil {
		return nil, err
	}
	lbtls.SortListeners(out)
	return out, nil
}

// AllowedProtocols reads a client SSL profile's options: TLS 1.0 through 1.3,
// less each one a no-tlsv* option turns off.
func AllowedProtocols(tmOptions string) []string {
	off := map[string]bool{}
	for _, opt := range strings.Fields(strings.NewReplacer("{", " ", "}", " ").Replace(tmOptions)) {
		switch strings.ToLower(opt) {
		case "no-tlsv1":
			off["TLSv1.0"] = true
		case "no-tlsv1.1":
			off["TLSv1.1"] = true
		case "no-tlsv1.2":
			off["TLSv1.2"] = true
		case "no-tlsv1.3":
			off["TLSv1.3"] = true
		}
	}
	var on []string
	for _, v := range []string{"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"} {
		if !off[v] {
			on = append(on, v)
		}
	}
	return on
}

func cipherString(p profile) []string {
	var out []string
	if c := strings.TrimSpace(p.Ciphers); c != "" && c != "none" {
		out = append(out, c)
	}
	if g := strings.TrimSpace(p.CipherGroup); g != "" && g != "none" {
		out = append(out, "group "+g)
	}
	return out
}

// destinationPort reads the port of a virtual destination such as
// /Common/10.0.0.10:443, /Common/10.0.0.10%2:443 or /Common/2001:db8::10.443.
func destinationPort(dest string) int {
	d := dest[strings.LastIndex(dest, "/")+1:]
	var raw string
	if strings.Count(d, ":") == 1 {
		raw = d[strings.LastIndex(d, ":")+1:]
	} else if i := strings.LastIndex(d, "."); i >= 0 {
		raw = d[i+1:]
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > 65535 {
		return 0
	}
	return n
}

// paged GETs a collection across its nextLink pages. BIG-IP writes nextLink
// against its own name (often https://localhost/...), so only its path and
// query are followed, always against the configured base URL.
func (r *Reader) paged(ctx context.Context, pathAndQuery string, page func([]byte) (string, error)) error {
	next := pathAndQuery
	for i := 0; i < maxPages && next != ""; i++ {
		raw, err := r.get(ctx, next)
		if err != nil {
			return err
		}
		link, err := page(raw)
		if err != nil {
			return fmt.Errorf("bigip: %s: decode response: %w", pathAndQuery, err)
		}
		next = ""
		if link != "" {
			u, err := url.Parse(link)
			if err != nil || !strings.HasPrefix(u.Path, "/mgmt/tm/ltm/") {
				return fmt.Errorf("bigip: %s: next page link is not a collection page", pathAndQuery)
			}
			next = u.EscapedPath()
			if u.RawQuery != "" {
				next += "?" + u.RawQuery
			}
		}
	}
	if next != "" {
		return fmt.Errorf("bigip: %s: more than %d pages", pathAndQuery, maxPages)
	}
	return nil
}

func (r *Reader) get(ctx context.Context, pathAndQuery string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.base.String()+pathAndQuery, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if r.cfg.Token != "" {
		req.Header.Set("X-F5-Auth-Token", r.cfg.Token)
	} else {
		req.Header.Set("Authorization", r.basicAuth())
	}
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bigip: GET %s: %w", strings.SplitN(pathAndQuery, "?", 2)[0], err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("bigip: read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("bigip: GET %s: status %d (response body redacted)", strings.SplitN(pathAndQuery, "?", 2)[0], resp.StatusCode)
	}
	return raw, nil
}

// basicAuth keeps the user and password byte-backed until the base64 header
// value crosses into a string at net/http's wire boundary.
func (r *Reader) basicAuth() string {
	raw := make([]byte, 0, len(r.cfg.Username)+1+len(r.cfg.Password))
	raw = append(raw, r.cfg.Username...)
	raw = append(raw, ':')
	raw = append(raw, r.cfg.Password...)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(encoded, raw)
	secret.Wipe(raw)
	defer secret.Wipe(encoded)
	return secrettext.Prefixed("Basic ", encoded)
}
