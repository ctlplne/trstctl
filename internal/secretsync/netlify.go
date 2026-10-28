// SPDX-License-Identifier: BUSL-1.1

package secretsync

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
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secrettext"
)

// DefaultNetlifyEndpoint is Netlify's API base.
const DefaultNetlifyEndpoint = "https://api.netlify.com/api/v1"

// NetlifyConfig configures a Netlify environment-variable destination (A202).
// Netlify addresses environment variables by account (team), optionally for
// one site; changes apply on the site's next deploy.
type NetlifyConfig struct {
	Endpoint   string
	HTTPClient HTTPDoer
	Token      []byte
	AccountID  string
	SiteID     string
	// Context is the deploy context the value applies to; empty is "all".
	Context string
	// Scopes for a variable this target creates; empty is builds, functions
	// and runtime.
	Scopes []string
}

// NetlifyPusher sets a secret environment variable's value, creating the
// variable (as a secret) when it does not exist.
type NetlifyPusher struct {
	endpoint  string
	doer      HTTPDoer
	token     *secret.Buffer
	accountID string
	siteID    string
	context   string
	scopes    []string
}

var netlifyContexts = map[string]bool{"all": true, "dev": true, "dev-server": true, "branch-deploy": true, "deploy-preview": true, "production": true}

var netlifyScopes = map[string]bool{"builds": true, "functions": true, "runtime": true, "post-processing": true}

// ValidateNetlifyTarget checks the context and scopes the API accepts.
func ValidateNetlifyTarget(context string, scopes []string) error {
	if context = strings.TrimSpace(context); context != "" && !netlifyContexts[context] {
		return fmt.Errorf("secretsync: netlify context %q is not all, dev, dev-server, branch-deploy, deploy-preview or production", context)
	}
	for _, scope := range scopes {
		if !netlifyScopes[strings.TrimSpace(scope)] {
			return fmt.Errorf("secretsync: netlify scope %q is not builds, functions, runtime or post-processing", scope)
		}
	}
	return nil
}

func NewNetlifyPusher(cfg NetlifyConfig) (*NetlifyPusher, error) {
	if strings.TrimSpace(cfg.AccountID) == "" || len(cfg.Token) == 0 {
		return nil, errors.New("secretsync: netlify account id and token are required")
	}
	if err := ValidateNetlifyTarget(cfg.Context, cfg.Scopes); err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if endpoint == "" {
		endpoint = DefaultNetlifyEndpoint
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = netsec.HardenedClient(30 * time.Second)
	}
	token, err := lockOptionalSecret(cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("secretsync: lock netlify token: %w", err)
	}
	context := strings.TrimSpace(cfg.Context)
	if context == "" {
		context = "all"
	}
	scopes := make([]string, 0, len(cfg.Scopes))
	for _, scope := range cfg.Scopes {
		scopes = append(scopes, strings.TrimSpace(scope))
	}
	if len(scopes) == 0 {
		scopes = []string{"builds", "functions", "runtime"}
	}
	return &NetlifyPusher{endpoint: endpoint, doer: doer, token: token, accountID: strings.TrimSpace(cfg.AccountID),
		siteID: strings.TrimSpace(cfg.SiteID), context: context, scopes: scopes}, nil
}

func (p *NetlifyPusher) url(path string) string {
	u := p.endpoint + "/accounts/" + pathEscape(p.accountID) + "/env" + path
	if p.siteID != "" {
		u += "?site_id=" + url.QueryEscape(p.siteID)
	}
	return u
}

func (p *NetlifyPusher) request(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.url(path), reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", secretBufferBytes(p.token)))
	return req, nil
}

// Push reads the variable first: an existing one gets the value for the
// target's context (PATCH); a missing one is created as a secret with the
// configured scopes and that contextual value (POST).
func (p *NetlifyPusher) Push(ctx context.Context, key string, value []byte) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("secretsync: netlify variable key is required")
	}
	if !utf8.Valid(value) {
		return errors.New("secretsync: netlify variable values are text; the secret must be UTF-8")
	}
	get, err := p.request(ctx, http.MethodGet, "/"+pathEscape(key), nil)
	if err != nil {
		return err
	}
	exists, err := netlifyVariableExists(p.doer, get)
	if err != nil {
		return err
	}
	var body []byte
	var req *http.Request
	if exists {
		body = append(body, `{"context":`...)
		body = appendJSONValueBytes(body, []byte(p.context))
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, '}')
		req, err = p.request(ctx, http.MethodPatch, "/"+pathEscape(key), body)
	} else {
		scopes, marshalErr := json.Marshal(p.scopes)
		if marshalErr != nil {
			return marshalErr
		}
		body = append(body, `[{"key":`...)
		body = appendJSONValueBytes(body, []byte(key))
		body = append(body, `,"scopes":`...)
		body = append(body, scopes...)
		body = append(body, `,"values":[{"value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, `,"context":`...)
		body = appendJSONValueBytes(body, []byte(p.context))
		body = append(body, `}],"is_secret":true}]`...)
		req, err = p.request(ctx, http.MethodPost, "", body)
	}
	defer secret.Wipe(body)
	if err != nil {
		return err
	}
	return expect2xx(p.doer, req)
}

// netlifyVariableExists is the read before a write: 200 is present, 404 is
// absent, anything else fails the delivery.
func netlifyVariableExists(doer HTTPDoer, req *http.Request) (bool, error) {
	resp, err := doer.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("secretsync: netlify variable read returned %d", resp.StatusCode)
	}
}

func (p *NetlifyPusher) Close() { destroySecretBuffer(&p.token) }
