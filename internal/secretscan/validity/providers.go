// SPDX-License-Identifier: BUSL-1.1

package validity

// P14-L1: checks for GitHub, GitLab and Slack tokens, Microsoft Entra ID
// client secrets and Google service-account keys, beside P14's AWS pairs.
//
// Each check calls the one read-only identity endpoint its provider documents:
// GitHub's GET /user (REST API, "Get the authenticated user"), GitLab's GET
// /api/v4/personal_access_tokens/self (Personal access tokens API), Slack's
// auth.test (Web API), the Microsoft identity platform's client-credentials
// token request (POST /{tenant}/oauth2/v2.0/token) and Google's OAuth 2.0
// token endpoint with a JWT-bearer assertion (OAuth 2.0 for service
// accounts). A token the identity platforms return is wiped unread.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Providers P14-L1 adds.
const (
	ProviderGitHub = "github"
	ProviderGitLab = "gitlab"
	ProviderSlack  = "slack"
	ProviderAzure  = "azure"
	ProviderGCP    = "gcp"
)

// ruleProviders maps the scanner's rule IDs (Gitleaks' default rules) to the
// provider whose check covers them. A private key is checked only when it is
// a Google service-account key.
var ruleProviders = map[string]string{
	"aws-access-token":             ProviderAWS,
	"github-pat":                   ProviderGitHub,
	"github-fine-grained-pat":      ProviderGitHub,
	"github-oauth":                 ProviderGitHub,
	"github-app-token":             ProviderGitHub,
	"gitlab-pat":                   ProviderGitLab,
	"gitlab-pat-routable":          ProviderGitLab,
	"slack-bot-token":              ProviderSlack,
	"slack-user-token":             ProviderSlack,
	"slack-legacy-bot-token":       ProviderSlack,
	"slack-legacy-token":           ProviderSlack,
	"slack-legacy-workspace-token": ProviderSlack,
	"azure-ad-client-secret":       ProviderAzure,
	"private-key":                  ProviderGCP,
}

// ProviderForRule is the provider whose check covers a scanner rule, or ""
// when none does.
func ProviderForRule(rule string) string { return ruleProviders[rule] }

// Providers lists every provider a check exists for.
func Providers() []string {
	out := make([]string, 0, len(DefaultEndpoints))
	for p := range DefaultEndpoints {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// CheckFinding checks the secret a finding of rule holds at file, line and
// column (1-based; 0 when unknown), read from the scanned tree at root. It
// reports false, with no verdict, when no check covers the rule, the rule's
// provider is not enabled, or a private key is not a Google service-account
// key.
func (c *Checker) CheckFinding(ctx context.Context, rule, root, file string, line, column int) (Result, bool) {
	provider := ProviderForRule(rule)
	if provider == "" || !c.Enabled(provider) {
		return Result{}, false
	}
	switch provider {
	case ProviderAWS:
		return c.CheckAWSFinding(ctx, root, file, line), true
	case ProviderAzure:
		return c.checkAzureFinding(ctx, root, file, line, column), true
	case ProviderGCP:
		return c.checkGCPFinding(ctx, root, file, line)
	default:
		return c.checkTokenFinding(ctx, provider, root, file, line, column), true
	}
}

var tokenPatterns = map[string]*regexp.Regexp{
	ProviderGitHub: regexp.MustCompile(`\b(?:gh[pous]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{82})\b`),
	ProviderGitLab: regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,300}(?:\.[0-9a-z]{9})?`),
	ProviderSlack:  regexp.MustCompile(`\bxox[abeoprs]-[0-9A-Za-z\-]{10,250}`),
}

// pickToken returns a copy of the match of re in text that starts nearest the
// finding's column (the first when the column is unknown).
func pickToken(text []byte, re *regexp.Regexp, column int) []byte {
	matches := re.FindAllIndex(text, -1)
	if len(matches) == 0 {
		return nil
	}
	best := matches[0]
	if column > 0 {
		distance := func(m []int) int {
			d := m[0] - (column - 1)
			if d < 0 {
				d = -d
			}
			return d
		}
		for _, m := range matches[1:] {
			if distance(m) < distance(best) {
				best = m
			}
		}
	}
	return append([]byte(nil), text[best[0]:best[1]]...)
}

func (c *Checker) checkTokenFinding(ctx context.Context, provider, root, file string, line, column int) Result {
	near, err := readNear(root, file, line, 0)
	if err != nil {
		return c.result(provider, StateUnchecked, "the finding's line could not be read")
	}
	defer secret.Wipe(near)
	token := pickToken(near, tokenPatterns[provider], column)
	if token == nil {
		return c.result(provider, StateUnchecked, "no "+providerNames[provider]+" token on the finding's line")
	}
	defer secret.Wipe(token)
	switch provider {
	case ProviderGitHub:
		return c.CheckGitHub(ctx, token)
	case ProviderGitLab:
		return c.CheckGitLab(ctx, token)
	default:
		return c.CheckSlack(ctx, token)
	}
}

// client is the configured client, never following a redirect: a check's
// token or signature reaches the declared endpoint alone (Go would carry a
// custom header such as GitLab's PRIVATE-TOKEN across one), and a redirect
// is answered as unknown.
func (c *Checker) client() *http.Client {
	cl := *c.cfg.Client
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cl
}

// do sends one check and returns the status and up to 64 KiB of the answer,
// which the caller wipes; a failed call is a verdict of its own.
func (c *Checker) do(provider string, req *http.Request) (int, []byte, *Result) {
	resp, err := c.client().Do(req)
	if err != nil {
		r := c.result(provider, StateUnknown, providerNames[provider]+" could not be reached")
		return 0, nil, &r
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, raw, nil
}

// clean bounds a provider-supplied name for a verdict: printable, at most 120
// characters.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > 120 {
		s = string(r[:120])
	}
	return s
}

func (c *Checker) answered(provider string, status int, why string) Result {
	if why = clean(why); why == "" {
		why = http.StatusText(status)
	}
	return c.result(provider, StateUnknown, providerNames[provider]+" answered "+why)
}

// CheckGitHub calls GET /user with the token (github.com or a GitHub
// Enterprise Server's /api/v3 base).
func (c *Checker) CheckGitHub(ctx context.Context, token []byte) Result {
	target := c.endpoint(ProviderGitHub) + "/user"
	if refused, ok := c.ready(ctx, ProviderGitHub, target); !ok {
		return refused
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return c.result(ProviderGitHub, StateUnchecked, "the check could not be built")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+string(token))
	status, raw, failed := c.do(ProviderGitHub, req)
	if failed != nil {
		return *failed
	}
	defer secret.Wipe(raw)
	var answer struct {
		Login   string `json:"login"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &answer)
	switch {
	case status == http.StatusOK && answer.Login != "":
		return c.result(ProviderGitHub, StateValid, "user "+clean(answer.Login))
	case status == http.StatusForbidden && strings.Contains(answer.Message, "Resource not accessible by integration"):
		// GitHub authenticated the token before refusing the call: an App
		// installation token works but has no user to name.
		return c.result(ProviderGitHub, StateValid, "a GitHub App installation token")
	case status == http.StatusUnauthorized:
		why := clean(answer.Message)
		if why == "" {
			why = "Bad credentials"
		}
		return c.result(ProviderGitHub, StateInvalid, "GitHub refused the token: "+why)
	default:
		return c.answered(ProviderGitHub, status, answer.Message)
	}
}

// CheckGitLab calls GET /api/v4/personal_access_tokens/self with the token
// (gitlab.com or a self-managed instance's base URL).
func (c *Checker) CheckGitLab(ctx context.Context, token []byte) Result {
	target := c.endpoint(ProviderGitLab) + "/api/v4/personal_access_tokens/self"
	if refused, ok := c.ready(ctx, ProviderGitLab, target); !ok {
		return refused
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return c.result(ProviderGitLab, StateUnchecked, "the check could not be built")
	}
	req.Header.Set("PRIVATE-TOKEN", string(token))
	status, raw, failed := c.do(ProviderGitLab, req)
	if failed != nil {
		return *failed
	}
	defer secret.Wipe(raw)
	var answer struct {
		ID               int64    `json:"id"`
		Name             string   `json:"name"`
		UserID           int64    `json:"user_id"`
		Active           *bool    `json:"active"`
		Revoked          bool     `json:"revoked"`
		Scopes           []string `json:"scopes"`
		Message          string   `json:"message"`
		ErrorDescription string   `json:"error_description"`
	}
	_ = json.Unmarshal(raw, &answer)
	switch {
	case status == http.StatusOK && answer.ID != 0 && (answer.Revoked || (answer.Active != nil && !*answer.Active)):
		return c.result(ProviderGitLab, StateInvalid, "GitLab reports the token revoked or inactive")
	case status == http.StatusOK && answer.ID != 0:
		return c.result(ProviderGitLab, StateValid, fmt.Sprintf("token %q of user %d (scopes %s)", clean(answer.Name), answer.UserID, clean(strings.Join(answer.Scopes, ", "))))
	case status == http.StatusUnauthorized:
		why := clean(answer.ErrorDescription)
		if why == "" {
			why = clean(answer.Message)
		}
		return c.result(ProviderGitLab, StateInvalid, "GitLab refused the token: "+why)
	default:
		return c.answered(ProviderGitLab, status, answer.Message)
	}
}

// slackRefusals are the auth.test errors that mean the token no longer works.
var slackRefusals = map[string]bool{"invalid_auth": true, "not_authed": true, "account_inactive": true, "token_revoked": true, "token_expired": true}

// CheckSlack calls auth.test with the token.
func (c *Checker) CheckSlack(ctx context.Context, token []byte) Result {
	target := c.endpoint(ProviderSlack) + "/api/auth.test"
	if refused, ok := c.ready(ctx, ProviderSlack, target); !ok {
		return refused
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, nil)
	if err != nil {
		return c.result(ProviderSlack, StateUnchecked, "the check could not be built")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+string(token))
	status, raw, failed := c.do(ProviderSlack, req)
	if failed != nil {
		return *failed
	}
	defer secret.Wipe(raw)
	var answer struct {
		OK     bool   `json:"ok"`
		Error  string `json:"error"`
		Team   string `json:"team"`
		TeamID string `json:"team_id"`
		User   string `json:"user"`
	}
	_ = json.Unmarshal(raw, &answer)
	switch {
	case status == http.StatusOK && answer.OK:
		return c.result(ProviderSlack, StateValid, "workspace "+clean(answer.Team)+" ("+clean(answer.TeamID)+"), user "+clean(answer.User))
	case status == http.StatusOK && slackRefusals[answer.Error]:
		return c.result(ProviderSlack, StateInvalid, "Slack refused the token: "+answer.Error)
	default:
		return c.answered(ProviderSlack, status, answer.Error)
	}
}

const guid = `[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}`

var (
	azureSecret = regexp.MustCompile(`[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.\-]{31,34}`)
	// A tenant and an application are found by their labels, the way an
	// environment file (AZURE_TENANT_ID, ARM_CLIENT_ID), an application
	// settings file (tenantId, clientId) or az ad sp create-for-rbac's output
	// (tenant, appId) holds them.
	azureTenant = regexp.MustCompile(`(?i)tenant(?:[_\-]?id)?["']?\s*[:=]\s*["']?(` + guid + `)`)
	azureClient = regexp.MustCompile(`(?i)(?:client|app|application)[_\-]?id["']?\s*[:=]\s*["']?(` + guid + `)`)
)

// AzureCredential finds the tenant and application IDs labeled near a client
// secret.
func AzureCredential(text []byte) (tenant, clientID string, ok bool) {
	t, a := azureTenant.FindSubmatch(text), azureClient.FindSubmatch(text)
	if t == nil || a == nil {
		return "", "", false
	}
	return strings.ToLower(string(t[1])), strings.ToLower(string(a[1])), true
}

func (c *Checker) checkAzureFinding(ctx context.Context, root, file string, line, column int) Result {
	own, err := readNear(root, file, line, 0)
	if err != nil {
		return c.result(ProviderAzure, StateUnchecked, "the finding's line could not be read")
	}
	defer secret.Wipe(own)
	clientSecret := pickToken(own, azureSecret, column)
	if clientSecret == nil {
		return c.result(ProviderAzure, StateUnchecked, "no client secret on the finding's line")
	}
	defer secret.Wipe(clientSecret)
	near, err := readNear(root, file, line, 6)
	if err != nil {
		return c.result(ProviderAzure, StateUnchecked, "the finding's line could not be read")
	}
	defer secret.Wipe(near)
	tenant, clientID, ok := AzureCredential(near)
	if !ok {
		return c.result(ProviderAzure, StateUnchecked, "no tenant and application ID beside the client secret")
	}
	return c.CheckAzure(ctx, tenant, clientID, clientSecret)
}

// queryEscape form-encodes a secret into a fresh buffer the caller wipes.
func queryEscape(value []byte) []byte {
	const hexDigits = "0123456789ABCDEF"
	out := make([]byte, 0, len(value)*3)
	for _, b := range value {
		switch {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9', b == '-', b == '.', b == '_', b == '~':
			out = append(out, b)
		default:
			out = append(out, '%', hexDigits[b>>4], hexDigits[b&15])
		}
	}
	return out
}

// azureRefusals are the identity platform's error codes that mean the client
// secret no longer works: AADSTS7000215 (not the application's secret) and
// AADSTS7000222 (expired).
var azureRefusals = map[int]string{7000215: "AADSTS7000215", 7000222: "AADSTS7000222"}

// CheckAzure requests a client-credentials token for the application in its
// tenant with the secret; the token, if one is issued, is wiped unread.
func (c *Checker) CheckAzure(ctx context.Context, tenant, clientID string, clientSecret []byte) Result {
	target := c.endpoint(ProviderAzure) + "/" + url.PathEscape(tenant) + "/oauth2/v2.0/token"
	if refused, ok := c.ready(ctx, ProviderAzure, target); !ok {
		return refused
	}
	escaped := queryEscape(clientSecret)
	form := append([]byte("grant_type=client_credentials&client_id="+url.QueryEscape(clientID)+"&scope="+
		url.QueryEscape("https://graph.microsoft.com/.default")+"&client_secret="), escaped...)
	secret.Wipe(escaped)
	defer secret.Wipe(form)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(form))
	if err != nil {
		return c.result(ProviderAzure, StateUnchecked, "the check could not be built")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	status, raw, failed := c.do(ProviderAzure, req)
	if failed != nil {
		return *failed
	}
	defer secret.Wipe(raw)
	var answer struct {
		AccessToken secret.JSONBytes `json:"access_token"`
		Error       string           `json:"error"`
		ErrorCodes  []int            `json:"error_codes"`
	}
	_ = json.Unmarshal(raw, &answer)
	defer secret.Wipe(answer.AccessToken)
	if status == http.StatusOK && len(answer.AccessToken) > 0 {
		return c.result(ProviderAzure, StateValid, "application "+clientID+" in tenant "+tenant)
	}
	if status == http.StatusBadRequest || status == http.StatusUnauthorized {
		for _, code := range answer.ErrorCodes {
			if name, refused := azureRefusals[code]; refused {
				return c.result(ProviderAzure, StateInvalid, "Microsoft Entra ID refused the secret: "+name)
			}
		}
	}
	why := answer.Error
	if len(answer.ErrorCodes) > 0 {
		why = fmt.Sprintf("%s (AADSTS%d)", answer.Error, answer.ErrorCodes[0])
	}
	return c.answered(ProviderAzure, status, why)
}

var (
	gcpServiceAccount = regexp.MustCompile(`"type"\s*:\s*"service_account"`)
	gcpEmail          = regexp.MustCompile(`"client_email"\s*:\s*"([A-Za-z0-9._%+\-]{1,128}@[A-Za-z0-9.\-]{1,128})"`)
	gcpKeyID          = regexp.MustCompile(`"private_key_id"\s*:\s*"([0-9a-fA-F]{8,64})"`)
	gcpKey            = regexp.MustCompile(`"private_key"\s*:\s*"(-----BEGIN PRIVATE KEY-----[A-Za-z0-9+/=\\ ]+-----END PRIVATE KEY-----(?:\\n)?)"`)
)

// GCPServiceAccountKey finds a Google service-account key file's account and
// its private key (PEM, the JSON's \n escapes undone) in text; the key is a
// fresh buffer the caller wipes.
func GCPServiceAccountKey(text []byte) (email, keyID string, keyPEM []byte, ok bool) {
	if !gcpServiceAccount.Match(text) {
		return "", "", nil, false
	}
	e, k := gcpEmail.FindSubmatch(text), gcpKey.FindSubmatchIndex(text)
	if e == nil || k == nil {
		return "", "", nil, false
	}
	if id := gcpKeyID.FindSubmatch(text); id != nil {
		keyID = string(id[1])
	}
	escaped := text[k[2]:k[3]]
	keyPEM = make([]byte, 0, len(escaped))
	for i := 0; i < len(escaped); i++ {
		if escaped[i] == '\\' && i+1 < len(escaped) && escaped[i+1] == 'n' {
			keyPEM = append(keyPEM, '\n')
			i++
			continue
		}
		keyPEM = append(keyPEM, escaped[i])
	}
	return string(e[1]), keyID, keyPEM, true
}

func (c *Checker) checkGCPFinding(ctx context.Context, root, file string, line int) (Result, bool) {
	near, err := readNear(root, file, line, 12)
	if err != nil {
		return Result{}, false
	}
	defer secret.Wipe(near)
	email, keyID, keyPEM, ok := GCPServiceAccountKey(near)
	if !ok {
		return Result{}, false
	}
	defer secret.Wipe(keyPEM)
	return c.CheckGCP(ctx, email, keyID, keyPEM), true
}

// gcpScope is the narrowest scope a service account may ask a token for.
const gcpScope = "https://www.googleapis.com/auth/userinfo.email"

// CheckGCP asks Google's token endpoint for a token with an assertion signed
// by the service account's key: only the signed assertion leaves the host,
// and the token, if one is issued, is wiped unread.
func (c *Checker) CheckGCP(ctx context.Context, email, keyID string, keyPEM []byte) Result {
	tokenURL := c.endpoint(ProviderGCP) + "/token"
	if refused, ok := c.ready(ctx, ProviderGCP, tokenURL); !ok {
		return refused
	}
	now := c.cfg.Now().UTC()
	assertion, err := crypto.SignJWTWithPEMKeyBytes(keyPEM, keyID, map[string]any{"iss": email, "scope": gcpScope,
		"aud": tokenURL, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()})
	if err != nil {
		return c.result(ProviderGCP, StateUnchecked, "the service account's key could not sign")
	}
	form := append([]byte("grant_type="+url.QueryEscape("urn:ietf:params:oauth:grant-type:jwt-bearer")+"&assertion="), assertion...)
	secret.Wipe(assertion)
	defer secret.Wipe(form)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader(form))
	if err != nil {
		return c.result(ProviderGCP, StateUnchecked, "the check could not be built")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	status, raw, failed := c.do(ProviderGCP, req)
	if failed != nil {
		return *failed
	}
	defer secret.Wipe(raw)
	var answer struct {
		AccessToken      secret.JSONBytes `json:"access_token"`
		Error            string           `json:"error"`
		ErrorDescription string           `json:"error_description"`
	}
	_ = json.Unmarshal(raw, &answer)
	defer secret.Wipe(answer.AccessToken)
	switch {
	case status == http.StatusOK && len(answer.AccessToken) > 0:
		return c.result(ProviderGCP, StateValid, "service account "+clean(email))
	case status == http.StatusBadRequest && answer.Error == "invalid_grant" &&
		(strings.Contains(answer.ErrorDescription, "Invalid JWT Signature") || strings.Contains(answer.ErrorDescription, "account not found")):
		return c.result(ProviderGCP, StateInvalid, "Google refused the key: "+clean(answer.ErrorDescription))
	default:
		why := answer.Error
		if answer.ErrorDescription != "" {
			why += ": " + answer.ErrorDescription
		}
		return c.answered(ProviderGCP, status, why)
	}
}

// bareTokenProviders are the providers a bare token can be checked with, in
// the order a value is matched against them.
var bareTokenProviders = []string{ProviderGitHub, ProviderGitLab, ProviderSlack}

// CheckCredential checks one static credential where an agent found it
// (P14-L2): a GitHub, GitLab or Slack token, alone or after "Bearer " or
// "token ", whose provider is enabled. It reports false, calling nothing,
// for any other value. The value is not kept.
func (c *Checker) CheckCredential(ctx context.Context, value []byte) (provider, state, detail string, ok bool) {
	v := bytes.TrimSpace(value)
	for _, scheme := range []string{"Bearer ", "bearer ", "token ", "Token "} {
		if bytes.HasPrefix(v, []byte(scheme)) {
			v = bytes.TrimSpace(v[len(scheme):])
			break
		}
	}
	for _, p := range bareTokenProviders {
		loc := tokenPatterns[p].FindIndex(v)
		if loc == nil || loc[0] != 0 || loc[1] != len(v) || !c.Enabled(p) {
			continue
		}
		token := append([]byte(nil), v...)
		defer secret.Wipe(token)
		var r Result
		switch p {
		case ProviderGitHub:
			r = c.CheckGitHub(ctx, token)
		case ProviderGitLab:
			r = c.CheckGitLab(ctx, token)
		default:
			r = c.CheckSlack(ctx, token)
		}
		return r.Provider, r.State, r.Detail, true
	}
	return "", "", "", false
}
