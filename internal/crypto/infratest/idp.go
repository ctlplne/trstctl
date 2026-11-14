// SPDX-License-Identifier: BUSL-1.1

package infratest

// Identity provider administration stand-ins (A272), plain HTTP on loopback
// as the hosted providers' tests use, each with a lockout counter: after
// LockoutThreshold wrong passwords in a row an account locks, and a right
// password resets the count.
//
// Okta (Okta Users and Authentication API references): SSWS-token POST
// /api/v1/users/{login} {"credentials":{"password":{"value"}}} sets the
// password; POST /api/v1/authn {username,password} answers 200 SUCCESS, or
// MFA_REQUIRED with a stateToken for an MFA-enrolled user, 200 LOCKED_OUT for
// a locked account, and 401 E0000004 for a wrong password; POST
// /api/v1/authn/cancel ends a pending transaction.
//
// Microsoft Entra ID (Microsoft identity platform and Graph references): POST
// /{tenant}/oauth2/v2.0/token with client_credentials issues a Graph token;
// with grant_type=password answers 200, or 400 with error_codes 50126 (wrong
// password), 50076 (MFA required after a right password) or 50053 (locked);
// PATCH /v1.0/users/{upn} {"passwordProfile":{"password"}} sets it (204).
//
// Google Workspace (Admin SDK Directory API and OAuth 2.0 for service
// accounts): POST /token with a jwt-bearer assertion signed (RS256) by the
// service account, sub the impersonated super administrator, issues a token;
// PATCH /admin/directory/v1/users/{email} {"password"} sets it.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// LockoutThreshold is the wrong passwords in a row that lock an account.
const LockoutThreshold = 5

type idpUser struct {
	password []byte
	mfa      bool
	failed   int
	locked   bool
}

// IdP is a running identity provider stand-in.
type IdP struct {
	kind string
	srv  *httptest.Server

	mu       sync.Mutex
	users    map[string]*idpUser
	drop     int
	pending  map[string]bool
	token    string // the administration credential it accepts
	clientID string
	saEmail  string
	subject  string
	saKey    *rsa.PrivateKey
	tokens   map[string]bool
	// assertions is each token request's form the Google stand-in received.
	assertions []string
}

func newIdP(kind string) *IdP {
	p := &IdP{kind: kind, users: map[string]*idpUser{}, pending: map[string]bool{}, tokens: map[string]bool{}}
	p.srv = httptest.NewServer(http.HandlerFunc(p.serve))
	return p
}

// StartOkta is an Okta org accepting apiToken as its SSWS token.
func StartOkta(apiToken string) *IdP {
	p := newIdP("okta")
	p.token = apiToken
	return p
}

// StartEntra is an Entra tenant whose application clientID authenticates
// with clientSecret.
func StartEntra(clientID, clientSecret string) *IdP {
	p := newIdP("entra")
	p.clientID, p.token = clientID, clientSecret
	return p
}

// StartGoogle is a Google Workspace domain whose service account saEmail may
// impersonate subject; ServiceAccountKeyPEM is its key.
func StartGoogle(saEmail, subject string) (*IdP, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	p := newIdP("google")
	p.saEmail, p.subject, p.saKey = saEmail, subject, key
	return p, nil
}

// StartGoogleServiceAccount is Google's token endpoint for a service account
// signing for itself (no impersonation), as a leaked key's validity check
// does (P14-L1): an assertion from saEmail with any scope issues a token, and
// one signed by another key is refused "Invalid JWT Signature."
func StartGoogleServiceAccount(saEmail string) (*IdP, error) {
	return StartGoogle(saEmail, "")
}

// Assertions is each token request's form the Google stand-in received.
func (p *IdP) Assertions() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.assertions...)
}

// ServiceAccountKeyPEM is the Google service account's private key (PKCS#8).
func (p *IdP) ServiceAccountKeyPEM() []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(p.saKey)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// AddUser adds an account; mfa makes a right password lead to an MFA step.
func (p *IdP) AddUser(name, password string, mfa bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users[strings.ToLower(name)] = &idpUser{password: []byte(password), mfa: mfa}
}

// Password is an account's current password.
func (p *IdP) Password(name string) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if u, ok := p.users[strings.ToLower(name)]; ok {
		return append([]byte(nil), u.password...)
	}
	return nil
}

// Failed and Locked report an account's wrong passwords in a row and
// whether it locked.
func (p *IdP) Failed(name string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if u, ok := p.users[strings.ToLower(name)]; ok {
		return u.failed
	}
	return 0
}

func (p *IdP) Locked(name string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	u, ok := p.users[strings.ToLower(name)]
	return ok && u.locked
}

// Pending counts sign-in transactions left waiting for an MFA step.
func (p *IdP) Pending() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pending)
}

// DropNextChanges makes the next n password changes succeed but keep the
// old password.
func (p *IdP) DropNextChanges(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.drop = n
}

// URL is the stand-in's root (Okta org, Graph and login host, or the Admin
// SDK and token host).
func (p *IdP) URL() string { return p.srv.URL }

// Close stops it.
func (p *IdP) Close() { p.srv.Close() }

func randomToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// signIn checks a password against the lockout counter.
func (p *IdP) signIn(name, password string) (ok, mfa, locked bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	u, found := p.users[strings.ToLower(name)]
	switch {
	case !found:
		return false, false, false
	case u.locked:
		return false, false, true
	case string(u.password) != password:
		u.failed++
		if u.failed >= LockoutThreshold {
			u.locked = true
		}
		return false, false, false
	}
	u.failed = 0
	return true, u.mfa, false
}

func (p *IdP) setPassword(name, password string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	u, ok := p.users[strings.ToLower(name)]
	if !ok {
		return false
	}
	if p.drop > 0 {
		p.drop--
		return true
	}
	u.password = []byte(password)
	return true
}

func writeIdPJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (p *IdP) bearerOK(r *http.Request) bool {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tokens[token]
}

func (p *IdP) serve(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	switch p.kind {
	case "okta":
		p.okta(w, r)
	case "entra":
		p.entra(w, r)
	case "google":
		p.google(w, r)
	}
}

func (p *IdP) okta(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/authn":
		var body struct{ Username, Password string }
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			writeIdPJSON(w, http.StatusBadRequest, map[string]string{"errorCode": "E0000003"})
			return
		}
		ok, mfa, locked := p.signIn(body.Username, body.Password)
		switch {
		case locked:
			writeIdPJSON(w, http.StatusOK, map[string]string{"status": "LOCKED_OUT"})
		case !ok:
			writeIdPJSON(w, http.StatusUnauthorized, map[string]string{"errorCode": "E0000004", "errorSummary": "Authentication failed"})
		case mfa:
			state := randomToken()
			p.mu.Lock()
			p.pending[state] = true
			p.mu.Unlock()
			writeIdPJSON(w, http.StatusOK, map[string]string{"status": "MFA_REQUIRED", "stateToken": state})
		default:
			writeIdPJSON(w, http.StatusOK, map[string]string{"status": "SUCCESS", "sessionToken": randomToken()})
		}
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/authn/cancel":
		var body struct {
			StateToken string `json:"stateToken"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		p.mu.Lock()
		delete(p.pending, body.StateToken)
		p.mu.Unlock()
		writeIdPJSON(w, http.StatusOK, map[string]string{"status": "UNAUTHENTICATED"})
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/users/"):
		if r.Header.Get("Authorization") != "SSWS "+p.token {
			writeIdPJSON(w, http.StatusUnauthorized, map[string]string{"errorCode": "E0000011"})
			return
		}
		var body struct {
			Credentials struct {
				Password struct {
					Value string `json:"value"`
				} `json:"password"`
			} `json:"credentials"`
		}
		login := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Credentials.Password.Value == "" {
			writeIdPJSON(w, http.StatusBadRequest, map[string]string{"errorCode": "E0000001"})
			return
		}
		if !p.setPassword(login, body.Credentials.Password.Value) {
			writeIdPJSON(w, http.StatusNotFound, map[string]string{"errorCode": "E0000007"})
			return
		}
		writeIdPJSON(w, http.StatusOK, map[string]any{"status": "ACTIVE", "profile": map[string]string{"login": login}})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (p *IdP) entra(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
		if r.ParseForm() != nil || r.PostForm.Get("client_id") != p.clientID || r.PostForm.Get("client_secret") != p.token {
			writeIdPJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client", "error_codes": []int{7000215}})
			return
		}
		switch r.PostForm.Get("grant_type") {
		case "client_credentials":
			token := randomToken()
			p.mu.Lock()
			p.tokens[token] = true
			p.mu.Unlock()
			writeIdPJSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3599})
		case "password":
			ok, mfa, locked := p.signIn(r.PostForm.Get("username"), r.PostForm.Get("password"))
			switch {
			case locked:
				writeIdPJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_codes": []int{50053}})
			case !ok:
				writeIdPJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_codes": []int{50126}})
			case mfa:
				writeIdPJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_codes": []int{50076}})
			default:
				writeIdPJSON(w, http.StatusOK, map[string]any{"access_token": randomToken(), "token_type": "Bearer"})
			}
		default:
			writeIdPJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
		}
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/v1.0/users/"):
		if !p.bearerOK(r) {
			writeIdPJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "InvalidAuthenticationToken"}})
			return
		}
		var body struct {
			PasswordProfile struct {
				Password string `json:"password"`
			} `json:"passwordProfile"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.PasswordProfile.Password == "" {
			writeIdPJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "Request_BadRequest"}})
			return
		}
		if !p.setPassword(strings.TrimPrefix(r.URL.Path, "/v1.0/users/"), body.PasswordProfile.Password) {
			writeIdPJSON(w, http.StatusNotFound, map[string]any{"error": map[string]string{"code": "Request_ResourceNotFound"}})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (p *IdP) google(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/token":
		parseErr := r.ParseForm()
		p.mu.Lock()
		p.assertions = append(p.assertions, r.PostForm.Encode())
		p.mu.Unlock()
		if parseErr != nil || r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || !p.assertionOK(r.PostForm.Get("assertion")) {
			writeIdPJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
			return
		}
		token := randomToken()
		p.mu.Lock()
		p.tokens[token] = true
		p.mu.Unlock()
		writeIdPJSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600})
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/admin/directory/v1/users/"):
		if !p.bearerOK(r) {
			writeIdPJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{"code": 401}})
			return
		}
		var body struct {
			Password string `json:"password"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Password == "" {
			writeIdPJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": 400}})
			return
		}
		email := strings.TrimPrefix(r.URL.Path, "/admin/directory/v1/users/")
		if !p.setPassword(email, body.Password) {
			writeIdPJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": 404}})
			return
		}
		writeIdPJSON(w, http.StatusOK, map[string]string{"primaryEmail": email})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// assertionOK verifies a service account's RS256 assertion and its claims.
func (p *IdP) assertionOK(assertion string) bool {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&p.saKey.PublicKey, crypto.SHA256, digest[:], sig) != nil {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Iss, Sub, Scope, Aud string
	}
	if json.Unmarshal(raw, &claims) != nil {
		return false
	}
	if p.subject == "" {
		// A service account signing for itself (P14-L1).
		return claims.Iss == p.saEmail && (claims.Sub == "" || claims.Sub == p.saEmail) && claims.Aud == p.srv.URL+"/token" && claims.Scope != ""
	}
	return claims.Iss == p.saEmail && claims.Sub == p.subject && claims.Aud == p.srv.URL+"/token" &&
		strings.Contains(claims.Scope, "https://www.googleapis.com/auth/admin.directory.user")
}
