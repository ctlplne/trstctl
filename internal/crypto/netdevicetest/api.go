// SPDX-License-Identifier: BUSL-1.1

package netdevicetest

// HTTPS management API stand-ins (A270 part 2), each the documented subset
// that account rotation and discovery use:
//
// Arista EOS eAPI (EOS command API guide): JSON-RPC 2.0 "runCmds" at
// POST /command-api with HTTP basic authentication; each command is a string
// or {"cmd", "input"} (enable's password); "format" json or text (text
// results are {"output"}); a failing command ends the request with error
// 1002. A privilege-15 account with exec authorization starts privileged.
// Commands: enable, disable, configure, end, `username NAME [privilege N]
// [role ROLE] secret 0 PASSWORD` (omitted attributes reset, so the caller
// must restate them), `enable password 0 PASSWORD`,
// `copy running-config startup-config`, `show running-config section
// username` (text only), `show version`.
//
// FortiGate REST API (FortiOS administration guide, REST API): an API
// administrator's token as "Authorization: Bearer"; GET and PUT
// /api/v2/cmdb/system/admin[/NAME] ({"password"} on PUT); the session
// sign-in POST /logincheck (form username, secretkey) answering "1" with a
// ccsrftoken cookie on success and "0" on failure; POST /logout.
//
// F5 BIG-IP iControl REST (F5 iControl REST API reference): POST
// /mgmt/shared/authn/login {"username","password","loginProviderName":"tmos"}
// returns {"token":{"token"}}, sent back as X-F5-Auth-Token; DELETE
// /mgmt/shared/authz/tokens/TOKEN; GET /mgmt/tm/auth/user; PATCH
// /mgmt/tm/auth/user/NAME {"password"}; POST /mgmt/tm/sys/config
// {"command":"save"}.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// API dialects.
const (
	EOS     Dialect = "eos"
	FortiOS Dialect = "fortios"
	BIGIP   Dialect = "bigip"
)

type apiAccount struct {
	password []byte
	level    string // EOS privilege, FortiOS access profile, BIG-IP role
	role     string // EOS role
}

// APIDevice is a running HTTPS stand-in.
type APIDevice struct {
	dialect Dialect
	srv     *httptest.Server

	mu       sync.Mutex
	accounts map[string]*apiAccount
	enable   []byte
	apiAdmin string
	apiToken string
	tokens   map[string]string // BIG-IP token -> user
	sessions map[string]string // FortiOS session cookie -> user
	drop     int
	saves    int
	revision int
}

// StartAPI brings up a stand-in of dialect. The administrator signs in with
// credential (EOS, BIG-IP) or, on FortiOS, is a REST API administrator whose
// token is credential. level is its privilege, access profile or role.
func StartAPI(dialect Dialect, admin, credential, level string) (*APIDevice, error) {
	if dialect != EOS && dialect != FortiOS && dialect != BIGIP {
		return nil, errors.New("netdevicetest: unknown API dialect")
	}
	d := &APIDevice{dialect: dialect, accounts: map[string]*apiAccount{}, tokens: map[string]string{}, sessions: map[string]string{}}
	if dialect == FortiOS {
		d.apiAdmin, d.apiToken = admin, credential
		d.accounts[admin] = &apiAccount{level: level}
	} else {
		d.accounts[admin] = &apiAccount{password: []byte(credential), level: level}
	}
	d.srv = httptest.NewTLSServer(http.HandlerFunc(d.serveHTTP))
	return d, nil
}

// AddAccount sets an account's password, level and (EOS) role.
func (d *APIDevice) AddAccount(name, password, level, role string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.accounts[name] = &apiAccount{password: []byte(password), level: level, role: role}
}

// SetEnableSecret sets EOS's enable password.
func (d *APIDevice) SetEnableSecret(secret string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.enable = []byte(secret)
}

// Password returns an account's current password.
func (d *APIDevice) Password(name string) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	if a, ok := d.accounts[name]; ok {
		return append([]byte(nil), a.password...)
	}
	return nil
}

// EnableSecret returns EOS's enable password.
func (d *APIDevice) EnableSecret() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]byte(nil), d.enable...)
}

// Level returns an account's privilege, access profile or role.
func (d *APIDevice) Level(name string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if a, ok := d.accounts[name]; ok {
		return a.level
	}
	return ""
}

// Role returns an EOS account's role.
func (d *APIDevice) Role(name string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if a, ok := d.accounts[name]; ok {
		return a.role
	}
	return ""
}

// DropNextChanges makes the next n password changes report success but keep
// the old password, as a device whose change did not take effect.
func (d *APIDevice) DropNextChanges(n int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.drop = n
}

// Saves counts saved configurations (EOS copy, BIG-IP save, FortiOS commits).
func (d *APIDevice) Saves() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.saves
}

// URL is the device's HTTPS endpoint.
func (d *APIDevice) URL() string { return d.srv.URL }

// CAPEM is the device's self-signed certificate, the pin a provider trusts.
func (d *APIDevice) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d.srv.Certificate().Raw})
}

// Client trusts only the device's certificate.
func (d *APIDevice) Client() *http.Client { return d.srv.Client() }

// Close stops the device.
func (d *APIDevice) Close() { d.srv.Close() }

// SignsIn reports whether user signs in with password through the device's
// own sign-in (eAPI basic authentication, FortiOS /logincheck, BIG-IP token
// login).
func (d *APIDevice) SignsIn(user, password string) bool {
	client := d.srv.Client()
	var req *http.Request
	switch d.dialect {
	case EOS:
		req, _ = http.NewRequest(http.MethodPost, d.srv.URL+"/command-api",
			strings.NewReader(`{"jsonrpc":"2.0","method":"runCmds","params":{"version":1,"cmds":["show version"],"format":"json"},"id":"probe"}`))
		req.SetBasicAuth(user, password)
	case FortiOS:
		req, _ = http.NewRequest(http.MethodPost, d.srv.URL+"/logincheck",
			strings.NewReader(url.Values{"username": {user}, "secretkey": {password}, "ajax": {"1"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case BIGIP:
		body, _ := json.Marshal(map[string]string{"username": user, "password": password, "loginProviderName": "tmos"})
		req, _ = http.NewRequest(http.MethodPost, d.srv.URL+"/mgmt/shared/authn/login", bytes.NewReader(body))
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch d.dialect {
	case FortiOS:
		return resp.StatusCode == http.StatusOK && bytes.HasPrefix(raw, []byte("1"))
	case EOS:
		return resp.StatusCode == http.StatusOK && !bytes.Contains(raw, []byte(`"error"`))
	}
	return resp.StatusCode == http.StatusOK
}

func (d *APIDevice) check(user string, password []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	a, ok := d.accounts[user]
	return ok && len(a.password) > 0 && bytes.Equal(a.password, password)
}

// change sets an account's password (or the EOS enable password, name
// "enable"), unless a dropped change is pending.
func (d *APIDevice) change(name string, password []byte, level, role *string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dialect == EOS && name == "enable" && level == nil {
		if d.drop > 0 {
			d.drop--
			return true
		}
		d.enable = append([]byte(nil), password...)
		return true
	}
	a, ok := d.accounts[name]
	if !ok {
		if d.dialect != EOS {
			return false
		}
		a = &apiAccount{}
		d.accounts[name] = a
	}
	if level != nil {
		a.level = *level
	}
	if role != nil {
		a.role = *role
	}
	if d.drop > 0 {
		d.drop--
		return true
	}
	a.password = append([]byte(nil), password...)
	return true
}

func fakeHash(password []byte) string {
	sum := sha256.Sum256(password)
	return base64.RawStdEncoding.EncodeToString(sum[:16])
}

func randomHex() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (d *APIDevice) serveHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	switch d.dialect {
	case EOS:
		d.eos(w, r)
	case FortiOS:
		d.fortios(w, r)
	case BIGIP:
		d.bigip(w, r)
	}
}

// eos serves eAPI.
func (d *APIDevice) eos(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/command-api" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	user, password, ok := r.BasicAuth()
	if !ok || !d.check(user, []byte(password)) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		ID      json.RawMessage `json:"id"`
		Params  struct {
			Version int               `json:"version"`
			Format  string            `json:"format"`
			Cmds    []json.RawMessage `json:"cmds"`
		} `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.JSONRPC != "2.0" || req.Method != "runCmds" || req.Params.Version != 1 {
		writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32600, "message": "Invalid request"}})
		return
	}
	text := req.Params.Format == "text"
	privileged := d.Level(user) == "15"
	configuring := false
	results := []any{}
	for i, raw := range req.Params.Cmds {
		var cmd, input string
		if err := json.Unmarshal(raw, &cmd); err != nil {
			var complex struct {
				Cmd   string `json:"cmd"`
				Input string `json:"input"`
			}
			if json.Unmarshal(raw, &complex) != nil {
				writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32602, "message": "Invalid params"}})
				return
			}
			cmd, input = complex.Cmd, complex.Input
		}
		result, err := d.eosCommand(cmd, input, text, &privileged, &configuring)
		if err != nil {
			data := append(results, map[string]any{"errors": []string{err.Error()}})
			writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": 1002,
				"message": fmt.Sprintf("CLI command %d of %d '%s' failed: %s", i+1, len(req.Params.Cmds), cmd, err), "data": data}})
			return
		}
		results = append(results, result)
	}
	writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": results})
}

func (d *APIDevice) eosCommand(cmd, input string, text bool, privileged, configuring *bool) (any, error) {
	out := func(s string) any {
		if text {
			return map[string]string{"output": s}
		}
		return map[string]any{}
	}
	fields := strings.Fields(cmd)
	switch {
	case cmd == "enable":
		d.mu.Lock()
		need := len(d.enable) > 0 && !*privileged
		good := !need || input == string(d.enable)
		d.mu.Unlock()
		if !good {
			return nil, errors.New("bad secret")
		}
		*privileged = true
		return out(""), nil
	case cmd == "disable":
		*privileged, *configuring = false, false
		return out(""), nil
	case cmd == "configure" || cmd == "configure terminal":
		if !*privileged {
			return nil, errors.New("invalid command")
		}
		*configuring = true
		return out(""), nil
	case cmd == "end" || cmd == "exit":
		*configuring = false
		return out(""), nil
	case cmd == "show version":
		if text {
			return out("Arista vEOS-lab\nSoftware image version: 4.32.0F\n"), nil
		}
		return map[string]any{"modelName": "vEOS-lab", "version": "4.32.0F"}, nil
	case cmd == "copy running-config startup-config":
		if !*privileged {
			return nil, errors.New("invalid command")
		}
		d.mu.Lock()
		d.saves++
		d.mu.Unlock()
		return out("Copy completed successfully.\n"), nil
	case cmd == "show running-config section username":
		if !*privileged {
			return nil, errors.New("invalid command")
		}
		if !text {
			return nil, errors.New("this is an unconverted command")
		}
		d.mu.Lock()
		names := make([]string, 0, len(d.accounts))
		for n := range d.accounts {
			names = append(names, n)
		}
		sort.Strings(names)
		var b strings.Builder
		for _, n := range names {
			a := d.accounts[n]
			fmt.Fprintf(&b, "username %s privilege %s", n, a.level)
			if a.role != "" {
				fmt.Fprintf(&b, " role %s", a.role)
			}
			fmt.Fprintf(&b, " secret sha512 $6$%s\n", fakeHash(a.password))
		}
		d.mu.Unlock()
		return out(b.String()), nil
	case *configuring && len(fields) == 4 && fields[0] == "enable" && fields[1] == "password" && fields[2] == "0":
		d.change("enable", []byte(fields[3]), nil, nil)
		return out(""), nil
	case *configuring && len(fields) >= 4 && fields[0] == "username":
		name, level, role := fields[1], "1", ""
		rest := fields[2:]
		for len(rest) >= 2 && (rest[0] == "privilege" || rest[0] == "role") {
			if rest[0] == "privilege" {
				level = rest[1]
			} else {
				role = rest[1]
			}
			rest = rest[2:]
		}
		if len(rest) != 3 || rest[0] != "secret" || rest[1] != "0" {
			return nil, errors.New("invalid command")
		}
		d.change(name, []byte(rest[2]), &level, &role)
		return out(""), nil
	}
	return nil, errors.New("invalid command")
}

// fortios serves the FortiGate REST API.
func (d *APIDevice) fortios(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/logincheck":
		if r.ParseForm() != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		user := r.PostForm.Get("username")
		if !d.check(user, []byte(r.PostForm.Get("secretkey"))) {
			_, _ = w.Write([]byte("0"))
			return
		}
		session := randomHex()
		d.mu.Lock()
		d.sessions[session] = user
		d.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "APSCOOKIE_8888", Value: session, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.SetCookie(w, &http.Cookie{Name: "ccsrftoken", Value: `"` + randomHex() + `"`, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		_, _ = w.Write([]byte(`1document.location="/ng/prompt?viewOnly&redir=%2Fng%2F";`))
		return
	case r.Method == http.MethodPost && r.URL.Path == "/logout":
		if c, err := r.Cookie("APSCOOKIE_8888"); err == nil {
			d.mu.Lock()
			delete(d.sessions, c.Value)
			d.mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+d.apiToken || d.apiToken == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"http_status": 401, "status": "error"})
		return
	}
	const collection = "/api/v2/cmdb/system/admin"
	switch {
	case r.Method == http.MethodGet && r.URL.Path == collection:
		d.mu.Lock()
		names := make([]string, 0, len(d.accounts))
		for n := range d.accounts {
			names = append(names, n)
		}
		sort.Strings(names)
		results := []map[string]any{}
		for _, n := range names {
			a := d.accounts[n]
			entry := map[string]any{"name": n, "q_origin_key": n, "accprofile": a.level, "vdom": []map[string]string{{"name": "root"}}}
			if len(a.password) > 0 {
				entry["password"] = "ENC SH2" + fakeHash(a.password)
			}
			results = append(results, entry)
		}
		d.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"http_method": "GET", "results": results, "vdom": "root", "path": "system", "name": "admin", "status": "success", "http_status": 200})
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, collection+"/"):
		name, _ := url.PathUnescape(strings.TrimPrefix(r.URL.Path, collection+"/"))
		var body struct {
			Password string `json:"password"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Password == "" || name == d.apiAdmin {
			writeJSON(w, http.StatusBadRequest, map[string]any{"http_method": "PUT", "status": "error", "http_status": 400})
			return
		}
		if !d.change(name, []byte(body.Password), nil, nil) {
			writeJSON(w, http.StatusNotFound, map[string]any{"http_method": "PUT", "status": "error", "http_status": 404})
			return
		}
		d.mu.Lock()
		d.saves++
		d.revision++
		revision := d.revision
		d.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"http_method": "PUT", "revision": fmt.Sprintf("%032d", revision), "mkey": name,
			"status": "success", "http_status": 200, "vdom": "root", "path": "system", "name": "admin"})
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"status": "error", "http_status": 404})
	}
}

// bigip serves iControl REST.
func (d *APIDevice) bigip(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/mgmt/shared/authn/login" {
		var body struct {
			Username, Password, LoginProviderName string
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.LoginProviderName != "tmos" || !d.check(body.Username, []byte(body.Password)) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 401, "message": "Authentication failed.", "errorStack": []string{}, "apiError": 1})
			return
		}
		token := strings.ToUpper(randomHex())[:26]
		d.mu.Lock()
		d.tokens[token] = body.Username
		d.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"username": body.Username, "loginProviderName": "tmos",
			"token": map[string]any{"token": token, "name": token, "userName": body.Username, "timeout": 1200}})
		return
	}
	d.mu.Lock()
	user, ok := d.tokens[r.Header.Get("X-F5-Auth-Token")]
	admin := ok && d.accounts[user] != nil && d.accounts[user].level == "admin"
	d.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 401, "message": "Authorization failed: no user authentication header or token detected.", "errorStack": []string{}, "apiError": 1})
		return
	}
	const users = "/mgmt/tm/auth/user"
	switch {
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/mgmt/shared/authz/tokens/"):
		d.mu.Lock()
		delete(d.tokens, strings.TrimPrefix(r.URL.Path, "/mgmt/shared/authz/tokens/"))
		d.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{})
	case !admin:
		writeJSON(w, http.StatusForbidden, map[string]any{"code": 403, "message": "Forbidden", "errorStack": []string{}, "apiError": 1})
	case r.Method == http.MethodGet && r.URL.Path == users:
		d.mu.Lock()
		names := make([]string, 0, len(d.accounts))
		for n := range d.accounts {
			names = append(names, n)
		}
		sort.Strings(names)
		items := []map[string]any{}
		for _, n := range names {
			a := d.accounts[n]
			items = append(items, map[string]any{"kind": "tm:auth:user:userstate", "name": n, "fullPath": n,
				"encryptedPassword": "$6$" + fakeHash(a.password), "shell": "none",
				"partitionAccess": []map[string]string{{"name": "all-partitions", "role": a.level}}})
		}
		d.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"kind": "tm:auth:user:usercollectionstate", "items": items})
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, users+"/"):
		name, _ := url.PathUnescape(strings.TrimPrefix(r.URL.Path, users+"/"))
		var body struct {
			Password string `json:"password"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": 400, "message": "invalid body", "errorStack": []string{}, "apiError": 3})
			return
		}
		if !d.change(name, []byte(body.Password), nil, nil) {
			writeJSON(w, http.StatusNotFound, map[string]any{"code": 404, "message": "01020036:3: The requested user role partition (/Common/" + name + ") was not found.", "errorStack": []string{}, "apiError": 3})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"kind": "tm:auth:user:userstate", "name": name, "fullPath": name})
	case r.Method == http.MethodPost && r.URL.Path == "/mgmt/tm/sys/config":
		var body struct {
			Command string `json:"command"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Command != "save" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": 400, "message": "invalid command", "errorStack": []string{}, "apiError": 3})
			return
		}
		d.mu.Lock()
		d.saves++
		d.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"kind": "tm:sys:config:savestate", "command": "save"})
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 404, "message": "not found", "errorStack": []string{}, "apiError": 1})
	}
}
