// SPDX-License-Identifier: BUSL-1.1

// Package infratest holds stand-ins for infrastructure management interfaces
// (A271): a Redfish service as a server management controller (HPE iLO
// first) exposes it, the vSphere Web Services API of an ESXi host, and a
// vCenter Server appliance. Each is the documented subset that account
// rotation, check-out and discovery use. It lives in the crypto boundary
// because each serves TLS (or SSH) with a key it generates.
package infratest

// Redfish (DMTF Redfish specification DSP0266 and schema bundle DSP8010;
// HPE iLO 5/6 Redfish API reference):
//   - POST /redfish/v1/SessionService/Sessions {"UserName","Password"}
//     answers 201 with an X-Auth-Token header and the session's Location;
//     DELETE that Location with the token ends it. A wrong password is 401.
//   - GET /redfish/v1/AccountService/Accounts lists {"Members":[{"@odata.id"}]};
//     GET a member is a ManagerAccount {"Id","UserName","RoleId","Enabled",
//     "Locked"} with an ETag; PATCH it {"Password"} (If-Match honored) changes
//     the password and answers 200. Only an Administrator (ConfigureUsers)
//     session may PATCH another account; any session may read.
//   - Every other request needs X-Auth-Token or HTTP basic authentication.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
)

type bmcAccount struct {
	id       string
	password []byte
	role     string
	enabled  bool
	etag     int
}

// Redfish is a running Redfish service stand-in.
type Redfish struct {
	srv *httptest.Server

	mu       sync.Mutex
	accounts map[string]*bmcAccount // by UserName
	sessions map[string]string      // token -> UserName
	drop     int
	nextID   int
}

// StartRedfish brings up a Redfish service with one administrator.
func StartRedfish(admin, password string) *Redfish {
	r := &Redfish{accounts: map[string]*bmcAccount{}, sessions: map[string]string{}}
	r.AddAccount(admin, password, "Administrator")
	r.srv = httptest.NewTLSServer(http.HandlerFunc(r.serve))
	return r
}

// AddAccount adds an enabled account with a Redfish RoleId (Administrator,
// Operator or ReadOnly).
func (r *Redfish) AddAccount(name, password, role string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextID++
	r.accounts[name] = &bmcAccount{id: fmt.Sprint(r.nextID), password: []byte(password), role: role, enabled: true, etag: 1}
}

// Password is an account's current password.
func (r *Redfish) Password(name string) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.accounts[name]; ok {
		return append([]byte(nil), a.password...)
	}
	return nil
}

// Role is an account's RoleId.
func (r *Redfish) Role(name string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.accounts[name]; ok {
		return a.role
	}
	return ""
}

// Sessions counts open sessions (every proof must log out).
func (r *Redfish) Sessions() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// DropNextChanges makes the next n password changes answer 200 but keep the
// old password, as a controller whose change did not take effect.
func (r *Redfish) DropNextChanges(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.drop = n
}

// URL is the service's HTTPS root.
func (r *Redfish) URL() string { return r.srv.URL }

// CAPEM is the service's self-signed certificate.
func (r *Redfish) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.srv.Certificate().Raw})
}

// Client trusts only the service's certificate.
func (r *Redfish) Client() *http.Client { return r.srv.Client() }

// Close stops the service.
func (r *Redfish) Close() { r.srv.Close() }

// SignsIn reports whether name opens a session with password.
func (r *Redfish) SignsIn(name, password string) bool {
	body, _ := json.Marshal(map[string]string{"UserName": name, "Password": password})
	resp, err := r.srv.Client().Post(r.srv.URL+"/redfish/v1/SessionService/Sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return false
	}
	req, _ := http.NewRequest(http.MethodDelete, r.srv.URL+resp.Header.Get("Location"), nil)
	req.Header.Set("X-Auth-Token", resp.Header.Get("X-Auth-Token"))
	if out, err := r.srv.Client().Do(req); err == nil {
		_ = out.Body.Close()
	}
	return true
}

func redfishError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "Base.1.8.GeneralError", "message": message}})
}

func (r *Redfish) check(name string, password []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.accounts[name]
	return ok && a.enabled && bytes.Equal(a.password, password)
}

func (r *Redfish) serve(w http.ResponseWriter, req *http.Request) {
	req.Body = http.MaxBytesReader(w, req.Body, 1<<20)
	const sessions = "/redfish/v1/SessionService/Sessions"
	if req.Method == http.MethodPost && req.URL.Path == sessions {
		var body struct{ UserName, Password string }
		if json.NewDecoder(req.Body).Decode(&body) != nil || !r.check(body.UserName, []byte(body.Password)) {
			redfishError(w, http.StatusUnauthorized, "Invalid username or password")
			return
		}
		var raw [16]byte
		_, _ = rand.Read(raw[:])
		token := hex.EncodeToString(raw[:])
		r.mu.Lock()
		r.sessions[token] = body.UserName
		r.mu.Unlock()
		w.Header().Set("X-Auth-Token", token)
		w.Header().Set("Location", sessions+"/"+token[:12])
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"@odata.id": sessions + "/" + token[:12], "UserName": body.UserName})
		return
	}
	user := ""
	if token := req.Header.Get("X-Auth-Token"); token != "" {
		r.mu.Lock()
		user = r.sessions[token]
		r.mu.Unlock()
	} else if name, password, ok := req.BasicAuth(); ok && r.check(name, []byte(password)) {
		user = name
	}
	if user == "" {
		redfishError(w, http.StatusUnauthorized, "No valid session")
		return
	}
	switch {
	case req.Method == http.MethodDelete && strings.HasPrefix(req.URL.Path, sessions+"/"):
		id := strings.TrimPrefix(req.URL.Path, sessions+"/")
		r.mu.Lock()
		for token := range r.sessions {
			if strings.HasPrefix(token, id) && token == req.Header.Get("X-Auth-Token") {
				delete(r.sessions, token)
			}
		}
		r.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case req.Method == http.MethodGet && req.URL.Path == "/redfish/v1/AccountService/Accounts":
		r.mu.Lock()
		ids := make([]string, 0, len(r.accounts))
		for _, a := range r.accounts {
			ids = append(ids, a.id)
		}
		r.mu.Unlock()
		sort.Strings(ids)
		members := []map[string]string{}
		for _, id := range ids {
			members = append(members, map[string]string{"@odata.id": "/redfish/v1/AccountService/Accounts/" + id})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"@odata.type": "#ManagerAccountCollection.ManagerAccountCollection", "Members": members, "Members@odata.count": len(members)})
	case strings.HasPrefix(req.URL.Path, "/redfish/v1/AccountService/Accounts/"):
		id := strings.TrimPrefix(req.URL.Path, "/redfish/v1/AccountService/Accounts/")
		r.mu.Lock()
		var name string
		var account *bmcAccount
		for n, a := range r.accounts {
			if a.id == id {
				name, account = n, a
			}
		}
		callerAdmin := r.accounts[user] != nil && r.accounts[user].role == "Administrator"
		r.mu.Unlock()
		if account == nil {
			redfishError(w, http.StatusNotFound, "The account was not found")
			return
		}
		switch req.Method {
		case http.MethodGet:
			r.mu.Lock()
			view := map[string]any{"@odata.type": "#ManagerAccount.v1_7_0.ManagerAccount", "Id": account.id, "UserName": name, "RoleId": account.role,
				"Enabled": account.enabled, "Locked": false, "Password": nil}
			etag := fmt.Sprintf(`W/"%d"`, account.etag)
			r.mu.Unlock()
			w.Header().Set("ETag", etag)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(view)
		case http.MethodPatch:
			if !callerAdmin {
				redfishError(w, http.StatusForbidden, "Insufficient privilege")
				return
			}
			var body struct {
				Password *string `json:"Password"`
			}
			if json.NewDecoder(req.Body).Decode(&body) != nil || body.Password == nil || *body.Password == "" {
				redfishError(w, http.StatusBadRequest, "Password is required")
				return
			}
			r.mu.Lock()
			if match := req.Header.Get("If-Match"); match != "" && match != fmt.Sprintf(`W/"%d"`, account.etag) {
				r.mu.Unlock()
				redfishError(w, http.StatusPreconditionFailed, "ETag does not match")
				return
			}
			if r.drop > 0 {
				r.drop--
			} else {
				account.password = []byte(*body.Password)
			}
			account.etag++
			r.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"@Message.ExtendedInfo": []map[string]string{{"MessageId": "Base.1.8.Success"}}})
		default:
			redfishError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	default:
		redfishError(w, http.StatusNotFound, "Not found")
	}
}
