// SPDX-License-Identifier: BUSL-1.1

package infratest

// ESXi (vSphere Web Services SDK programming guide and API reference, vim25):
// SOAP 1.1 over HTTPS at POST /sdk.
//   - RetrieveServiceContent(_this=ServiceInstance) names the host's managed
//     objects: sessionManager ha-sessionmgr, accountManager
//     ha-localacctmgr, userDirectory ha-user-directory, authorizationManager
//     ha-authmgr.
//   - SessionManager.Login(userName, password) sets the vmware_soap_session
//     cookie; a wrong password, or an account with no permission, faults
//     (InvalidLogin / NoPermission, HTTP 500). Logout ends it.
//   - HostLocalAccountManager.UpdateUser(user: HostAccountSpec{id,
//     password}) changes a local account's password (an Admin session only).
//   - UserDirectory.RetrieveUserGroups(searchStr, exactMatch, findUsers,
//     findGroups) lists local users (UserSearchResult principal, fullName).
//   - AuthorizationManager.RetrieveAllPermissions lists Permission{entity,
//     principal, group, roleId, propagate}; -1 is Admin, -2 ReadOnly, -5
//     NoAccess.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
)

type esxiAccount struct {
	password []byte
	roleID   int
}

// ESXi is a running ESXi host API stand-in.
type ESXi struct {
	srv *httptest.Server

	mu       sync.Mutex
	accounts map[string]*esxiAccount
	sessions map[string]string // cookie -> user
	drop     int
}

// StartESXi brings up a host whose administrator (role -1, Admin) signs in
// with password.
func StartESXi(admin, password string) *ESXi {
	e := &ESXi{accounts: map[string]*esxiAccount{}, sessions: map[string]string{}}
	e.AddAccount(admin, password, -1)
	e.srv = httptest.NewTLSServer(http.HandlerFunc(e.serve))
	return e
}

// AddAccount adds a local account with a permission on the host root
// (roleID -1 Admin, -2 ReadOnly, or a custom role's id).
func (e *ESXi) AddAccount(name, password string, roleID int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.accounts[name] = &esxiAccount{password: []byte(password), roleID: roleID}
}

// Password is an account's current password.
func (e *ESXi) Password(name string) []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	if a, ok := e.accounts[name]; ok {
		return append([]byte(nil), a.password...)
	}
	return nil
}

// Sessions counts open sessions.
func (e *ESXi) Sessions() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.sessions)
}

// DropNextChanges makes the next n UpdateUser calls succeed but keep the old
// password.
func (e *ESXi) DropNextChanges(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.drop = n
}

// URL is the host's HTTPS root (the API is at /sdk).
func (e *ESXi) URL() string { return e.srv.URL }

// CAPEM is the host's self-signed certificate.
func (e *ESXi) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.srv.Certificate().Raw})
}

// Client trusts only the host's certificate.
func (e *ESXi) Client() *http.Client { return e.srv.Client() }

// Close stops the host.
func (e *ESXi) Close() { e.srv.Close() }

// SignsIn reports whether name signs in with password (and logs out).
func (e *ESXi) SignsIn(name, password string) bool {
	var user, pw bytes.Buffer
	_ = xml.EscapeText(&user, []byte(name))
	_ = xml.EscapeText(&pw, []byte(password))
	body := `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="urn:vim25"><soapenv:Body>` +
		`<vim25:Login><vim25:_this type="SessionManager">ha-sessionmgr</vim25:_this><vim25:userName>` + user.String() +
		`</vim25:userName><vim25:password>` + pw.String() + `</vim25:password></vim25:Login></soapenv:Body></soapenv:Envelope>`
	resp, err := e.srv.Client().Post(e.srv.URL+"/sdk", "text/xml; charset=utf-8", strings.NewReader(body))
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	for _, c := range resp.Cookies() {
		if c.Name == "vmware_soap_session" {
			e.mu.Lock()
			delete(e.sessions, c.Value)
			e.mu.Unlock()
		}
	}
	return true
}

// soapCall is the one operation element inside a SOAP body.
type soapCall struct {
	XMLName  xml.Name
	This     string `xml:"_this"`
	UserName string `xml:"userName"`
	Password string `xml:"password"`
	User     struct {
		ID       string `xml:"id"`
		Password string `xml:"password"`
	} `xml:"user"`
	FindUsers bool `xml:"findUsers"`
}

func (e *ESXi) fault(w http.ResponseWriter, kind, message string) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body><soapenv:Fault><faultcode>ServerFaultCode</faultcode><faultstring>%s</faultstring><detail><%sFault xmlns="urn:vim25" xsi:type="%s"/></detail></soapenv:Fault></soapenv:Body></soapenv:Envelope>`,
		message, kind, kind)
}

func (e *ESXi) reply(w http.ResponseWriter, operation, inner string) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body><%sResponse xmlns="urn:vim25">%s</%sResponse></soapenv:Body></soapenv:Envelope>`,
		operation, inner, operation)
}

func (e *ESXi) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/sdk" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var envelope struct {
		Body struct {
			Call soapCall `xml:",any"`
		} `xml:"Body"`
	}
	if xml.Unmarshal(raw, &envelope) != nil {
		e.fault(w, "InvalidRequest", "Unable to parse the request")
		return
	}
	call := envelope.Body.Call
	session := ""
	if c, err := r.Cookie("vmware_soap_session"); err == nil {
		session = c.Value
	}
	e.mu.Lock()
	user := e.sessions[session]
	admin := user != "" && e.accounts[user] != nil && e.accounts[user].roleID == -1
	e.mu.Unlock()
	switch call.XMLName.Local {
	case "RetrieveServiceContent":
		e.reply(w, "RetrieveServiceContent", `<returnval><rootFolder type="Folder">ha-folder-root</rootFolder>`+
			`<sessionManager type="SessionManager">ha-sessionmgr</sessionManager><accountManager type="HostLocalAccountManager">ha-localacctmgr</accountManager>`+
			`<userDirectory type="UserDirectory">ha-user-directory</userDirectory><authorizationManager type="AuthorizationManager">ha-authmgr</authorizationManager>`+
			`<about><name>VMware ESXi</name><apiType>HostAgent</apiType><apiVersion>8.0.3.0</apiVersion></about></returnval>`)
	case "Login":
		e.mu.Lock()
		a, ok := e.accounts[call.UserName]
		good := ok && call.Password == string(a.password)
		permitted := good && a.roleID != -5
		e.mu.Unlock()
		switch {
		case !good:
			e.fault(w, "InvalidLogin", "Cannot complete login due to an incorrect user name or password.")
			return
		case !permitted:
			e.fault(w, "NoPermission", "Permission to perform this operation was denied.")
			return
		}
		var b [16]byte
		_, _ = rand.Read(b[:])
		cookie := hex.EncodeToString(b[:])
		e.mu.Lock()
		e.sessions[cookie] = call.UserName
		e.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "vmware_soap_session", Value: cookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		e.reply(w, "Login", `<returnval><key>`+cookie[:8]+`</key><userName>`+call.UserName+`</userName></returnval>`)
	case "Logout":
		e.mu.Lock()
		delete(e.sessions, session)
		e.mu.Unlock()
		e.reply(w, "Logout", "")
	case "UpdateUser":
		if !admin {
			e.fault(w, "NoPermission", "Permission to perform this operation was denied.")
			return
		}
		e.mu.Lock()
		a, ok := e.accounts[call.User.ID]
		if ok && call.User.Password != "" {
			if e.drop > 0 {
				e.drop--
			} else {
				a.password = []byte(call.User.Password)
			}
		}
		e.mu.Unlock()
		if !ok {
			e.fault(w, "UserNotFound", "The user or group named '"+call.User.ID+"' does not exist.")
			return
		}
		e.reply(w, "UpdateUser", "")
	case "RetrieveUserGroups":
		if user == "" {
			e.fault(w, "NotAuthenticated", "The session is not authenticated.")
			return
		}
		var b strings.Builder
		for _, n := range e.names() {
			fmt.Fprintf(&b, `<returnval xsi:type="UserSearchResult"><principal>%s</principal><fullName>%s</fullName><group>false</group></returnval>`, n, n)
		}
		e.reply(w, "RetrieveUserGroups", b.String())
	case "RetrieveAllPermissions":
		if user == "" {
			e.fault(w, "NotAuthenticated", "The session is not authenticated.")
			return
		}
		var b strings.Builder
		e.mu.Lock()
		for _, n := range e.namesLocked() {
			fmt.Fprintf(&b, `<returnval><entity type="Folder">ha-folder-root</entity><principal>%s</principal><group>false</group><roleId>%d</roleId><propagate>true</propagate></returnval>`, n, e.accounts[n].roleID)
		}
		e.mu.Unlock()
		e.reply(w, "RetrieveAllPermissions", b.String())
	default:
		e.fault(w, "MethodNotFound", "Unknown method")
	}
}

func (e *ESXi) names() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.namesLocked()
}

func (e *ESXi) namesLocked() []string {
	names := make([]string, 0, len(e.accounts))
	for n := range e.accounts {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
