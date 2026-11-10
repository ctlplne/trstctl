// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pamdiscovery"
)

// A271: VMware ESXi local accounts through the vSphere Web Services API
// (SOAP at /sdk) over HTTPS, the host's certificate pinned by the caller's
// client. An administrator signs in (SessionManager.Login), changes the bound
// account with HostLocalAccountManager.UpdateUser and logs out; the change is
// proved by signing in as the account with the new password, and a change the
// host does not prove is put back. Discovery reads the local users and their
// permissions' roles. vpxuser (vCenter's own account) and dcui are never
// rotated: vCenter and the console manage them.

// ESXiConfig configures one host.
type ESXiConfig struct {
	// Endpoint is the host's https://host[:port]; the API is its /sdk.
	Endpoint      string
	HTTPClient    *http.Client
	AdminUser     string
	AdminPassword []byte
	RoleAccounts  map[string]string
}

// esxiSystemAccounts are managed by vCenter and the console, never here.
var esxiSystemAccounts = map[string]bool{"vpxuser": true, "dcui": true}

// ESXiBackend rotates and discovers one host's local accounts.
type ESXiBackend struct {
	endpoint string
	client   *http.Client
	admin    string
	password *secret.Buffer
	accounts map[string]string
}

// NewESXiBackend validates cfg.
func NewESXiBackend(cfg ESXiConfig) (*ESXiBackend, error) {
	parsed, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" {
		return nil, errors.New("dynsecret esxi: endpoint must be the host's https://host[:port]")
	}
	if cfg.HTTPClient == nil || !networkAPIAccount.MatchString(cfg.AdminUser) || len(cfg.AdminPassword) == 0 {
		return nil, errors.New("dynsecret esxi: the pinned client, admin_user and its password are required")
	}
	b := &ESXiBackend{endpoint: "https://" + parsed.Host, client: cfg.HTTPClient, admin: cfg.AdminUser, accounts: map[string]string{}}
	seen := map[string]bool{}
	for role, account := range cfg.RoleAccounts {
		account = strings.TrimSpace(account)
		switch {
		case !networkAPIAccount.MatchString(account):
			return nil, fmt.Errorf("dynsecret esxi: role %q names %q, which is not a local account name", role, account)
		case esxiSystemAccounts[account]:
			return nil, fmt.Errorf("dynsecret esxi: role %q names %s, which vCenter or the console manages", role, account)
		case account == cfg.AdminUser:
			return nil, fmt.Errorf("dynsecret esxi: role %q names the administrator that makes the change", role)
		case seen[account]:
			return nil, fmt.Errorf("dynsecret esxi: account %q serves two roles", account)
		}
		seen[account] = true
		b.accounts[role] = account
	}
	if len(b.accounts) == 0 {
		return nil, errors.New("dynsecret esxi: every allowed role needs its account in role_bindings")
	}
	if b.password, err = secret.NewFrom(cfg.AdminPassword); err != nil {
		return nil, err
	}
	return b, nil
}

// Create implements Backend: host accounts are rotated, not leased.
func (b *ESXiBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend for a static rotation.
func (b *ESXiBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if !req.Static {
		return "", nil, errors.New("dynsecret esxi: a host account is rotated, not leased; use a static rotation")
	}
	account, ok := b.accounts[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret esxi: role %q has no account", req.Role)
	}
	password, err := randomPolicyPassword(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	if err := b.set(ctx, account, password); err != nil {
		return "", nil, err
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the rotated host credential; the rotation seals it before storage (CWE-200)
		Host     string           `json:"host"`
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}{Host: strings.TrimPrefix(b.endpoint, "https://"), Username: account, Password: password})
	if err != nil {
		return "", nil, err
	}
	return account + "/" + req.LeaseID, credential, nil
}

// xmlText appends b escaped as XML character data. A secret never becomes a
// string; a control character XML cannot carry is refused.
func xmlText(dst, b []byte) ([]byte, error) {
	for _, c := range b {
		switch c {
		case '&':
			dst = append(dst, "&amp;"...)
		case '<':
			dst = append(dst, "&lt;"...)
		case '>':
			dst = append(dst, "&gt;"...)
		case '"':
			dst = append(dst, "&quot;"...)
		case '\'':
			dst = append(dst, "&apos;"...)
		default:
			if c < 0x20 && c != '\t' {
				return dst, errors.New("dynsecret esxi: a control character cannot travel in the host's API")
			}
			dst = append(dst, c)
		}
	}
	return dst, nil
}

// soap posts one operation and returns its answer; the caller wipes it.
func (b *ESXiBackend) soap(ctx context.Context, cookie string, operation []byte) (int, []*http.Cookie, []byte, error) {
	body := append([]byte(`<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="urn:vim25" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body>`), operation...)
	body = append(body, "</soapenv:Body></soapenv:Envelope>"...)
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint+"/sdk", bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", `"urn:vim25/7.0"`)
	if cookie != "" {
		req.Header.Set("Cookie", "vmware_soap_session="+cookie)
	}
	resp, err := b.client.Do(req) // #nosec G704 -- the operator's configured host through the pinned, egress-guarded client (CWE-918)
	if err != nil {
		// A dial, TLS handshake or deadline reads as unreachable, so a scan
		// or a check names it instead of a generic error.
		if class := classifyNetwork(err); class != nil {
			return 0, nil, nil, fmt.Errorf("%w: dynsecret esxi: the host did not answer", class)
		}
		return 0, nil, nil, errors.New("dynsecret esxi: the host did not answer")
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, networkAPIMaxBody+1))
	if err != nil || len(raw) > networkAPIMaxBody {
		secret.Wipe(raw)
		return 0, nil, nil, errors.New("dynsecret esxi: the host's answer was unreadable or too large")
	}
	return resp.StatusCode, resp.Cookies(), raw, nil
}

// esxiFault names a SOAP fault's type (InvalidLogin, NoPermission, ...),
// never its text.
func esxiFault(raw []byte) string {
	var envelope struct {
		Body struct {
			Fault struct {
				Detail struct {
					Inner struct {
						XMLName xml.Name
					} `xml:",any"`
				} `xml:"detail"`
			} `xml:"Fault"`
		} `xml:"Body"`
	}
	if xml.Unmarshal(raw, &envelope) != nil {
		return "unreadable"
	}
	return strings.TrimSuffix(envelope.Body.Fault.Detail.Inner.XMLName.Local, "Fault")
}

// login signs in as user and returns the session cookie (a header string, as
// net/http requires; it ends with Logout).
func (b *ESXiBackend) login(ctx context.Context, user string, password []byte) (string, error) {
	op := []byte(`<vim25:Login><vim25:_this type="SessionManager">ha-sessionmgr</vim25:_this><vim25:userName>`)
	op, err := xmlText(op, []byte(user))
	if err != nil {
		return "", err
	}
	op = append(op, "</vim25:userName><vim25:password>"...)
	if op, err = xmlText(op, password); err != nil {
		secret.Wipe(op)
		return "", err
	}
	op = append(op, "</vim25:password></vim25:Login>"...)
	status, cookies, raw, err := b.soap(ctx, "", op)
	secret.Wipe(op)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(raw)
	if status != http.StatusOK {
		// InvalidLogin is the host refusing the user name and password: the
		// rejected class, which tells an operator the stored password is wrong
		// or changed rather than that the host failed.
		fault := esxiFault(raw)
		if fault == "InvalidLogin" {
			return "", fmt.Errorf("%w: dynsecret esxi: the host refused %s's sign-in (%s)", ErrSignInRejected, user, fault)
		}
		return "", fmt.Errorf("dynsecret esxi: the host refused %s's sign-in (%s)", user, fault)
	}
	for _, c := range cookies {
		if c.Name == "vmware_soap_session" && c.Value != "" {
			return c.Value, nil
		}
	}
	return "", errors.New("dynsecret esxi: the sign-in returned no session")
}

func (b *ESXiBackend) logout(ctx context.Context, cookie string) {
	_, _, raw, _ := b.soap(ctx, cookie, []byte(`<vim25:Logout><vim25:_this type="SessionManager">ha-sessionmgr</vim25:_this></vim25:Logout>`))
	secret.Wipe(raw)
}

func (b *ESXiBackend) adminSession(ctx context.Context, fn func(cookie string) error) error {
	return b.password.Use(func(admin []byte) error {
		cookie, err := b.login(ctx, b.admin, admin)
		if err != nil {
			return err
		}
		defer b.logout(context.WithoutCancel(ctx), cookie)
		return fn(cookie)
	})
}

// set changes account's password with HostLocalAccountManager.UpdateUser.
func (b *ESXiBackend) set(ctx context.Context, account string, password []byte) error {
	op := []byte(`<vim25:UpdateUser><vim25:_this type="HostLocalAccountManager">ha-localacctmgr</vim25:_this><vim25:user><vim25:id>`)
	op, err := xmlText(op, []byte(account))
	if err != nil {
		return err
	}
	op = append(op, "</vim25:id><vim25:password>"...)
	if op, err = xmlText(op, password); err != nil {
		secret.Wipe(op)
		return err
	}
	op = append(op, "</vim25:password></vim25:user></vim25:UpdateUser>"...)
	defer secret.Wipe(op)
	return b.adminSession(ctx, func(cookie string) error {
		status, _, raw, err := b.soap(ctx, cookie, op)
		if err != nil {
			return err
		}
		defer secret.Wipe(raw)
		if status != http.StatusOK {
			return fmt.Errorf("dynsecret esxi: the host refused the change (%s)", esxiFault(raw))
		}
		return nil
	})
}

// VerifyCredential proves the credential signs in to the host.
func (b *ESXiBackend) VerifyCredential(ctx context.Context, credential []byte) error {
	var parsed struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || parsed.Username == "" || len(parsed.Password) == 0 {
		return errors.New("dynsecret esxi: the credential carries no account and password")
	}
	defer secret.Wipe(parsed.Password)
	cookie, err := b.login(ctx, parsed.Username, parsed.Password)
	if err != nil {
		return err
	}
	b.logout(ctx, cookie)
	return nil
}

// RestoreStaticCredential puts role's predecessor back and proves it signs in
// again (the rollback of a failed rotation).
func (b *ESXiBackend) RestoreStaticCredential(ctx context.Context, role, _ string, credential []byte) error {
	account, ok := b.accounts[role]
	var parsed struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || !ok || parsed.Username != account || len(parsed.Password) == 0 {
		return errors.New("dynsecret esxi: the predecessor is not this role's account credential")
	}
	defer secret.Wipe(parsed.Password)
	if err := b.set(ctx, account, parsed.Password); err != nil {
		return err
	}
	return b.VerifyCredential(ctx, credential)
}

// Revoke implements Backend: the predecessor stopped working when the next
// password was set.
func (b *ESXiBackend) Revoke(_ context.Context, ref string) error {
	account, _, _ := strings.Cut(ref, "/")
	for _, bound := range b.accounts {
		if account == bound {
			return nil
		}
	}
	return fmt.Errorf("dynsecret esxi: refusing %q, which names no account this provider rotates", ref)
}

// esxiRoles names the host's system roles.
var esxiRoles = map[int]string{-1: "Admin", -2: "ReadOnly", -3: "View", -4: "Anonymous", -5: "NoAccess"}

// DiscoverPrivilegedAccounts lists the host's local users with the roles
// their permissions grant; vpxuser and dcui are marked as system accounts.
func (b *ESXiBackend) DiscoverPrivilegedAccounts(ctx context.Context) ([]pamdiscovery.Account, error) {
	var out []pamdiscovery.Account
	err := b.adminSession(ctx, func(cookie string) error {
		status, _, raw, err := b.soap(ctx, cookie, []byte(`<vim25:RetrieveUserGroups><vim25:_this type="UserDirectory">ha-user-directory</vim25:_this>`+
			`<vim25:searchStr></vim25:searchStr><vim25:exactMatch>false</vim25:exactMatch><vim25:findUsers>true</vim25:findUsers><vim25:findGroups>false</vim25:findGroups></vim25:RetrieveUserGroups>`))
		if err != nil {
			return err
		}
		var users struct {
			Body struct {
				Response struct {
					Results []struct {
						Principal string `xml:"principal"`
						Group     bool   `xml:"group"`
					} `xml:"returnval"`
				} `xml:"RetrieveUserGroupsResponse"`
			} `xml:"Body"`
		}
		err = xml.Unmarshal(raw, &users)
		secret.Wipe(raw)
		if status != http.StatusOK || err != nil {
			return fmt.Errorf("dynsecret esxi: the local users were unreadable (HTTP %d)", status)
		}
		status, _, raw, err = b.soap(ctx, cookie, []byte(`<vim25:RetrieveAllPermissions><vim25:_this type="AuthorizationManager">ha-authmgr</vim25:_this></vim25:RetrieveAllPermissions>`))
		if err != nil {
			return err
		}
		var permissions struct {
			Body struct {
				Response struct {
					Permissions []struct {
						Principal string `xml:"principal"`
						Group     bool   `xml:"group"`
						RoleID    int    `xml:"roleId"`
					} `xml:"returnval"`
				} `xml:"RetrieveAllPermissionsResponse"`
			} `xml:"Body"`
		}
		err = xml.Unmarshal(raw, &permissions)
		secret.Wipe(raw)
		if status != http.StatusOK || err != nil {
			return fmt.Errorf("dynsecret esxi: the permissions were unreadable (HTTP %d)", status)
		}
		roles := map[string][]string{}
		for _, p := range permissions.Body.Response.Permissions {
			if p.Group {
				continue
			}
			name, ok := esxiRoles[p.RoleID]
			if !ok {
				name = strconv.Itoa(p.RoleID)
			}
			roles[p.Principal] = append(roles[p.Principal], "role "+name)
		}
		if len(users.Body.Response.Results) > pamdiscovery.MaxAccounts {
			return errors.New("dynsecret esxi: more accounts than one discovery holds")
		}
		for _, u := range users.Body.Response.Results {
			if u.Group || u.Principal == "" {
				continue
			}
			details := map[string]string{"host": "esxi"}
			if esxiSystemAccounts[u.Principal] {
				details["system_account"] = "true"
			}
			out = append(out, pamdiscovery.Account{Key: "user:" + u.Principal, Name: u.Principal, Kind: "local_user",
				Privileges: roles[u.Principal], Details: details})
		}
		return nil
	})
	return out, err
}

// Close wipes the administrator's password.
func (b *ESXiBackend) Close() { b.password.Destroy() }
