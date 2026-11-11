// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pamdiscovery"
)

// A270 part 2: local account passwords on network devices changed through
// the device's management API over HTTPS, the device's certificate pinned by
// the caller's client: Arista EOS (eAPI), FortiGate (REST API) and F5 BIG-IP
// (iControl REST). Each allowed role is bound to one account whose password
// changes in place (single-phase); on EOS the account "enable" is the enable
// password. The administrator that makes the change is never a rotated
// account.

// NetworkAPIConfig configures one device.
type NetworkAPIConfig struct {
	// Vendor is "eos", "fortigate" or "bigip".
	Vendor string
	// Endpoint is the device's HTTPS management URL; HTTPClient pins its
	// certificate.
	Endpoint   string
	HTTPClient *http.Client
	// AdminUser makes the changes: with AdminPassword on EOS and BIG-IP; on
	// FortiGate it is the REST API administrator whose token is APIToken.
	AdminUser     string
	AdminPassword []byte
	APIToken      []byte
	// RoleAccounts binds each role to the account it rotates.
	RoleAccounts map[string]string
}

// networkAPIAccount is a device account name: letters, digits and ".-_",
// which every vendor accepts and which needs no escaping in a CLI command or
// a URL path.
var networkAPIAccount = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// networkAPIMaxBody bounds every device response.
const networkAPIMaxBody = 1 << 20

// NetworkAPIBackend rotates and discovers one device's local accounts.
type NetworkAPIBackend struct {
	vendor     string
	endpoint   string
	client     *http.Client
	admin      string
	credential *secret.Buffer
	accounts   map[string]string
}

// NewNetworkAPIBackend validates cfg.
func NewNetworkAPIBackend(cfg NetworkAPIConfig) (*NetworkAPIBackend, error) {
	switch cfg.Vendor {
	case "eos", "fortigate", "bigip":
	default:
		return nil, fmt.Errorf("dynsecret network: unknown device API %q", cfg.Vendor)
	}
	parsed, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" {
		return nil, errors.New("dynsecret network: endpoint must be the device's https://host[:port]")
	}
	if cfg.HTTPClient == nil || !networkAPIAccount.MatchString(cfg.AdminUser) {
		return nil, errors.New("dynsecret network: the pinned client and admin_user are required")
	}
	credential := cfg.AdminPassword
	if cfg.Vendor == "fortigate" {
		credential = cfg.APIToken
	}
	if len(credential) == 0 {
		return nil, errors.New("dynsecret network: the administrator's password (or FortiGate API token) is required")
	}
	b := &NetworkAPIBackend{vendor: cfg.Vendor, endpoint: "https://" + parsed.Host, client: cfg.HTTPClient, admin: cfg.AdminUser, accounts: map[string]string{}}
	seen := map[string]bool{}
	for role, account := range cfg.RoleAccounts {
		account = strings.TrimSpace(account)
		switch {
		case account == NetworkEnableAccount && cfg.Vendor != "eos":
			return nil, fmt.Errorf("dynsecret network: role %q names the enable password, which only EOS has here", role)
		case account == "root" && cfg.Vendor == "bigip":
			return nil, fmt.Errorf("dynsecret network: role %q names BIG-IP's root, which is not an iControl REST user", role)
		case !networkAPIAccount.MatchString(account):
			return nil, fmt.Errorf("dynsecret network: role %q names %q, which is not a device account name", role, account)
		case account == cfg.AdminUser:
			return nil, fmt.Errorf("dynsecret network: role %q names the administrator that makes the change", role)
		case seen[account]:
			return nil, fmt.Errorf("dynsecret network: account %q serves two roles", account)
		}
		seen[account] = true
		b.accounts[role] = account
	}
	if len(b.accounts) == 0 {
		return nil, errors.New("dynsecret network: every allowed role needs its account in role_bindings")
	}
	if b.credential, err = secret.NewFrom(credential); err != nil {
		return nil, err
	}
	return b, nil
}

// Create implements Backend: device accounts are rotated, not leased.
func (b *NetworkAPIBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend for a static rotation: the bound
// account's password (or EOS's enable password) changes in place.
func (b *NetworkAPIBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if !req.Static {
		return "", nil, errors.New("dynsecret network: a device account is rotated, not leased; use a static rotation")
	}
	account, ok := b.accounts[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret network: role %q has no account", req.Role)
	}
	password, err := randomPolicyPassword(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	if err := b.set(ctx, account, password); err != nil {
		return "", nil, err
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the rotated device credential; the rotation seals it before storage (CWE-200)
		Host     string           `json:"host"`
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}{Host: strings.TrimPrefix(b.endpoint, "https://"), Username: account, Password: password})
	if err != nil {
		return "", nil, err
	}
	return account + "/" + req.LeaseID, credential, nil
}

// do sends one request and returns its bounded response. The body and the
// response may carry secrets; callers wipe both.
func (b *NetworkAPIBackend) do(ctx context.Context, method, path string, header http.Header, body []byte) (int, []byte, []*http.Cookie, error) {
	req, err := http.NewRequestWithContext(ctx, method, b.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := b.client.Do(req) // #nosec G704 -- the operator's configured device endpoint through the pinned, egress-guarded client (CWE-918)
	if err != nil {
		// A dial, TLS handshake or deadline reads as unreachable (DEV-D1).
		return 0, nil, nil, withSignInClass(classifyNetwork(err), fmt.Errorf("dynsecret %s: the device did not answer", b.vendor))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, networkAPIMaxBody+1))
	if err != nil || len(raw) > networkAPIMaxBody {
		secret.Wipe(raw)
		return 0, nil, nil, fmt.Errorf("dynsecret %s: the device's answer was unreadable or too large", b.vendor)
	}
	return resp.StatusCode, raw, resp.Cookies(), nil
}

// eapiCommand is one eAPI command, with enable's password as its input.
type eapiCommand struct{ cmd, input []byte }

// eapi runs commands as user over eAPI and returns each command's result
// (text results are their "output"). A refused command fails the request
// without the device's message, which echoes the command.
func (b *NetworkAPIBackend) eapi(ctx context.Context, user string, password []byte, text bool, commands []eapiCommand) ([]json.RawMessage, error) {
	format := "json"
	if text {
		format = "text"
	}
	body := []byte(`{"jsonrpc":"2.0","method":"runCmds","id":"trstctl","params":{"version":1,"format":"` + format + `","cmds":[`)
	for i, c := range commands {
		if i > 0 {
			body = append(body, ',')
		}
		cmd, err := secret.JSONBytes(c.cmd).MarshalJSON()
		if err != nil {
			secret.Wipe(body)
			return nil, err
		}
		if c.input == nil {
			body = append(body, cmd...)
		} else {
			input, err := secret.JSONBytes(c.input).MarshalJSON()
			if err != nil {
				secret.Wipe(cmd)
				secret.Wipe(body)
				return nil, err
			}
			body = append(append(append(append(append(body, `{"cmd":`...), cmd...), `,"input":`...), input...), '}')
			secret.Wipe(input)
		}
		secret.Wipe(cmd)
	}
	body = append(body, "]}}"...)
	defer secret.Wipe(body)
	header := http.Header{"Content-Type": {"application/json"}, "Authorization": {basicAuthorization(user, password)}}
	status, raw, _, err := b.do(ctx, http.MethodPost, "/command-api", header, body)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(raw)
	if status == http.StatusUnauthorized {
		return nil, fmt.Errorf("%w: dynsecret eos: the device refused %s's sign-in", ErrSignInRejected, user)
	}
	var reply struct {
		Result []json.RawMessage `json:"result"`
		Error  *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &reply) != nil {
		return nil, fmt.Errorf("dynsecret eos: eAPI answered HTTP %d", status)
	}
	if reply.Error != nil || len(reply.Result) != len(commands) {
		code := 0
		if reply.Error != nil {
			code = reply.Error.Code
		}
		return nil, fmt.Errorf("dynsecret eos: the device refused a command (eAPI error %d)", code)
	}
	results := make([]json.RawMessage, len(reply.Result))
	for i, r := range reply.Result {
		results[i] = append(json.RawMessage(nil), r...)
	}
	return results, nil
}

// basicAuthorization is an HTTP basic Authorization header value. The header
// is a string, as net/http requires; it lives only for one request.
func basicAuthorization(user string, password []byte) string {
	raw := append([]byte(user+":"), password...)
	defer secret.Wipe(raw)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(encoded, raw)
	defer secret.Wipe(encoded)
	return "Basic " + string(encoded)
}

var eosUsername = regexp.MustCompile(`(?m)^username (\S+)(?: privilege (\d+))?(?: role (\S+))?`)

// eosAccounts reads the configured accounts (name, privilege, role); the
// secret hashes on the same lines are never kept.
func (b *NetworkAPIBackend) eosAccounts(ctx context.Context) (map[string][2]string, error) {
	var results []json.RawMessage
	err := b.credential.Use(func(admin []byte) error {
		var err error
		results, err = b.eapi(ctx, b.admin, admin, true, []eapiCommand{{cmd: []byte("enable")}, {cmd: []byte("show running-config section username")}})
		return err
	})
	if err != nil {
		return nil, err
	}
	var text struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal(results[1], &text); err != nil {
		return nil, errors.New("dynsecret eos: the running configuration was unreadable")
	}
	accounts := map[string][2]string{}
	for _, m := range eosUsername.FindAllStringSubmatch(text.Output, -1) {
		privilege := m[2]
		if privilege == "" {
			privilege = "1"
		}
		accounts[m[1]] = [2]string{privilege, m[3]}
	}
	return accounts, nil
}

// set changes account's password (or EOS's enable password) and saves the
// configuration where the device needs it.
func (b *NetworkAPIBackend) set(ctx context.Context, account string, password []byte) error {
	switch b.vendor {
	case "eos":
		if err := cliPassword(password); err != nil {
			return err
		}
		change := append([]byte("enable password 0 "), password...)
		if account != NetworkEnableAccount {
			accounts, err := b.eosAccounts(ctx)
			if err != nil {
				return err
			}
			current, ok := accounts[account]
			if !ok {
				return fmt.Errorf("dynsecret eos: account %q is not on the device", account)
			}
			prefix := "username " + account + " privilege " + current[0]
			if current[1] != "" {
				prefix += " role " + current[1]
			}
			secret.Wipe(change)
			change = append([]byte(prefix+" secret 0 "), password...)
		}
		defer secret.Wipe(change)
		return b.credential.Use(func(admin []byte) error {
			_, err := b.eapi(ctx, b.admin, admin, false, []eapiCommand{{cmd: []byte("enable")}, {cmd: []byte("configure")}, {cmd: change},
				{cmd: []byte("end")}, {cmd: []byte("copy running-config startup-config")}})
			return err
		})
	case "fortigate":
		value, err := secret.JSONBytes(password).MarshalJSON()
		if err != nil {
			return err
		}
		body := append(append([]byte(`{"password":`), value...), '}')
		secret.Wipe(value)
		defer secret.Wipe(body)
		return b.credential.Use(func(token []byte) error {
			status, raw, _, err := b.do(ctx, http.MethodPut, "/api/v2/cmdb/system/admin/"+url.PathEscape(account),
				http.Header{"Content-Type": {"application/json"}, "Authorization": {bearer(token)}}, body)
			if err != nil {
				return err
			}
			defer secret.Wipe(raw)
			var reply struct {
				Status string `json:"status"`
			}
			if status == http.StatusUnauthorized {
				return fmt.Errorf("%w: dynsecret fortigate: the device refused the API token (HTTP %d)", ErrSignInRejected, status)
			}
			if status != http.StatusOK || json.Unmarshal(raw, &reply) != nil || reply.Status != "success" {
				return fmt.Errorf("dynsecret fortigate: the device refused the change (HTTP %d)", status)
			}
			return nil
		})
	case "bigip":
		value, err := secret.JSONBytes(password).MarshalJSON()
		if err != nil {
			return err
		}
		body := append(append([]byte(`{"password":`), value...), '}')
		secret.Wipe(value)
		defer secret.Wipe(body)
		return b.bigipSession(ctx, func(token []byte) error {
			header := http.Header{"Content-Type": {"application/json"}, "X-F5-Auth-Token": {string(token)}}
			status, raw, _, err := b.do(ctx, http.MethodPatch, "/mgmt/tm/auth/user/"+url.PathEscape(account), header, body)
			secret.Wipe(raw)
			if err != nil {
				return err
			}
			if status != http.StatusOK {
				return fmt.Errorf("dynsecret bigip: the device refused the change (HTTP %d)", status)
			}
			status, raw, _, err = b.do(ctx, http.MethodPost, "/mgmt/tm/sys/config", header, []byte(`{"command":"save"}`))
			secret.Wipe(raw)
			if err != nil {
				return err
			}
			if status != http.StatusOK {
				return fmt.Errorf("dynsecret bigip: the device did not save its configuration (HTTP %d)", status)
			}
			return nil
		})
	}
	return errors.New("dynsecret network: unknown device API")
}

func bearer(token []byte) string { return "Bearer " + string(token) }

// bigipLogin signs in to iControl REST and returns the session token.
func (b *NetworkAPIBackend) bigipLogin(ctx context.Context, user string, password []byte) ([]byte, error) {
	value, err := secret.JSONBytes(password).MarshalJSON()
	if err != nil {
		return nil, err
	}
	name, _ := json.Marshal(user)
	body := append(append(append(append([]byte(`{"username":`), name...), `,"password":`...), value...), `,"loginProviderName":"tmos"}`...)
	secret.Wipe(value)
	defer secret.Wipe(body)
	status, raw, _, err := b.do(ctx, http.MethodPost, "/mgmt/shared/authn/login", http.Header{"Content-Type": {"application/json"}}, body)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(raw)
	if status == http.StatusUnauthorized {
		// iControl REST answers a refused user name or password with 401.
		return nil, fmt.Errorf("%w: dynsecret bigip: the device refused %s's sign-in (HTTP %d)", ErrSignInRejected, user, status)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("dynsecret bigip: the device refused %s's sign-in (HTTP %d)", user, status)
	}
	var reply struct {
		Token struct {
			Token secret.JSONBytes `json:"token"`
		} `json:"token"`
	}
	if json.Unmarshal(raw, &reply) != nil || len(reply.Token.Token) == 0 {
		secret.Wipe(reply.Token.Token)
		return nil, errors.New("dynsecret bigip: the sign-in returned no token")
	}
	return reply.Token.Token, nil
}

// bigipLogout ends a token so it cannot be replayed.
func (b *NetworkAPIBackend) bigipLogout(ctx context.Context, token []byte) {
	header := http.Header{"X-F5-Auth-Token": {string(token)}}
	_, raw, _, _ := b.do(ctx, http.MethodDelete, "/mgmt/shared/authz/tokens/"+url.PathEscape(string(token)), header, nil)
	secret.Wipe(raw)
}

func (b *NetworkAPIBackend) bigipSession(ctx context.Context, fn func(token []byte) error) error {
	return b.credential.Use(func(admin []byte) error {
		token, err := b.bigipLogin(ctx, b.admin, admin)
		if err != nil {
			return err
		}
		defer secret.Wipe(token)
		defer b.bigipLogout(context.WithoutCancel(ctx), token)
		return fn(token)
	})
}

// VerifyCredential proves the credential signs in through the device's own
// sign-in; EOS's enable password is proved by entering privileged mode.
func (b *NetworkAPIBackend) VerifyCredential(ctx context.Context, credential []byte) error {
	var parsed struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || parsed.Username == "" || len(parsed.Password) == 0 {
		return errors.New("dynsecret network: the credential carries no account and password")
	}
	defer secret.Wipe(parsed.Password)
	switch b.vendor {
	case "eos":
		if parsed.Username == NetworkEnableAccount {
			return b.credential.Use(func(admin []byte) error {
				_, err := b.eapi(ctx, b.admin, admin, false, []eapiCommand{{cmd: []byte("disable")}, {cmd: []byte("enable"), input: parsed.Password}})
				return err
			})
		}
		_, err := b.eapi(ctx, parsed.Username, parsed.Password, false, []eapiCommand{{cmd: []byte("show version")}})
		return err
	case "fortigate":
		return b.fortigateSignIn(ctx, parsed.Username, parsed.Password)
	case "bigip":
		token, err := b.bigipLogin(ctx, parsed.Username, parsed.Password)
		if err != nil {
			return err
		}
		b.bigipLogout(ctx, token)
		secret.Wipe(token)
		return nil
	}
	return errors.New("dynsecret network: unknown device API")
}

// fortigateSignIn signs in at /logincheck and logs the session out.
func (b *NetworkAPIBackend) fortigateSignIn(ctx context.Context, user string, password []byte) error {
	body := append([]byte("username="+url.QueryEscape(user)+"&secretkey="), queryEscapeBytes(password)...)
	body = append(body, "&ajax=1"...)
	defer secret.Wipe(body)
	status, raw, cookies, err := b.do(ctx, http.MethodPost, "/logincheck", http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, body)
	if err != nil {
		return err
	}
	ok := status == http.StatusOK && bytes.HasPrefix(raw, []byte("1"))
	secret.Wipe(raw)
	csrf := ""
	for _, c := range cookies {
		if c.Name == "ccsrftoken" {
			csrf = strings.Trim(c.Value, `"`)
		}
	}
	if status == http.StatusUnauthorized || (status == http.StatusOK && !ok) {
		// FortiOS answers a refused /logincheck with a body that is not "1".
		return fmt.Errorf("%w: dynsecret fortigate: the device refused %s's sign-in", ErrSignInRejected, user)
	}
	if !ok || csrf == "" {
		return fmt.Errorf("dynsecret fortigate: the device refused %s's sign-in", user)
	}
	header := http.Header{"X-CSRFTOKEN": {csrf}}
	for _, c := range cookies {
		header.Add("Cookie", c.Name+"="+c.Value)
	}
	_, raw, _, _ = b.do(ctx, http.MethodPost, "/logout", header, nil)
	secret.Wipe(raw)
	return nil
}

// queryEscapeBytes form-encodes a secret without making it a string.
func queryEscapeBytes(b []byte) []byte {
	const hexDigits = "0123456789ABCDEF"
	out := make([]byte, 0, len(b)*3)
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			out = append(out, c)
		case c == ' ':
			out = append(out, '+')
		default:
			out = append(out, '%', hexDigits[c>>4], hexDigits[c&0x0f])
		}
	}
	return out
}

// RestoreStaticCredential puts role's predecessor back on the device and
// proves it signs in again (the rollback of a failed rotation).
func (b *NetworkAPIBackend) RestoreStaticCredential(ctx context.Context, role, _ string, credential []byte) error {
	account, ok := b.accounts[role]
	var parsed struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || !ok || parsed.Username != account || len(parsed.Password) == 0 {
		return errors.New("dynsecret network: the predecessor is not this role's account credential")
	}
	defer secret.Wipe(parsed.Password)
	if err := b.set(ctx, account, parsed.Password); err != nil {
		return err
	}
	return b.VerifyCredential(ctx, credential)
}

// Revoke implements Backend: the predecessor stopped working when the next
// password was set, so retiring it has nothing left to do.
func (b *NetworkAPIBackend) Revoke(_ context.Context, ref string) error {
	account, _, _ := strings.Cut(ref, "/")
	for _, bound := range b.accounts {
		if account == bound {
			return nil
		}
	}
	return fmt.Errorf("dynsecret %s: refusing %q, which names no account this provider rotates", b.vendor, ref)
}

// DiscoverPrivilegedAccounts lists the device's local accounts with their
// privilege and role (EOS), access profile (FortiGate) or partition roles
// (BIG-IP); password hashes are never read into the result.
func (b *NetworkAPIBackend) DiscoverPrivilegedAccounts(ctx context.Context) ([]pamdiscovery.Account, error) {
	var accounts []pamdiscovery.Account
	add := func(name string, privileges ...string) {
		accounts = append(accounts, pamdiscovery.Account{Key: "user:" + name, Name: name, Kind: "local_user", Privileges: privileges,
			Details: map[string]string{"device": b.vendor}})
	}
	switch b.vendor {
	case "eos":
		found, err := b.eosAccounts(ctx)
		if err != nil {
			return nil, err
		}
		for name, level := range found {
			if level[1] != "" {
				add(name, "privilege "+level[0], "role "+level[1])
			} else {
				add(name, "privilege "+level[0])
			}
		}
	case "fortigate":
		err := b.credential.Use(func(token []byte) error {
			status, raw, _, err := b.do(ctx, http.MethodGet, "/api/v2/cmdb/system/admin", http.Header{"Authorization": {bearer(token)}}, nil)
			if err != nil {
				return err
			}
			defer secret.Wipe(raw)
			var reply struct {
				Results []struct {
					Name       string `json:"name"`
					AccProfile string `json:"accprofile"`
				} `json:"results"`
			}
			if status == http.StatusUnauthorized {
				// The REST API administrator's token was refused.
				return fmt.Errorf("%w: dynsecret fortigate: the device refused the API token (HTTP %d)", ErrSignInRejected, status)
			}
			if status != http.StatusOK || json.Unmarshal(raw, &reply) != nil {
				return fmt.Errorf("dynsecret fortigate: the administrator list was unreadable (HTTP %d)", status)
			}
			for _, r := range reply.Results {
				add(r.Name, "accprofile "+r.AccProfile)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	case "bigip":
		err := b.bigipSession(ctx, func(token []byte) error {
			status, raw, _, err := b.do(ctx, http.MethodGet, "/mgmt/tm/auth/user", http.Header{"X-F5-Auth-Token": {string(token)}}, nil)
			if err != nil {
				return err
			}
			defer secret.Wipe(raw)
			var reply struct {
				Items []struct {
					Name            string `json:"name"`
					PartitionAccess []struct {
						Name string `json:"name"`
						Role string `json:"role"`
					} `json:"partitionAccess"`
				} `json:"items"`
			}
			if status != http.StatusOK || json.Unmarshal(raw, &reply) != nil {
				return fmt.Errorf("dynsecret bigip: the user list was unreadable (HTTP %d)", status)
			}
			for _, item := range reply.Items {
				var privileges []string
				for _, p := range item.PartitionAccess {
					privileges = append(privileges, "role "+p.Role+" on "+p.Name)
				}
				add(item.Name, privileges...)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(accounts) > pamdiscovery.MaxAccounts {
		return nil, errors.New("dynsecret network: more accounts than one discovery holds")
	}
	return accounts, nil
}

// Close wipes the administrator's credential.
func (b *NetworkAPIBackend) Close() { b.credential.Destroy() }
