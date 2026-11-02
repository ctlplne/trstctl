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
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
)

var (
	snowflakeRole    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]{0,254}$`)
	snowflakeAccount = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,254}$`)
	snowflakeUser    = regexp.MustCompile(`^[A-Z0-9_]{1,255}$`)
	snowflakeHandle  = regexp.MustCompile(`^[0-9a-f-]{1,64}$`)
)

// ParseSnowflakeRoles reads a role binding: the Snowflake roles a lease's user
// is granted, comma separated, for example "ANALYST". Names are unquoted
// Snowflake identifiers, so they are upper-cased as Snowflake would.
func ParseSnowflakeRoles(binding string) ([]string, error) {
	var roles []string
	for _, role := range strings.Split(binding, ",") {
		role = strings.TrimSpace(role)
		if !snowflakeRole.MatchString(role) {
			return nil, fmt.Errorf("role %q is not a Snowflake role name", role)
		}
		roles = append(roles, strings.ToUpper(role))
	}
	return roles, nil
}

// SnowflakeConfig configures the Snowflake provider (A239): each lease is a
// service user (TYPE = SERVICE) that authenticates with a key pair the
// provider generates, granted only its role's roles, and expiring in Snowflake
// itself after the provider's maximum lifetime (DAYS_TO_EXPIRY, whole days);
// revocation disables the user, which aborts its running queries, and drops
// it. No password exists, so none reaches SQL text or query history.
type SnowflakeConfig struct {
	// Endpoint is the account URL, https://<account>.snowflakecomputing.com.
	Endpoint string
	// Account is the account identifier the key-pair JWT names
	// (<orgname>-<accountname>).
	Account string
	// AdminUser and AdminPrivateKey are a user allowed to create, alter and
	// drop users and grant the bound roles (USERADMIN or SECURITYADMIN), and
	// the private key registered for it.
	AdminUser       string
	AdminPrivateKey []byte
	RoleBindings    map[string]string
	UsernamePrefix  string
	MaxLifetime     time.Duration
	// AllowInsecureLoopback admits a loopback http:// stand-in for tests.
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
	Now                   func() time.Time
}

// SnowflakeBackend issues Snowflake service users.
type SnowflakeBackend struct {
	endpoint   string
	account    string
	adminUser  string
	adminKey   *secret.Buffer
	roles      map[string][]string
	prefix     string
	expiryDays int
	client     *http.Client
	now        func() time.Time
}

// NewSnowflakeBackend validates cfg.
func NewSnowflakeBackend(cfg SnowflakeConfig) (*SnowflakeBackend, error) {
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(cfg.Endpoint, cfg.AllowInsecureLoopback); err != nil {
		return nil, fmt.Errorf("dynsecret snowflake: endpoint: %w", err)
	}
	if !snowflakeAccount.MatchString(cfg.Account) {
		return nil, errors.New("dynsecret snowflake: the account identifier must be <orgname>-<accountname>")
	}
	if strings.TrimSpace(cfg.AdminUser) == "" || len(cfg.AdminPrivateKey) == 0 || cfg.HTTPClient == nil {
		return nil, errors.New("dynsecret snowflake: the administrator user, its private key and an HTTP client are required")
	}
	if cfg.MaxLifetime < time.Minute {
		return nil, errors.New("dynsecret snowflake: the maximum lifetime must be at least a minute")
	}
	b := &SnowflakeBackend{endpoint: strings.TrimRight(cfg.Endpoint, "/"), account: strings.ToUpper(strings.ReplaceAll(cfg.Account, ".", "-")),
		adminUser: strings.ToUpper(cfg.AdminUser), roles: map[string][]string{}, prefix: cfg.UsernamePrefix,
		expiryDays: int(math.Ceil(cfg.MaxLifetime.Hours() / 24)), client: cfg.HTTPClient, now: cfg.Now}
	if b.now == nil {
		b.now = time.Now
	}
	for role, binding := range cfg.RoleBindings {
		roles, err := ParseSnowflakeRoles(binding)
		if err != nil {
			return nil, fmt.Errorf("dynsecret snowflake: role %q: %w", role, err)
		}
		b.roles[role] = roles
	}
	if len(b.roles) == 0 {
		return nil, errors.New("dynsecret snowflake: every allowed role needs Snowflake roles in role_bindings")
	}
	if _, err := crypto.PublicKeyDERFromPEMKey(cfg.AdminPrivateKey); err != nil {
		return nil, fmt.Errorf("dynsecret snowflake: the administrator private key: %w", err)
	}
	var err error
	if b.adminKey, err = secret.NewFrom(cfg.AdminPrivateKey); err != nil {
		return nil, err
	}
	return b, nil
}

// SnowflakeKeyFingerprint is the public key fingerprint Snowflake's key-pair
// JWT issuer names: "SHA256:" and the base64 of the SubjectPublicKeyInfo's
// SHA-256.
func SnowflakeKeyFingerprint(publicKeyDER []byte) string {
	return "SHA256:" + base64.StdEncoding.EncodeToString(crypto.SHA256Sum(publicKeyDER))
}

// SnowflakeKeyPairJWT is the JWT a user authenticates to Snowflake with: RS256
// over {iss: <ACCOUNT>.<USER>.<fingerprint>, sub: <ACCOUNT>.<USER>}, valid an
// hour at most (Snowflake's limit), signed by the user's private key.
func SnowflakeKeyPairJWT(account, user string, privateKeyPEM []byte, now time.Time) (string, error) {
	der, err := crypto.PublicKeyDERFromPEMKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	qualified := strings.ToUpper(account) + "." + strings.ToUpper(user)
	return crypto.SignJWTWithPEMKey(privateKeyPEM, "", map[string]any{
		"iss": qualified + "." + SnowflakeKeyFingerprint(der), "sub": qualified,
		"iat": now.Unix(), "exp": now.Add(59 * time.Minute).Unix(),
	})
}

// RevocationConfirmed reports that revocation disables and drops the user.
func (b *SnowflakeBackend) RevocationConfirmed() bool { return true }

// Create implements Backend.
func (b *SnowflakeBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend. The user's name derives from the
// lease, and every statement finds what an earlier attempt left (CREATE USER IF
// NOT EXISTS, then the new key is set and the user enabled; a grant already
// held stays), so a retry after an uncertain attempt converges on one user with
// the new key. If a grant fails, the user is disabled and dropped again.
func (b *SnowflakeBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New("dynsecret snowflake: static credentials are not served")
	}
	roles, ok := b.roles[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret snowflake: role %q has no Snowflake roles", req.Role)
	}
	name, err := scopedNameForRequest(b.prefix, req, 255, "_")
	if err != nil {
		return "", nil, err
	}
	user := strings.ToUpper(name)
	if !snowflakeUser.MatchString(user) {
		return "", nil, fmt.Errorf("dynsecret snowflake: generated user name %q is not plain", user)
	}
	key, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		return "", nil, err
	}
	defer key.Destroy()
	privateKeyPEM, err := key.PrivateKeyPEM()
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(privateKeyPEM)
	publicKey := base64.StdEncoding.EncodeToString(key.Public().DER)
	quoted := `"` + user + `"`
	statements := []string{
		fmt.Sprintf(`CREATE USER IF NOT EXISTS %s TYPE = SERVICE RSA_PUBLIC_KEY = '%s' DEFAULT_ROLE = "%s" DAYS_TO_EXPIRY = %d COMMENT = 'trstctl dynamic secret'`,
			quoted, publicKey, roles[0], b.expiryDays),
		fmt.Sprintf(`ALTER USER %s SET RSA_PUBLIC_KEY = '%s' DISABLED = FALSE DAYS_TO_EXPIRY = %d`, quoted, publicKey, b.expiryDays),
	}
	for _, statement := range statements {
		if err := b.execute(ctx, statement); err != nil {
			return "", nil, fmt.Errorf("dynsecret snowflake: create user %s: %w", user, err)
		}
	}
	for _, role := range roles {
		if err := b.execute(ctx, fmt.Sprintf(`GRANT ROLE "%s" TO USER %s`, role, quoted)); err != nil {
			_ = b.Revoke(ctx, user)
			return "", nil, fmt.Errorf("dynsecret snowflake: grant role %s to %s: %w", role, user, err)
		}
	}
	expiresAt := b.now().UTC().Add(time.Duration(b.expiryDays) * 24 * time.Hour).Truncate(time.Second)
	credential, err := json.Marshal(struct { // #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
		Account       string           `json:"account"`
		User          string           `json:"user"`
		PrivateKey    secret.JSONBytes `json:"private_key"`
		Role          string           `json:"role"`
		UserExpiresAt time.Time        `json:"user_expires_at"`
	}{Account: b.account, User: user, PrivateKey: privateKeyPEM, Role: roles[0], UserExpiresAt: expiresAt})
	if err != nil {
		return "", nil, err
	}
	return user, credential, nil
}

// Revoke implements Backend: the user is disabled, which aborts its running
// queries and refuses its logins, then dropped. Only users this provider names
// are touched; one already gone counts as revoked.
func (b *SnowflakeBackend) Revoke(ctx context.Context, ref string) error {
	if !snowflakeUser.MatchString(ref) || !issuedPrincipalName(b.prefix, ref) {
		return fmt.Errorf("dynsecret snowflake: refusing to drop %q, which this provider did not create", ref)
	}
	for _, statement := range []string{
		fmt.Sprintf(`ALTER USER IF EXISTS "%s" SET DISABLED = TRUE`, ref),
		fmt.Sprintf(`DROP USER IF EXISTS "%s"`, ref),
	} {
		if err := b.execute(ctx, statement); err != nil {
			return fmt.Errorf("dynsecret snowflake: revoke %s: %w", ref, err)
		}
	}
	return nil
}

// execute runs one statement through the SQL API as the administrator,
// waiting (bounded) while Snowflake answers 202 for a statement still running.
func (b *SnowflakeBackend) execute(ctx context.Context, statement string) error {
	var jwt string
	if err := b.adminKey.Use(func(key []byte) error {
		var err error
		jwt, err = SnowflakeKeyPairJWT(b.account, b.adminUser, key, b.now())
		return err
	}); err != nil {
		return fmt.Errorf("sign the key-pair JWT: %w", err)
	}
	body, err := json.Marshal(map[string]any{"statement": statement, "timeout": 60})
	if err != nil {
		return err
	}
	status, response, err := b.call(ctx, http.MethodPost, "/api/v2/statements", jwt, body)
	for attempt := 0; err == nil && status == http.StatusAccepted && attempt < 30; attempt++ {
		var pending struct {
			Handle string `json:"statementHandle"`
		}
		if json.Unmarshal(response, &pending) != nil || !snowflakeHandle.MatchString(pending.Handle) {
			return errors.New("the SQL API answered 202 without a statement handle")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		status, response, err = b.call(ctx, http.MethodGet, "/api/v2/statements/"+pending.Handle, jwt, nil)
	}
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		var failure struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(response, &failure)
		return fmt.Errorf("the SQL API answered HTTP %d (code %s): %s", status, failure.Code, failure.Message)
	}
	return nil
}

func (b *SnowflakeBackend) call(ctx context.Context, method, path, jwt string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, b.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Snowflake-Authorization-Token-Type", "KEYPAIR_JWT")
	resp, err := b.client.Do(req) // #nosec G704 -- the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918)
	if err != nil {
		return 0, nil, fmt.Errorf("dynsecret snowflake: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	response, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return 0, nil, fmt.Errorf("dynsecret snowflake: read the response: %w", err)
	}
	return resp.StatusCode, response, nil
}

// Close wipes the administrator's private key.
func (b *SnowflakeBackend) Close() { b.adminKey.Destroy() }
