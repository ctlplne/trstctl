// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	hdb "github.com/SAP/go-hdb/driver"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

// hanaName is a role name this provider quotes (ESCAPE_DOUBLE_QUOTES) as SAP
// HANA stores it, or a user name, which it upper-cases and splices bare.
var hanaName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,126}$`)

// hanaUser is a user name as this provider issues and splices it: bare
// upper case, the form SAP HANA stores an unquoted name in.
var hanaUser = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,126}$`)

// The SQLScript below never carries a value in its text: the password
// arrives as a VARBINARY bind the database turns into the quoted password it
// splices into the DDL it runs itself, a role name is quoted the same way
// (ESCAPE_DOUBLE_QUOTES), and a user name is spliced bare, because SAP HANA's
// CREATE, ALTER and DROP USER and a GRANT's grantee take a bare user name, not
// a quoted identifier (CI 41597708898: error 257 "incorrect syntax near" the
// opening quote). Bare is safe: the provider names users itself, upper case,
// matching hanaName, before any statement runs. Each statement is built in a
// variable and run as EXEC :stmt (CI 41585418047: error 257 to EXEC of a
// concatenated expression).
const (
	hanaUpsertUser = `DO (IN uname NVARCHAR(256) => ?, IN pw VARBINARY(256) => ?) BEGIN
  DECLARE n INTEGER;
  DECLARE secret_literal NVARCHAR(1024);
  DECLARE stmt NVARCHAR(2048);
  secret_literal = '"' || ESCAPE_DOUBLE_QUOTES(BINTOSTR(:pw)) || '"';
  SELECT COUNT(*) INTO n FROM SYS.USERS WHERE USER_NAME = :uname;
  IF :n = 0 THEN
    stmt = 'CREATE USER ' || :uname || ' PASSWORD ' || :secret_literal || ' NO FORCE_FIRST_PASSWORD_CHANGE';
    EXEC :stmt;
  ELSE
    stmt = 'ALTER USER ' || :uname || ' PASSWORD ' || :secret_literal || ' NO FORCE_FIRST_PASSWORD_CHANGE';
    EXEC :stmt;
    stmt = 'ALTER USER ' || :uname || ' ACTIVATE USER NOW';
    EXEC :stmt;
  END IF;
  stmt = 'ALTER USER ' || :uname || ' DISABLE PASSWORD LIFETIME';
  EXEC :stmt;
END`
	hanaGrantRole = `DO (IN rname NVARCHAR(256) => ?, IN uname NVARCHAR(256) => ?) BEGIN
  DECLARE n INTEGER;
  DECLARE stmt NVARCHAR(1024);
  SELECT COUNT(*) INTO n FROM SYS.GRANTED_ROLES WHERE GRANTEE = :uname AND ROLE_NAME = :rname;
  IF :n = 0 THEN
    stmt = 'GRANT "' || ESCAPE_DOUBLE_QUOTES(:rname) || '" TO ' || :uname;
    EXEC :stmt;
  END IF;
END`
	// hanaRevokeUser deactivates the user so no session starts, disconnects
	// the ones open, and drops it with what it owns.
	hanaRevokeUser = `DO (IN uname NVARCHAR(256) => ?) BEGIN
  DECLARE n INTEGER;
  DECLARE stmt NVARCHAR(1024);
  DECLARE CURSOR sessions FOR SELECT CONNECTION_ID FROM SYS.M_CONNECTIONS WHERE USER_NAME = :uname AND OWN = 'FALSE' AND CONNECTION_STATUS <> '';
  SELECT COUNT(*) INTO n FROM SYS.USERS WHERE USER_NAME = :uname;
  IF :n > 0 THEN
    stmt = 'ALTER USER ' || :uname || ' DEACTIVATE USER NOW';
    EXEC :stmt;
    FOR s AS sessions DO
      stmt = 'ALTER SYSTEM DISCONNECT SESSION ''' || TO_NVARCHAR(s.CONNECTION_ID) || '''';
      EXEC :stmt;
    END FOR;
    stmt = 'DROP USER ' || :uname || ' CASCADE';
    EXEC :stmt;
  END IF;
END`
)

// HANAProbeUpsertUser is the user upsert block, for the lab's diagnostic
// probe (A239): the probe runs it with a fabricated user and password, so
// SAP HANA's whole answer, which can quote the statement, may be logged.
const HANAProbeUpsertUser = hanaUpsertUser

// HANAConfig configures the SAP HANA provider (A239).
type HANAConfig struct {
	// AdminDSN is the administrator's go-hdb URL (hdb://user:password@host:port),
	// whose address and options a credential is verified at.
	AdminDSN []byte
	// RoleBindings maps each allowed role to the existing HANA roles its
	// users are granted, comma separated, for example "ORDERS_READER".
	RoleBindings   map[string]string
	UsernamePrefix string
}

// HANABackend issues SAP HANA users granted roles.
type HANABackend struct {
	exec      SQLExecutor
	roles     map[string][]string
	prefix    string
	verifyURL *url.URL
}

// NewHANABackend validates cfg; exec runs as an administrator allowed to
// create, alter and drop users, grant the bound roles and disconnect
// sessions (USER ADMIN, the roles WITH ADMIN OPTION, SESSION ADMIN and
// CATALOG READ).
func NewHANABackend(exec SQLExecutor, cfg HANAConfig) (*HANABackend, error) {
	if exec == nil {
		return nil, errors.New("dynsecret hana: executor required")
	}
	b := &HANABackend{exec: exec, roles: map[string][]string{}, prefix: cfg.UsernamePrefix}
	parsed, err := url.Parse(secrettext.String(bytes.TrimRight(cfg.AdminDSN, "\r\n")))
	if err != nil || parsed.Scheme != "hdb" || parsed.Host == "" {
		return nil, errors.New("dynsecret hana: the admin DSN must be an hdb:// URL with a host")
	}
	parsed.User = nil
	b.verifyURL = parsed
	for role, binding := range cfg.RoleBindings {
		for _, name := range strings.Split(binding, ",") {
			name = strings.TrimSpace(name)
			if !hanaName.MatchString(name) {
				return nil, fmt.Errorf("dynsecret hana: role %q: %q is not a HANA role name", role, name)
			}
			b.roles[role] = append(b.roles[role], name)
		}
	}
	if len(b.roles) == 0 {
		return nil, errors.New("dynsecret hana: every allowed role needs HANA roles in role_bindings")
	}
	return b, nil
}

// Create implements Backend.
func (b *HANABackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend. The user's name derives from
// the lease and every step finds what an earlier attempt left (the user gets
// the new password and is reactivated, a role it holds stays), so a retry
// after an uncertain attempt converges on one user; if a grant fails the new
// user is dropped again.
func (b *HANABackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New("dynsecret hana: static credentials are not served")
	}
	roles, ok := b.roles[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret hana: role %q has no HANA roles", req.Role)
	}
	name, err := scopedNameForRequest(b.prefix, req, 127, "_")
	if err != nil {
		return "", nil, err
	}
	user := strings.ToUpper(name)
	if !hanaUser.MatchString(user) {
		return "", nil, fmt.Errorf("dynsecret hana: generated user name %q is not plain", user)
	}
	password, err := randomPolicyPassword(32)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	if _, err := b.exec.ExecContext(ctx, hanaUpsertUser, user, password); err != nil {
		return "", nil, fmt.Errorf("dynsecret hana: create %s failed (%s)", user, hanaErrorCode(err))
	}
	for _, role := range roles {
		if _, err := b.exec.ExecContext(ctx, hanaGrantRole, role, user); err != nil {
			if _, cleanup := b.exec.ExecContext(ctx, hanaRevokeUser, user); cleanup != nil {
				return "", nil, fmt.Errorf("dynsecret hana: grant %s to %s failed (%s), and dropping the new user failed (%s)",
					role, user, hanaErrorCode(err), hanaErrorCode(cleanup))
			}
			return "", nil, fmt.Errorf("dynsecret hana: grant %s to %s failed (%s)", role, user, hanaErrorCode(err))
		}
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}{Username: user, Password: password})
	if err != nil {
		return "", nil, err
	}
	return user, credential, nil
}

// Revoke implements Backend: the user is deactivated, its sessions are
// disconnected and it is dropped, so its next login fails. Only users this
// provider names are dropped; one already gone counts as revoked.
func (b *HANABackend) Revoke(ctx context.Context, ref string) error {
	if !hanaUser.MatchString(ref) || !issuedPrincipalName(b.prefix, ref) {
		return fmt.Errorf("dynsecret hana: refusing to drop %q, which this provider did not create", ref)
	}
	if _, err := b.exec.ExecContext(ctx, hanaRevokeUser, ref); err != nil {
		return fmt.Errorf("dynsecret hana: drop %s failed (%s)", ref, hanaErrorCode(err))
	}
	return nil
}

// VerifyCredential connects as the credential's user to the administrator's
// address and selects from DUMMY.
func (b *HANABackend) VerifyCredential(ctx context.Context, credential []byte) error {
	var parsed struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || parsed.Username == "" || len(parsed.Password) == 0 {
		return errors.New("dynsecret hana: the credential is not a username and password")
	}
	defer secret.Wipe(parsed.Password)
	target := *b.verifyURL
	target.User = url.UserPassword(parsed.Username, secrettext.String(parsed.Password))
	db, err := sql.Open(hdb.DriverName, target.String())
	if err != nil {
		return errors.New("dynsecret hana: open the credential's connection failed")
	}
	defer func() { _ = db.Close() }()
	verifyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var one int
	if err := db.QueryRowContext(verifyCtx, "SELECT 1 FROM DUMMY").Scan(&one); err != nil || one != 1 {
		return fmt.Errorf("dynsecret hana: the credential did not connect (%s)", hanaErrorCode(err))
	}
	return nil
}

// hanaErrorCode names a failure by SAP HANA's error code only: a server
// message can quote the statement.
func hanaErrorCode(err error) string {
	var db hdb.Error
	if errors.As(err, &db) {
		return fmt.Sprintf("SAP HANA error %d", db.Code())
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err.Error()
	}
	return "connection error"
}

// OpenHANAExecutor opens and verifies a go-hdb client from an admin URL
// (hdb://user:password@host:port). Callers close it after the operation,
// keeping the authority-bearing URL out of long-lived state.
func OpenHANAExecutor(ctx context.Context, adminDSN []byte) (*sql.DB, error) {
	adminDSN = bytes.TrimRight(adminDSN, "\r\n")
	if len(adminDSN) == 0 {
		return nil, errors.New("dynsecret hana: admin DSN required")
	}
	db, err := sql.Open(hdb.DriverName, secrettext.String(adminDSN))
	if err != nil {
		return nil, errors.New("dynsecret hana: open admin connection failed")
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("dynsecret hana: ping admin connection failed (%s)", hanaErrorCode(err))
	}
	return db, nil
}
