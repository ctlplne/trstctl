// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	go_ora "github.com/sijms/go-ora/v2"
	"github.com/sijms/go-ora/v2/network"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

// oracleName is a user or role name this provider passes to
// DBMS_ASSERT.ENQUOTE_NAME, exactly as Oracle stores it (an unquoted name is
// stored in upper case).
var oracleName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_$#]{0,127}$`)

// The PL/SQL below never carries a password in its text: it arrives as a RAW
// bind, which the database turns into the quoted identifier it splices into
// the DDL it runs itself. Names arrive as binds too and are quoted by
// DBMS_ASSERT.ENQUOTE_NAME, which refuses a name it cannot quote.
const (
	oracleUpsertUser = `DECLARE
  uname VARCHAR2(128) := :username;
  pw VARCHAR2(130) := DBMS_ASSERT.ENQUOTE_NAME(UTL_RAW.CAST_TO_VARCHAR2(:password), FALSE);
  n NUMBER;
BEGIN
  SELECT COUNT(*) INTO n FROM all_users WHERE username = uname;
  IF n = 0 THEN
    EXECUTE IMMEDIATE 'CREATE USER ' || DBMS_ASSERT.ENQUOTE_NAME(uname, FALSE) || ' IDENTIFIED BY ' || pw;
  ELSE
    EXECUTE IMMEDIATE 'ALTER USER ' || DBMS_ASSERT.ENQUOTE_NAME(uname, FALSE) || ' IDENTIFIED BY ' || pw || ' ACCOUNT UNLOCK';
  END IF;
  pw := NULL;
END;`
	oracleAlterUserIdentifiedBy = `DECLARE
  uname VARCHAR2(128) := :username;
  pw VARCHAR2(130) := DBMS_ASSERT.ENQUOTE_NAME(UTL_RAW.CAST_TO_VARCHAR2(:password), FALSE);
BEGIN
  EXECUTE IMMEDIATE 'ALTER USER ' || DBMS_ASSERT.ENQUOTE_NAME(uname, FALSE) || ' IDENTIFIED BY ' || pw;
  pw := NULL;
END;`
	oracleGrantRole = `BEGIN
  EXECUTE IMMEDIATE 'GRANT ' || DBMS_ASSERT.ENQUOTE_NAME(:role, FALSE) || ' TO ' || DBMS_ASSERT.ENQUOTE_NAME(:username, FALSE);
END;`
	// oracleEndSessions locks the account first when asked, so no session
	// starts, then kills the ones open: Oracle refuses to drop a connected
	// user, and a session outlives a password change. ORA-00030 (the session
	// is gone) and ORA-00031 (marked for kill) count as ended.
	oracleEndSessions = `DECLARE
  uname VARCHAR2(128) := :username;
  n NUMBER;
BEGIN
  SELECT COUNT(*) INTO n FROM all_users WHERE username = uname;
  IF n = 0 THEN
    RETURN;
  END IF;
  IF :lock_account = 1 THEN
    EXECUTE IMMEDIATE 'ALTER USER ' || DBMS_ASSERT.ENQUOTE_NAME(uname, FALSE) || ' ACCOUNT LOCK';
  END IF;
  FOR s IN (SELECT sid, serial# AS serial FROM v$session WHERE username = uname) LOOP
    BEGIN
      EXECUTE IMMEDIATE 'ALTER SYSTEM KILL SESSION ''' || s.sid || ',' || s.serial || ''' IMMEDIATE';
    EXCEPTION WHEN OTHERS THEN
      IF SQLCODE NOT IN (-30, -31) THEN
        RAISE;
      END IF;
    END;
  END LOOP;
END;`
	oracleDropUser = `DECLARE
  uname VARCHAR2(128) := :username;
  n NUMBER;
BEGIN
  SELECT COUNT(*) INTO n FROM all_users WHERE username = uname;
  IF n > 0 THEN
    EXECUTE IMMEDIATE 'DROP USER ' || DBMS_ASSERT.ENQUOTE_NAME(uname, FALSE) || ' CASCADE';
  END IF;
END;`
)

// oracleUserConnected is ORA-01940: a killed session can take a moment to go.
const oracleUserConnected = 1940

// OracleConfig configures the Oracle Database provider (A239, A240).
type OracleConfig struct {
	// AdminDSN is the administrator's go-ora URL
	// (oracle://user:password@host:1521/service), whose address and options a
	// credential is verified against.
	AdminDSN []byte
	// RoleBindings maps each allowed role to the existing Oracle roles its
	// users are granted, comma separated, for example "ORDERS_READER"; the
	// roles carry CREATE SESSION and the lease's privileges.
	RoleBindings   map[string]string
	UsernamePrefix string
	// RotationAccounts maps a role to the two existing users its static
	// rotation alternates between (A240).
	RotationAccounts map[string][2]string
}

// OracleBackend issues Oracle Database users granted roles, and rotates a
// role between two existing users.
type OracleBackend struct {
	exec             SQLExecutor
	roles            map[string][]string
	prefix           string
	rotationAccounts map[string][2]string
	host             string
	port             int
	service          string
	options          map[string]string
	retryWait        time.Duration
}

// NewOracleBackend validates cfg; exec runs as an administrator allowed to
// create, alter and drop users, grant the bound roles, and kill sessions
// (ALTER SYSTEM, and SELECT on V$SESSION).
func NewOracleBackend(exec SQLExecutor, cfg OracleConfig) (*OracleBackend, error) {
	if exec == nil {
		return nil, errors.New("dynsecret oracle: executor required")
	}
	b := &OracleBackend{exec: exec, roles: map[string][]string{}, prefix: cfg.UsernamePrefix,
		rotationAccounts: map[string][2]string{}, retryWait: 500 * time.Millisecond}
	if err := b.parseAddress(cfg.AdminDSN); err != nil {
		return nil, err
	}
	for role, binding := range cfg.RoleBindings {
		for _, name := range strings.Split(binding, ",") {
			name = strings.TrimSpace(name)
			if !oracleName.MatchString(name) {
				return nil, fmt.Errorf("dynsecret oracle: role %q: %q is not an Oracle role name", role, name)
			}
			b.roles[role] = append(b.roles[role], name)
		}
	}
	for role, pair := range cfg.RotationAccounts {
		if !oracleName.MatchString(pair[0]) || !oracleName.MatchString(pair[1]) || pair[0] == pair[1] {
			return nil, fmt.Errorf("dynsecret oracle: role %q needs two distinct Oracle user names to rotate between", role)
		}
		b.rotationAccounts[role] = pair
	}
	if len(b.roles) == 0 && len(b.rotationAccounts) == 0 {
		return nil, errors.New("dynsecret oracle: every allowed role needs Oracle roles in role_bindings or two rotation_accounts")
	}
	return b, nil
}

// parseAddress keeps the admin URL's address, service and options, never
// its credentials, so a leased credential can be verified at the same place.
func (b *OracleBackend) parseAddress(adminDSN []byte) error {
	adminDSN = bytes.TrimRight(adminDSN, "\r\n")
	parsed, err := url.Parse(secrettext.String(adminDSN))
	if err != nil || parsed.Scheme != "oracle" || parsed.Host == "" {
		return errors.New("dynsecret oracle: admin DSN must be oracle://user:password@host:port/service")
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		host, portText = parsed.Host, "1521"
	}
	port, err := strconv.Atoi(portText)
	if err != nil || host == "" || port < 1 || port > 65535 {
		return errors.New("dynsecret oracle: admin DSN needs host:port")
	}
	b.host, b.port, b.service = host, port, strings.TrimPrefix(parsed.Path, "/")
	if b.service == "" {
		return errors.New("dynsecret oracle: admin DSN needs a service name")
	}
	b.options = map[string]string{}
	for key, values := range parsed.Query() {
		b.options[key] = strings.Join(values, ",")
	}
	return nil
}

// Create implements Backend.
func (b *OracleBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend. A static request for a role
// with rotation_accounts sets a new password on the account the predecessor
// does not name (A240). Otherwise the user's name derives from the lease and
// every step finds what an earlier attempt left (the user gets the new
// password and is unlocked, a role it holds stays), so a retry after an
// uncertain attempt converges on one user; if a grant fails the new user is
// dropped again.
func (b *OracleBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if account, ok := TwoUserAccount(b.rotationAccounts, req.Role, req.Predecessor); ok && req.Static {
		return b.stageTwoUser(ctx, account)
	}
	if req.Static {
		return "", nil, errors.New("dynsecret oracle: static credentials need two rotation_accounts for the role")
	}
	roles, ok := b.roles[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret oracle: role %q has no Oracle roles", req.Role)
	}
	name, err := scopedNameForRequest(b.prefix, req, 128, "_")
	if err != nil {
		return "", nil, err
	}
	user := strings.ToUpper(name)
	if !oracleName.MatchString(user) {
		return "", nil, fmt.Errorf("dynsecret oracle: generated user name %q is not plain", user)
	}
	password, err := randomPolicyPassword(30)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	if _, err := b.exec.ExecContext(ctx, oracleUpsertUser, sql.Named("username", user), sql.Named("password", password)); err != nil {
		return "", nil, fmt.Errorf("dynsecret oracle: create %s failed (%s)", user, oracleErrorCode(err))
	}
	for _, role := range roles {
		if _, err := b.exec.ExecContext(ctx, oracleGrantRole, sql.Named("role", role), sql.Named("username", user)); err != nil {
			if cleanup := b.dropUser(ctx, user); cleanup != nil {
				return "", nil, fmt.Errorf("dynsecret oracle: grant %s to %s failed (%s), and dropping the new user failed: %v", role, user, oracleErrorCode(err), cleanup)
			}
			return "", nil, fmt.Errorf("dynsecret oracle: grant %s to %s failed (%s)", role, user, oracleErrorCode(err))
		}
	}
	credential, err := oracleCredential(user, password)
	if err != nil {
		return "", nil, err
	}
	return user, credential, nil
}

// stageTwoUser sets a new password on the role's inactive account (A240). A
// retry sets the same account's password again, so an uncertain attempt
// leaves no second credential; the predecessor is untouched.
func (b *OracleBackend) stageTwoUser(ctx context.Context, account string) (string, []byte, error) {
	password, err := randomPolicyPassword(30)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	if _, err := b.exec.ExecContext(ctx, oracleAlterUserIdentifiedBy, sql.Named("username", account), sql.Named("password", password)); err != nil {
		return "", nil, fmt.Errorf("dynsecret oracle: set the password of %s failed (%s)", account, oracleErrorCode(err))
	}
	credential, err := oracleCredential(account, password)
	if err != nil {
		return "", nil, err
	}
	return account, credential, nil
}

func oracleCredential(user string, password []byte) ([]byte, error) {
	return json.Marshal(struct { // #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}{Username: user, Password: password})
}

// Revoke implements Backend. A two-user account is retired, never dropped:
// it gets a password nobody holds and its sessions end, so its grants
// persist (A240). A leased user is locked, its sessions are killed, and it
// is dropped. Only users this provider names are dropped; one already gone
// counts as revoked.
func (b *OracleBackend) Revoke(ctx context.Context, ref string) error {
	if isRotationAccount(b.rotationAccounts, ref) {
		return b.retireTwoUser(ctx, ref)
	}
	if !oracleName.MatchString(ref) || !issuedPrincipalName(b.prefix, ref) {
		return fmt.Errorf("dynsecret oracle: refusing to drop %q, which this provider did not create", ref)
	}
	if _, err := b.exec.ExecContext(ctx, oracleEndSessions, sql.Named("username", ref), sql.Named("lock_account", 1)); err != nil {
		return fmt.Errorf("dynsecret oracle: end the sessions of %s failed (%s)", ref, oracleErrorCode(err))
	}
	return b.dropUser(ctx, ref)
}

// dropUser drops the user, waiting out sessions that are still going.
func (b *OracleBackend) dropUser(ctx context.Context, user string) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if _, err = b.exec.ExecContext(ctx, oracleDropUser, sql.Named("username", user)); err == nil {
			return nil
		}
		if oracleCode(err) != oracleUserConnected {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(b.retryWait):
		}
	}
	return fmt.Errorf("dynsecret oracle: drop %s failed (%s)", user, oracleErrorCode(err))
}

// retireTwoUser replaces the account's password with one nobody holds, then
// ends its sessions; the account is not locked, so the next cycle only sets a
// password.
func (b *OracleBackend) retireTwoUser(ctx context.Context, account string) error {
	scrambled, err := randomPolicyPassword(30)
	if err != nil {
		return err
	}
	defer secret.Wipe(scrambled)
	if _, err := b.exec.ExecContext(ctx, oracleAlterUserIdentifiedBy, sql.Named("username", account), sql.Named("password", scrambled)); err != nil {
		return fmt.Errorf("dynsecret oracle: retire %s failed (%s)", account, oracleErrorCode(err))
	}
	if _, err := b.exec.ExecContext(ctx, oracleEndSessions, sql.Named("username", account), sql.Named("lock_account", 0)); err != nil {
		return fmt.Errorf("dynsecret oracle: end the sessions of %s failed (%s)", account, oracleErrorCode(err))
	}
	return nil
}

// VerifyCredential connects as the credential's user to the administrator's
// address and service, and queries DUAL.
func (b *OracleBackend) VerifyCredential(ctx context.Context, credential []byte) error {
	var parsed struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || parsed.Username == "" || len(parsed.Password) == 0 {
		return errors.New("dynsecret oracle: the credential is not a username and password")
	}
	defer secret.Wipe(parsed.Password)
	connURL := go_ora.BuildUrl(b.host, b.port, b.service, parsed.Username, secrettext.String(parsed.Password), b.options)
	db, err := sql.Open("oracle", connURL)
	if err != nil {
		return errors.New("dynsecret oracle: open the credential's connection failed")
	}
	defer func() { _ = db.Close() }()
	verifyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var one int
	if err := db.QueryRowContext(verifyCtx, "SELECT 1 FROM DUAL").Scan(&one); err != nil || one != 1 {
		return fmt.Errorf("dynsecret oracle: the credential did not connect (%s)", oracleErrorCode(err))
	}
	return nil
}

// oracleCode returns an ORA- error's number, or 0.
func oracleCode(err error) int {
	var oracle *network.OracleError
	if errors.As(err, &oracle) {
		return oracle.ErrCode
	}
	return 0
}

// oracleErrorCode names a failure by its ORA- number only: a server message
// can quote the statement.
func oracleErrorCode(err error) string {
	if code := oracleCode(err); code != 0 {
		return fmt.Sprintf("ORA-%05d", code)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err.Error()
	}
	return "connection error"
}

// OpenOracleExecutor opens and verifies a go-ora client from an admin URL
// (oracle://user:password@host:1521/service). Callers close it after the
// operation, keeping the authority-bearing URL out of long-lived state.
func OpenOracleExecutor(ctx context.Context, adminDSN []byte) (*sql.DB, error) {
	adminDSN = bytes.TrimRight(adminDSN, "\r\n")
	if len(adminDSN) == 0 {
		return nil, errors.New("dynsecret oracle: admin DSN required")
	}
	db, err := sql.Open("oracle", secrettext.String(adminDSN))
	if err != nil {
		return nil, errors.New("dynsecret oracle: open admin connection failed")
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("dynsecret oracle: ping admin connection failed (%s)", oracleErrorCode(err))
	}
	return db, nil
}
