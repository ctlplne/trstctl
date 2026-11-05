// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

// A258: a brokered account's health is whether the credential the broker
// holds for it still signs in. A check signs in once with that credential
// and changes nothing; its outcome is one of these classes.
const (
	SignInHealthy     = "healthy"
	SignInRejected    = "rejected"    // the server refused the credential: changed, wrong, or expired where the server does not say
	SignInExpired     = "expired"     // the server says the credential has expired or must be changed
	SignInLocked      = "locked"      // the server says the account is locked
	SignInUnreachable = "unreachable" // no sign-in exchange took place: dial, TLS or a timeout
	SignInError       = "error"       // anything else
)

var (
	ErrSignInRejected    = errors.New("dynsecret: the server refused the credential")
	ErrSignInExpired     = errors.New("dynsecret: the server says the credential has expired")
	ErrSignInLocked      = errors.New("dynsecret: the server says the account is locked")
	ErrSignInUnreachable = errors.New("dynsecret: the server could not be reached")
)

// SignInChecker is a backend that can prove its stored credential still signs
// in, changing nothing at the server.
type SignInChecker interface {
	CheckSignIn(ctx context.Context) error
}

// SignInStatusOf is the class of a check's error (nil is healthy).
func SignInStatusOf(err error) string {
	switch {
	case err == nil:
		return SignInHealthy
	case errors.Is(err, ErrSignInRejected):
		return SignInRejected
	case errors.Is(err, ErrSignInExpired):
		return SignInExpired
	case errors.Is(err, ErrSignInLocked):
		return SignInLocked
	case errors.Is(err, ErrSignInUnreachable):
		return SignInUnreachable
	}
	return SignInError
}

// SignInJudged reports whether the server judged the credential — the kind of
// failure an account lockout policy counts. A checker never repeats such a
// sign-in with an unchanged credential.
func SignInJudged(status string) bool {
	return status == SignInRejected || status == SignInExpired || status == SignInLocked
}

// classifyNetwork is ErrSignInUnreachable for an error that happened before
// any sign-in exchange: a dial, TLS handshake or deadline.
func classifyNetwork(err error) error {
	var netErr net.Error
	var opErr *net.OpError
	if errors.As(err, &opErr) || errors.As(err, &netErr) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) {
		return ErrSignInUnreachable
	}
	return nil
}

// classifyPostgresSignIn maps a pgx connection error to its class. PostgreSQL
// reports an expired password (VALID UNTIL) as a failed password, so it reads
// as rejected.
func classifyPostgresSignIn(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "28P01", "28000":
			return ErrSignInRejected
		}
		return fmt.Errorf("dynsecret postgres: sign-in failed with SQLSTATE %s", pgErr.Code)
	}
	if class := classifyNetwork(err); class != nil {
		return class
	}
	return errors.New("dynsecret postgres: sign-in failed")
}

// classifyMySQLSignIn maps a go-sql-driver error to its class by MySQL's
// error number.
func classifyMySQLSignIn(err error) error {
	var myErr *mysql.MySQLError
	if errors.As(err, &myErr) {
		switch myErr.Number {
		case 1045: // ER_ACCESS_DENIED_ERROR
			return ErrSignInRejected
		case 1820, 1862: // ER_MUST_CHANGE_PASSWORD(_LOGIN)
			return ErrSignInExpired
		case 3118, 3955: // ER_ACCOUNT_HAS_BEEN_LOCKED, blocked by FAILED_LOGIN_ATTEMPTS
			return ErrSignInLocked
		}
		return fmt.Errorf("dynsecret mysql: sign-in failed with error %d", myErr.Number)
	}
	if class := classifyNetwork(err); class != nil {
		return class
	}
	return errors.New("dynsecret mysql: sign-in failed")
}

// classifyMongoSignIn maps a MongoDB driver error to its class: code 18
// (AuthenticationFailed) is a refused credential.
func classifyMongoSignIn(err error) error {
	var serverErr mongo.ServerError
	if errors.As(err, &serverErr) && serverErr.HasErrorCode(18) {
		return ErrSignInRejected
	}
	// The handshake's authentication failure arrives wrapped in a connection
	// error; its text names the server's code name and carries no credential.
	if strings.Contains(err.Error(), "AuthenticationFailed") || strings.Contains(err.Error(), "auth error") {
		return ErrSignInRejected
	}
	if mongo.IsNetworkError(err) || mongo.IsTimeout(err) {
		return ErrSignInUnreachable
	}
	if class := classifyNetwork(err); class != nil {
		return class
	}
	return errors.New("dynsecret mongodb: sign-in failed")
}

// CheckSignIn signs in with the admin DSN on a new connection and runs
// SELECT 1.
func (b *PostgresBackend) CheckSignIn(ctx context.Context) error {
	conn, err := pgconn.Connect(ctx, secrettext.String(b.dsn.Bytes()))
	if err != nil {
		return classifyPostgresSignIn(err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	if result := conn.ExecParams(ctx, "SELECT 1", nil, nil, nil, nil).Read(); result.Err != nil {
		return classifyPostgresSignIn(result.Err)
	}
	return nil
}

// CheckSignIn runs SELECT 1 through the executor OpenMySQLExecutor opened,
// which signed in with the admin DSN on a new pool. A statement, not a ping:
// an expired password's sandbox answers a ping but refuses a statement.
func (b *MySQLBackend) CheckSignIn(ctx context.Context) error {
	if _, err := b.exec.ExecContext(ctx, "SELECT 1"); err != nil {
		return classifyMySQLSignIn(err)
	}
	return nil
}

// CheckSignIn pings through the admin OpenMongoAdmin connected, which signed
// in with the admin URI.
func (b *MongoBackend) CheckSignIn(ctx context.Context) error {
	pinger, ok := b.admin.(interface{ Ping(context.Context) error })
	if !ok {
		return errors.New("dynsecret mongodb: the admin connection cannot be pinged")
	}
	if err := pinger.Ping(ctx); err != nil {
		return classifyMongoSignIn(err)
	}
	return nil
}

// Ping proves the admin connection still answers as its user.
func (a *MongoDriverAdmin) Ping(ctx context.Context) error {
	if a == nil || a.client == nil {
		return errors.New("dynsecret mongodb: disconnected admin")
	}
	return a.client.Ping(ctx, nil)
}

// CheckSignIn opens a new connection, authenticates with the admin password
// and runs PING.
func (b *RedisBackend) CheckSignIn(ctx context.Context) error {
	conn, err := b.connect(ctx)
	if err != nil {
		return ErrSignInUnreachable
	}
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	if b.password != nil && b.password.Len() > 0 {
		if err := redisWriteArray(conn, [][]byte{[]byte("AUTH"), b.password.Bytes()}); err != nil {
			return ErrSignInUnreachable
		}
		if err := redisReadOK(reader); err != nil {
			if errors.Is(err, errRedisRejected) {
				return ErrSignInRejected
			}
			return ErrSignInUnreachable
		}
	}
	if err := redisWriteArray(conn, [][]byte{[]byte("PING")}); err != nil {
		return ErrSignInUnreachable
	}
	if err := redisReadOK(reader); err != nil {
		return errors.New("dynsecret redis: PING failed after sign-in")
	}
	return nil
}

// CheckSignIn runs SELECT 1 as the admin user. ClickHouse answers a refused
// sign-in with AUTHENTICATION_FAILED (516), UNKNOWN_USER (192) or
// WRONG_PASSWORD (193).
func (b *ClickHouseBackend) CheckSignIn(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, strings.NewReader("SELECT 1"))
	if err != nil {
		return err
	}
	if err := b.adminPassword.Use(func(password []byte) error {
		req.SetBasicAuth(b.adminUser, string(password))
		return nil
	}); err != nil {
		return err
	}
	resp, err := b.client.Do(req) // #nosec G704 -- the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918)
	if err != nil {
		return ErrSignInUnreachable
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	defer secret.Wipe(body)
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if m := clickHouseErrorCode.FindSubmatch(body); m != nil {
		switch string(m[1]) {
		case "516", "192", "193":
			return ErrSignInRejected
		}
		return fmt.Errorf("dynsecret clickhouse: sign-in failed with HTTP %d, error code %s", resp.StatusCode, m[1])
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrSignInRejected
	}
	return fmt.Errorf("dynsecret clickhouse: sign-in failed with HTTP %d", resp.StatusCode)
}

// CheckSignIn reads the API server's discovery document with the provider's
// token: every authenticated user may read it, and a token the API server
// does not accept is refused with 401.
func (b *KubernetesBackend) CheckSignIn(ctx context.Context) error {
	err := b.json(ctx, http.MethodGet, "/api", nil, nil)
	var status *cloudhttp.StatusError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &status) && status.StatusCode == http.StatusUnauthorized:
		return ErrSignInRejected
	case errors.As(err, &status):
		return fmt.Errorf("dynsecret kubernetes: sign-in failed with HTTP %d", status.StatusCode)
	}
	if class := classifyNetwork(err); class != nil {
		return class
	}
	return errors.New("dynsecret kubernetes: sign-in failed")
}
