// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
)

// A258: a check's error reads as its class, and only a class where the
// server judged the credential counts as one a lockout policy would count.
func TestSignInClassesA258(t *testing.T) {
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"healthy", nil, SignInHealthy},
		{"postgres wrong password", classifyPostgresSignIn(fmt.Errorf("connect: %w", &pgconn.PgError{Code: "28P01"})), SignInRejected},
		{"postgres no such role", classifyPostgresSignIn(&pgconn.PgError{Code: "28000"}), SignInRejected},
		{"postgres other SQLSTATE", classifyPostgresSignIn(&pgconn.PgError{Code: "53300"}), SignInError},
		{"postgres dial", classifyPostgresSignIn(dial), SignInUnreachable},
		{"mysql access denied", classifyMySQLSignIn(&mysql.MySQLError{Number: 1045}), SignInRejected},
		{"mysql must change password", classifyMySQLSignIn(&mysql.MySQLError{Number: 1862}), SignInExpired},
		{"mysql expired in sandbox", classifyMySQLSignIn(&mysql.MySQLError{Number: 1820}), SignInExpired},
		{"mysql locked", classifyMySQLSignIn(&mysql.MySQLError{Number: 3118}), SignInLocked},
		{"mysql blocked by failed logins", classifyMySQLSignIn(&mysql.MySQLError{Number: 3955}), SignInLocked},
		{"mysql other", classifyMySQLSignIn(&mysql.MySQLError{Number: 1040}), SignInError},
		{"mysql dial", classifyMySQLSignIn(fmt.Errorf("ping: %w", dial)), SignInUnreachable},
		{"wrapped by an opener", fmt.Errorf("dynsecret mysql: ping admin connection failed: %w", ErrSignInRejected), SignInRejected},
		{"deadline", classifyPostgresSignIn(context.DeadlineExceeded), SignInUnreachable},
	}
	for _, c := range cases {
		if got := SignInStatusOf(c.err); got != c.want {
			t.Errorf("%s: class %q, want %q", c.name, got, c.want)
		}
	}
	for status, judged := range map[string]bool{SignInHealthy: false, SignInRejected: true, SignInExpired: true, SignInLocked: true,
		SignInUnreachable: false, SignInError: false} {
		if SignInJudged(status) != judged {
			t.Errorf("SignInJudged(%q) = %t", status, !judged)
		}
	}
}

// A258: a class names no part of the credential the sign-in used.
func TestSignInClassesCarryNoCredentialA258(t *testing.T) {
	err := classifyMySQLSignIn(&mysql.MySQLError{Number: 1045, Message: "Access denied for user 'admin'@'%' (using password: YES) s3cr3t"})
	if text := err.Error(); text != ErrSignInRejected.Error() {
		t.Fatalf("the class carries the server's message: %q", text)
	}
	err = classifyPostgresSignIn(&pgconn.PgError{Code: "08006", Message: "password s3cr3t"})
	if text := err.Error(); text != "dynsecret postgres: sign-in failed with SQLSTATE 08006" {
		t.Fatalf("the class carries the server's message: %q", text)
	}
}
