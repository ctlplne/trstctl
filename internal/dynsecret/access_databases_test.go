// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bufio"
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"

	"trstctl.com/trstctl/internal/redisacl"
)

// TestMySQLGrantLinesBecomeGrantsG2L2 pins how SHOW GRANTS lines read: the
// privilege and its object, a role membership, and nothing for the USAGE on
// *.* every account has.
func TestMySQLGrantLinesBecomeGrantsG2L2(t *testing.T) {
	for line, want := range map[string]string{
		"GRANT SELECT ON `app`.* TO `trstctl_x`@`127.0.0.1`":                         "SELECT on app.*",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON `app`.* TO `trstctl_x`@`127.0.0.1`": "SELECT, INSERT, UPDATE, DELETE on app.*",
		"GRANT SELECT ON `app`.`orders` TO `trstctl_x`@`%`":                          "SELECT on app.orders",
		"GRANT `reader`@`%` TO `trstctl_x`@`127.0.0.1`":                              "member of role reader@%",
		"GRANT USAGE ON *.* TO `trstctl_x`@`127.0.0.1`":                              "",
		"REVOKE SELECT ON `app`.* FROM `trstctl_x`@`127.0.0.1`":                      "",
	} {
		if got := mysqlGrantText(line); got != want {
			t.Errorf("mysqlGrantText(%q) = %q, want %q", line, got, want)
		}
	}
}

// TestMySQLAccessErrorsAreClassifiedWithoutTheirTextG2L2: a user MySQL has no
// grants for is a missing login, a privilege the admin lacks is denied, and a
// broken connection is unreachable; none keeps the driver's text.
func TestMySQLAccessErrorsAreClassifiedWithoutTheirTextG2L2(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want error
	}{
		{&mysql.MySQLError{Number: 1141, Message: "There is no such grant defined for user 'trstctl_x'"}, ErrAccessLoginMissing},
		{&mysql.MySQLError{Number: 1227, Message: "Access denied; you need the SELECT privilege"}, ErrAccessDenied},
		{&mysql.MySQLError{Number: 1064, Message: "You have an error in your SQL syntax near 'hunter2'"}, ErrAccessUnreadable},
		{mysql.ErrInvalidConn, ErrAccessUnreachable},
		{context.DeadlineExceeded, ErrAccessUnreachable},
	} {
		got := mysqlAccessError(tc.err)
		if !errors.Is(got, tc.want) || strings.Contains(got.Error(), "trstctl_x") || strings.Contains(got.Error(), "hunter2") {
			t.Errorf("mysqlAccessError(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

type rolesMongoAdmin struct {
	recordingMongoAdmin
	roles map[string][]MongoRole
}

func (m *rolesMongoAdmin) UserRoles(_ context.Context, db, user string) ([]MongoRole, bool, error) {
	roles, ok := m.roles[db+"/"+user]
	return roles, ok, nil
}

// TestMongoLeaseAccessListsTheUsersRolesG2L2 reads a lease user's roles from
// usersInfo: each role on its database; a user MongoDB no longer has is a
// missing login; an admin that cannot read users cannot say.
func TestMongoLeaseAccessListsTheUsersRolesG2L2(t *testing.T) {
	ctx := context.Background()
	admin := &rolesMongoAdmin{roles: map[string][]MongoRole{"app/trstctl_r1": {{Role: "read", DB: "app"}, {Role: "readWrite", DB: "reports"}}}}
	backend, err := NewMongoBackend(admin, MongoConfig{Database: "app", URI: []byte("mongodb://admin:hunter2@db.internal:27017/?authSource=admin"), UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	access, err := backend.ResolveAccess(ctx, "trstctl_r1")
	if err != nil || access.TargetKind != AccessTargetMongoDBDatabase || access.TargetRef != "mongodb://db.internal:27017/app" || access.Login != "trstctl_r1" ||
		!slices.Equal(access.Grants, []string{"role read on database app", "role readWrite on database reports"}) {
		t.Fatalf("Mongo access = %+v, %v", access, err)
	}
	if _, err := backend.ResolveAccess(ctx, "trstctl_gone"); !errors.Is(err, ErrAccessLoginMissing) {
		t.Fatalf("a user MongoDB no longer has = %v, want login missing", err)
	}
	plain, err := NewMongoBackend(&recordingMongoAdmin{}, MongoConfig{Database: "app", UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.ResolveAccess(ctx, "trstctl_r1"); !errors.Is(err, ErrAccessUnsupported) {
		t.Fatalf("an admin that cannot read users = %v, want unsupported", err)
	}
}

// aclServer answers AUTH with OK and ACL GETUSER with a fixed reply.
func aclServer(t *testing.T, reply string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if strings.Contains(strings.Join(parseRESPArray(string(buf[:n])), " "), "GETUSER") {
						_, _ = c.Write([]byte(reply))
						continue
					}
					_, _ = c.Write([]byte("+OK\r\n"))
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func aclBackend(t *testing.T, addr string) *RedisBackend {
	t.Helper()
	b, err := NewRedisBackend(RedisConfig{Addr: addr, Password: []byte("operator-admin"), UsernamePrefix: "trstctl", AllowPlaintext: true,
		RolePolicies: map[string]redisacl.Role{"readonly": {KeyPrefixes: []string{"trstctl:dod:"}, Commands: []string{"get"}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

// TestRedisLeaseAccessReadsTheUsersACLG2L2 reads a lease user's ACL from ACL
// GETUSER, as Redis 7 and later answer it: flags, commands, key patterns and
// channels, never the password hashes beside them. A user Redis does not have
// is a missing login.
func TestRedisLeaseAccessReadsTheUsersACLG2L2(t *testing.T) {
	ctx := context.Background()
	const hash = "2d9c75aa3fbb0c7b1d8f6a1e0b4f5c3a2d9c75aa3fbb0c7b1d8f6a1e0b4f5c3a"
	reply := "*12\r\n$5\r\nflags\r\n*1\r\n$2\r\non\r\n$9\r\npasswords\r\n*1\r\n$64\r\n" + hash + "\r\n" +
		"$8\r\ncommands\r\n$16\r\n-@all +get +ping\r\n$4\r\nkeys\r\n$14\r\n~trstctl:dod:*\r\n$8\r\nchannels\r\n$0\r\n\r\n$9\r\nselectors\r\n*0\r\n"
	addr := aclServer(t, reply)
	access, err := aclBackend(t, addr).ResolveAccess(ctx, "trstctl_r1")
	if err != nil || access.TargetKind != AccessTargetRedisServer || access.TargetRef != "redis://"+addr || access.Login != "trstctl_r1" {
		t.Fatalf("Redis access = %+v, %v", access, err)
	}
	want := []string{"commands -@all +get +ping", "flags on", "keys ~trstctl:dod:*"}
	if !slices.Equal(access.Grants, want) {
		t.Fatalf("Redis grants = %q, want %q", access.Grants, want)
	}
	for _, grant := range access.Grants {
		if strings.Contains(grant, hash) || strings.Contains(grant, "passwords") {
			t.Fatalf("a password hash reached the grants: %q", access.Grants)
		}
	}
	if _, err := aclBackend(t, aclServer(t, "*-1\r\n")).ResolveAccess(ctx, "trstctl_gone"); !errors.Is(err, ErrAccessLoginMissing) {
		t.Fatalf("a user Redis does not have = %v, want login missing", err)
	}
	if _, err := aclBackend(t, aclServer(t, "-NOPERM this user has no permissions to run the 'acl|getuser' command\r\n")).ResolveAccess(ctx, "trstctl_r1"); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("an admin without ACL permission = %v, want denied", err)
	}
}

// TestRESPRepliesAreBoundedG2L2: the access reader refuses a reply nested too
// deep, an array past its element bound, a bulk string past the byte budget,
// a line without CRLF and an unknown type, and reads a RESP3 map in order.
func TestRESPRepliesAreBoundedG2L2(t *testing.T) {
	read := func(raw string) (respValue, error) {
		budget := maxRESPReplyBytes
		return readRESPValue(bufio.NewReader(strings.NewReader(raw)), 0, &budget)
	}
	m, err := read("%2\r\n+flags\r\n*1\r\n+on\r\n+keys\r\n$3\r\n~a*\r\n")
	if err != nil || len(m.items) != 4 || m.items[0].text != "flags" || m.items[1].items[0].text != "on" || m.items[3].text != "~a*" {
		t.Fatalf("RESP3 map = %+v, %v", m, err)
	}
	for name, raw := range map[string]string{
		"too deep":       strings.Repeat("*1\r\n", maxRESPDepth+2) + "+x\r\n",
		"too many":       "*1025\r\n",
		"over budget":    "$300000\r\n",
		"no CRLF bulk":   "$2\r\nabcd",
		"no CR":          "+OK\n",
		"unknown type":   "?x\r\n",
		"negative count": "*-2\r\n",
	} {
		if _, err := read(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
