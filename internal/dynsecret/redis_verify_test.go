// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"net"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/redisacl"
)

// A201: the Redis lease check authenticates as the credential's user against
// the backend's configured server, never the address the credential names,
// and runs PING; a refused AUTH fails, and a credential that is not a redis
// URL with user information fails before any connection.
func TestRedisVerifyCredentialAuthenticatesAsTheLeaseUser(t *testing.T) {
	srv := newRESPServer(t)
	backend, err := NewRedisBackend(RedisConfig{
		Addr: srv.addr, Password: []byte("operator-admin"), UsernamePrefix: "trstctl", AllowPlaintext: true,
		RolePolicies: map[string]redisacl.Role{"readonly": {KeyPrefixes: []string{"a201:"}, Commands: []string{"get"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	ctx := context.Background()
	credential := redisCredential("10.9.9.9:6379", 0, "trstctl_lease_user", []byte("p@ss:w/rd"), false)
	if err := backend.VerifyCredential(ctx, credential); err != nil {
		t.Fatalf("verify = %v", err)
	}
	srv.require(t, "AUTH trstctl_lease_user p@ss:w/rd")
	srv.require(t, "PING")

	refusing, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = refusing.Close() }()
	go func() {
		for {
			c, err := refusing.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 512)
				if _, err := c.Read(buf); err == nil {
					_, _ = c.Write([]byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n"))
				}
			}(c)
		}
	}()
	refused, err := NewRedisBackend(RedisConfig{
		Addr: refusing.Addr().String(), Password: []byte("operator-admin"), UsernamePrefix: "trstctl", AllowPlaintext: true,
		RolePolicies: map[string]redisacl.Role{"readonly": {KeyPrefixes: []string{"a201:"}, Commands: []string{"get"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer refused.Close()
	if err := refused.VerifyCredential(ctx, credential); err == nil {
		t.Fatal("a refused AUTH verified")
	}
	for _, bad := range []string{"https://user:pass@host/0", "redis://host:6379/0", "redis://:pass@host/0", "redis://user:%zz@host/0"} {
		if err := backend.VerifyCredential(ctx, []byte(bad)); err == nil || !strings.Contains(err.Error(), "credential") {
			t.Fatalf("verify %q = %v, want a credential refusal", bad, err)
		}
	}
}
