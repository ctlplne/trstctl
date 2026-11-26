// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/redisacl"
)

func TestCR597RedisRevokesAfterPrefixEditOnlyAtIssuingServer(t *testing.T) {
	ctx := context.Background()
	issuedServer := newRESPServer(t)
	config := RedisConfig{Addr: issuedServer.addr, Password: []byte("operator-admin"), UsernamePrefix: "earlier", AllowPlaintext: true,
		RolePolicies: map[string]redisacl.Role{"reader": {KeyPrefixes: []string{"orders:"}, Commands: []string{"get"}}}}
	issued, err := NewRedisBackend(config)
	if err != nil {
		t.Fatal(err)
	}
	defer issued.Close()
	req := GenerateRequest{Role: "reader", LeaseID: "cr597-redis", PrincipalSuffix: testPrincipalSuffix("cr597-redis")}
	ref, credential, err := issued.CreateCredential(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(credential)
	user, err := scopedNameForRequest(config.UsernamePrefix, req, 64, "_")
	if err != nil {
		t.Fatal(err)
	}
	config.UsernamePrefix = "newer"
	current, err := NewRedisBackend(config)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	if err := current.Revoke(ctx, ref); err != nil {
		t.Fatalf("old lease could not be revoked after prefix edit: %v", err)
	}
	if !strings.HasPrefix(ref, "v1:") || !strings.HasSuffix(ref, ":"+user) {
		t.Fatalf("lease reference does not bind issuing target and principal: %q", ref)
	}
	issuedServer.require(t, "ACL DELUSER "+user)

	otherServer := newRESPServer(t)
	config.Addr = otherServer.addr
	elsewhere, err := NewRedisBackend(config)
	if err != nil {
		t.Fatal(err)
	}
	defer elsewhere.Close()
	if err := elsewhere.Revoke(ctx, ref); err == nil {
		t.Fatal("repointed Redis target claimed another server's lease")
	}
	if err := elsewhere.Revoke(ctx, user); err == nil {
		t.Fatal("historical target-unbound name was accepted")
	}
	if _, err := elsewhere.ResolveAccess(ctx, ref); !errors.Is(err, ErrAccessLoginMissing) {
		t.Fatalf("repointed Redis target claimed the lease access: %v", err)
	}
	otherServer.reject(t, "ACL DELUSER")
	otherServer.reject(t, "ACL GETUSER")
}
