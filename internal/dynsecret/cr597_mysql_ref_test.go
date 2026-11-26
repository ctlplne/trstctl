// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCR597MySQLRevokesAfterPrefixEditOnlyAtIssuingTarget(t *testing.T) {
	ctx := context.Background()
	issuedExec := &recordingSQLExec{}
	config := MySQLConfig{Database: "app", Addr: "mysql.internal:3306", AdminTarget: "admin-a.internal:3306", AccountHost: "10.4.0.12", UsernamePrefix: "earlier"}
	issued, err := NewMySQLBackend(issuedExec, config)
	if err != nil {
		t.Fatal(err)
	}
	req := GenerateRequest{Role: "reader", LeaseID: "cr597-mysql", PrincipalSuffix: testPrincipalSuffix("cr597-mysql")}
	ref, credential, err := issued.CreateCredential(ctx, req)
	if err != nil || len(credential) == 0 {
		t.Fatalf("issue MySQL lease: %v", err)
	}
	user, err := scopedNameForRequest(config.UsernamePrefix, req, 32, "_")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ref, "v1:") || !strings.HasSuffix(ref, ":"+user) {
		t.Fatalf("lease did not bind its issued principal and target: %q", ref)
	}
	otherExec := &recordingSQLExec{}
	elsewhere, err := NewMySQLBackend(otherExec, MySQLConfig{Database: "other", Addr: config.Addr, AccountHost: config.AccountHost, UsernamePrefix: "newer"})
	if err != nil {
		t.Fatal(err)
	}
	if err := elsewhere.Revoke(ctx, ref); err == nil || len(otherExec.queries) != 0 {
		t.Fatal("different database received a revoke or reported success")
	}
	if err := elsewhere.Revoke(ctx, user); err == nil || len(otherExec.queries) != 0 {
		t.Fatal("historical target-unbound reference was accepted")
	}
	movedConfig := config
	movedConfig.AdminTarget = "admin-b.internal:3306"
	moved, err := NewMySQLBackend(otherExec, movedConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := moved.Revoke(ctx, ref); err == nil || len(otherExec.queries) != 0 {
		t.Fatal("repointed administrator DSN received a revoke or reported success")
	}
	if _, err := moved.ResolveAccess(ctx, ref); !errors.Is(err, ErrAccessLoginMissing) {
		t.Fatalf("repointed administrator DSN claimed the lease access: %v", err)
	}
	config.UsernamePrefix = "newer"
	current, err := NewMySQLBackend(issuedExec, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := current.Revoke(ctx, ref); err != nil {
		t.Fatalf("revoke after prefix edit: %v", err)
	}
	if _, err := current.ResolveAccess(ctx, ref); !errors.Is(err, ErrAccessUnsupported) {
		t.Fatalf("same-target access lookup did not unwrap the issued name: %v", err)
	}
	issuedExec.requireContains(t, "DROP USER IF EXISTS "+mysqlAccount(user, config.AccountHost))
}
