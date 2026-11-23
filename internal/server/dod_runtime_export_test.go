//go:build trstctl_dodproof

// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
)

// CR-040 CI: DoD's independently launched control binary must receive the
// actual private-socket DSN from its bundled database, not a guessed TCP URL.
func TestDODBundledStoreReturnsUsablePrivateSocketDSNCR040(t *testing.T) {
	ctx := context.Background()
	_, dsn, stop, err := DODOpenBundledStore(ctx, filepath.Join(t.TempDir(), "postgres"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if u.User == nil || u.User.Username() != "postgres" || u.Query().Get("host") == "" || u.Query().Get("sslmode") != "disable" {
		t.Fatalf("DoD database DSN did not carry its private peer socket: %q", dsn)
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		t.Fatal("DoD database DSN carried a bootstrap password")
	}
	peer, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("independent peer could not use returned private DSN: %v", err)
	}
	defer func() { _ = peer.Close(ctx) }()
	var currentUser string
	if err := peer.QueryRow(ctx, `SELECT current_user`).Scan(&currentUser); err != nil || currentUser != "postgres" {
		t.Fatalf("private peer readback current_user=%q err=%v", currentUser, err)
	}
}
