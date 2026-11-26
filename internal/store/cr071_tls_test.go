// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/trust/trusttest"
	"trstctl.com/trstctl/internal/store"
)

func TestCR071ControlPlanePostgresRefusesDistrustedPeerBeforePassword(t *testing.T) {
	checkStoreDistrustedPeer(t, "verify-full", 1)
}

func TestCR071ControlPlanePostgresPreferDoesNotDowngradeAfterDistrust(t *testing.T) {
	checkStoreDistrustedPeer(t, "prefer", 2)
}

func checkStoreDistrustedPeer(t *testing.T, mode string, attempts int) {
	t.Helper()
	peer := trusttest.NewPostgresPasswordPeer(t, attempts)
	trusttest.Install(t, peer.DistrustList)
	caFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(caFile, peer.RootsPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(peer.Addr)
	if err != nil {
		t.Fatal(err)
	}
	dsn := fmt.Sprintf("postgres://operator:test-password@%s:%s/trstctl?sslmode=%s&sslrootcert=%s", host, port, mode, caFile)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	opened, err := store.Open(ctx, dsn)
	if opened != nil {
		opened.Close()
	}
	if err == nil {
		t.Fatal("distrusted control-plane database peer connected")
	}
	select {
	case transport := <-peer.PasswordTransport:
		if transport != "" {
			t.Fatalf("control-plane database password reached a distrusted peer over %s", transport)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fake PostgreSQL peer did not finish")
	}
}
