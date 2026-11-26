// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/trust/trusttest"
)

// The step-ca ledger reader holds a database password. A peer whose chain is
// valid under the configured CA but forbidden by the runtime distrust list
// must fail during TLS, before PostgreSQL asks for that password.
func TestCR071StepCAPostgresRefusesDistrustedPeerBeforePassword(t *testing.T) {
	checkStepCADistrustedPeer(t, "verify-full", 1)
}

func TestCR071StepCAPostgresPreferDoesNotDowngradeAfterDistrust(t *testing.T) {
	checkStepCADistrustedPeer(t, "prefer", 2)
}

func checkStepCADistrustedPeer(t *testing.T, mode string, attempts int) {
	t.Helper()
	peer := trusttest.NewPostgresPasswordPeer(t, attempts)
	trusttest.Install(t, peer.DistrustList)
	caFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(caFile, peer.RootsPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	dsnFile := filepath.Join(t.TempDir(), "stepca.dsn")
	host, port, err := net.SplitHostPort(peer.Addr)
	if err != nil {
		t.Fatal(err)
	}
	dsn := fmt.Sprintf("postgres://operator:test-password@%s:%s/stepca?sslmode=%s&sslrootcert=%s", host, port, mode, caFile)
	if err := os.WriteFile(dsnFile, []byte(dsn), 0o600); err != nil {
		t.Fatal(err)
	}
	source := &stepCASource{cfg: StepCASourceConfig{AuthorityID: "test", DSNFile: dsnFile, AllowLoopback: true}}
	ctx := t.Context()
	conn, err := source.connect(ctx)
	if conn != nil {
		_ = conn.Close(ctx)
	}
	if err == nil {
		t.Fatal("distrusted database peer connected")
	}
	select {
	case transport := <-peer.PasswordTransport:
		if transport != "" {
			t.Fatalf("step-ca database password reached a distrusted peer over %s", transport)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fake PostgreSQL peer did not finish")
	}
}
