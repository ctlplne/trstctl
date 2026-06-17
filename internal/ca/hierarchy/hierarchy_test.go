package hierarchy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"trstctl.com/trstctl/internal/config"
	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

const testTenant = "11111111-1111-1111-1111-111111111111"

var testDSN string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trstctl-hierarchy-pg")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
		RuntimePath(dir + "/rt").
		DataPath(dir + "/data").
		BinariesPath(dir + "/bin").
		Logger(io.Discard).
		StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	testDSN = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
	code := m.Run()
	_ = pg.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func newHierarchyHarness(t *testing.T) (*Manager, *store.Store) {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := s.Pool().Exec(ctx,
		`TRUNCATE tenants, ca_authorities, ca_key_ceremonies, ca_ceremony_approvals
		 RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: testTenant, Name: "Acme"}); err != nil {
		t.Fatalf("UpsertTenant: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return NewManager(s, log), s
}

func approvedCeremony(t *testing.T, m *Manager, purpose string) string {
	t.Helper()
	ctx := context.Background()
	id, err := m.StartCeremony(ctx, testTenant, purpose, 1)
	if err != nil {
		t.Fatalf("StartCeremony(%q): %v", purpose, err)
	}
	if _, err := m.Approve(ctx, testTenant, id, "custodian-1"); err != nil {
		t.Fatalf("Approve(%q): %v", purpose, err)
	}
	return id
}

func TestPurposeRootCanonicalizesSetOrdering(t *testing.T) {
	a := CASpec{
		CommonName:          "root",
		PermittedDNSDomains: []string{"b.example", "a.example"},
		MaxPathLen:          2,
		EKUs:                []string{"serverAuth", "clientAuth"},
		TTL:                 time.Hour,
	}
	b := CASpec{
		CommonName:          "root",
		PermittedDNSDomains: []string{"a.example", "b.example"},
		MaxPathLen:          2,
		EKUs:                []string{"clientAuth", "serverAuth"},
		TTL:                 time.Hour,
	}
	if PurposeRoot(a) != PurposeRoot(b) {
		t.Fatalf("equivalent root specs produced different purposes: %q vs %q", PurposeRoot(a), PurposeRoot(b))
	}
}

func createRootForTest(t *testing.T, m *Manager, name string) store.CAAuthority {
	t.Helper()
	spec := CASpec{CommonName: name, MaxPathLen: 2, TTL: time.Hour}
	rec, err := m.CreateRoot(context.Background(), testTenant, approvedCeremony(t, m, PurposeRoot(spec)), spec)
	if err != nil {
		t.Fatalf("CreateRoot(%s): %v", name, err)
	}
	return rec
}

func TestCompletedCeremonyCannotBeReused(t *testing.T) {
	m, s := newHierarchyHarness(t)
	ctx := context.Background()

	firstSpec := CASpec{CommonName: "root-a", MaxPathLen: 1, TTL: time.Hour}
	secondSpec := CASpec{CommonName: "root-b", MaxPathLen: 1, TTL: time.Hour}
	ceremonyID := approvedCeremony(t, m, PurposeRoot(firstSpec))
	if _, err := m.CreateRoot(ctx, testTenant, ceremonyID, firstSpec); err != nil {
		t.Fatalf("first CreateRoot: %v", err)
	}
	if _, err := m.CreateRoot(ctx, testTenant, ceremonyID, secondSpec); !errors.Is(err, store.ErrKeyCeremonyNotPending) {
		t.Fatalf("reusing completed ceremony = %v, want ErrKeyCeremonyNotPending", err)
	}
	authorities, err := s.ListCAAuthorities(ctx, testTenant)
	if err != nil {
		t.Fatalf("ListCAAuthorities: %v", err)
	}
	if len(authorities) != 1 || authorities[0].CommonName != "root-a" {
		t.Fatalf("authorities after reuse attempt = %+v, want only root-a", authorities)
	}
}

func TestCeremonyPurposeMismatchFailsClosedForPrivilegedCAOperations(t *testing.T) {
	m, _ := newHierarchyHarness(t)
	ctx := context.Background()

	rootSpec := CASpec{CommonName: "wrong-root", MaxPathLen: 1, TTL: time.Hour}
	approvedOtherRootSpec := CASpec{CommonName: "approved-root", MaxPathLen: 1, TTL: time.Hour}
	if _, err := m.CreateRoot(ctx, testTenant, approvedCeremony(t, m, PurposeRoot(approvedOtherRootSpec)), rootSpec); !errors.Is(err, store.ErrKeyCeremonyPurposeMismatch) {
		t.Fatalf("root purpose mismatch = %v, want ErrKeyCeremonyPurposeMismatch", err)
	}

	root := createRootForTest(t, m, "root")
	interSpec := CASpec{
		CommonName: "sub", TTL: time.Hour,
	}
	if _, err := m.CreateIntermediate(ctx, testTenant, approvedCeremony(t, m, PurposeIntermediate("different-parent", interSpec)), root.ID, interSpec); !errors.Is(err, store.ErrKeyCeremonyPurposeMismatch) {
		t.Fatalf("intermediate purpose mismatch = %v, want ErrKeyCeremonyPurposeMismatch", err)
	}

	if _, err := m.Rotate(ctx, testTenant, root.ID, approvedCeremony(t, m, PurposeRotate("different-ca"))); !errors.Is(err, store.ErrKeyCeremonyPurposeMismatch) {
		t.Fatalf("rotate purpose mismatch = %v, want ErrKeyCeremonyPurposeMismatch", err)
	}

	target, err := cryptoca.NewRoot(cryptoca.CASpec{CommonName: "target", MaxPathLen: 1, TTL: time.Hour})
	if err != nil {
		t.Fatalf("target root: %v", err)
	}
	defer target.Destroy()
	wrongTarget := append([]byte(nil), target.CertificateDER()...)
	wrongTarget = append(wrongTarget, 0)
	if _, err := m.CrossSign(ctx, testTenant, approvedCeremony(t, m, PurposeCrossSign(root.ID, wrongTarget)), root.ID, target.CertificateDER()); !errors.Is(err, store.ErrKeyCeremonyPurposeMismatch) {
		t.Fatalf("cross-sign purpose mismatch = %v, want ErrKeyCeremonyPurposeMismatch", err)
	}
}
