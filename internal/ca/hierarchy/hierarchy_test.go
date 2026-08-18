// SPDX-License-Identifier: MPL-2.0

package hierarchy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/config"
	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
	"trstctl.com/trstctl/internal/crypto/jose"
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
		Port(uint32(port)). // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
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
	if _, err := s.SystemPool().Exec(ctx,
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
	return ceremonyWithApprovals(t, m, purpose, 1, 1)
}

func ceremonyWithApprovals(t *testing.T, m *Manager, purpose string, threshold, approvals int) string {
	t.Helper()
	ctx := context.Background()
	id, err := m.StartCeremony(ctx, testTenant, purpose, threshold)
	if err != nil {
		t.Fatalf("StartCeremony(%q): %v", purpose, err)
	}
	for i := range approvals {
		custodian := fmt.Sprintf("custodian-%d", i+1)
		if _, err := m.Approve(ctx, testTenant, id, custodian); err != nil {
			t.Fatalf("Approve(%q, %s): %v", purpose, custodian, err)
		}
	}
	return id
}

func consumeCeremonyDirectly(t *testing.T, s *store.Store, ceremonyID, purpose string) {
	t.Helper()
	ctx := context.Background()
	if err := s.WithTenant(ctx, testTenant, func(tx pgx.Tx) error {
		_, err := s.ConsumeKeyCeremonyTx(ctx, tx, testTenant, ceremonyID, purpose)
		return err
	}); err != nil {
		t.Fatalf("direct ConsumeKeyCeremonyTx(%q): %v", purpose, err)
	}
}

type caOperationProbe struct {
	newRoot            int
	createIntermediate int
	crossSign          int
}

func (p *caOperationProbe) install(m *Manager) {
	base := m.caOps
	m.caOps = caOperations{
		newRoot: func(spec cryptoca.CASpec) (*cryptoca.CA, error) {
			p.newRoot++
			return base.newRoot(spec)
		},
		createIntermediate: func(parent *cryptoca.CA, spec cryptoca.CASpec) (*cryptoca.CA, error) {
			p.createIntermediate++
			return base.createIntermediate(parent, spec)
		},
		crossSign: func(ca *cryptoca.CA, certDER []byte) ([]byte, error) {
			p.crossSign++
			return base.crossSign(ca, certDER)
		},
	}
}

func (p caOperationProbe) total() int {
	return p.newRoot + p.createIntermediate + p.crossSign
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

func TestNoCAOperationBeforeCeremonyQuorum(t *testing.T) {
	type caOperationCase struct {
		name  string
		setup func(t *testing.T, m *Manager) (purpose string, run func(ceremonyID string) error)
	}

	cases := []caOperationCase{
		{
			name: "create root",
			setup: func(t *testing.T, m *Manager) (string, func(string) error) {
				spec := CASpec{CommonName: "guarded-root", MaxPathLen: 1, TTL: time.Hour}
				return PurposeRoot(spec), func(ceremonyID string) error {
					_, err := m.CreateRoot(context.Background(), testTenant, ceremonyID, spec)
					return err
				}
			},
		},
		{
			name: "create intermediate",
			setup: func(t *testing.T, m *Manager) (string, func(string) error) {
				parent := createRootForTest(t, m, "guarded-parent")
				spec := CASpec{CommonName: "guarded-intermediate", MaxPathLen: 0, TTL: time.Hour}
				return PurposeIntermediate(parent.ID, spec), func(ceremonyID string) error {
					_, err := m.CreateIntermediate(context.Background(), testTenant, ceremonyID, parent.ID, spec)
					return err
				}
			},
		},
		{
			name: "rotate root",
			setup: func(t *testing.T, m *Manager) (string, func(string) error) {
				root := createRootForTest(t, m, "guarded-rotate-root")
				return PurposeRotate(root.ID), func(ceremonyID string) error {
					_, err := m.Rotate(context.Background(), testTenant, root.ID, ceremonyID)
					return err
				}
			},
		},
		{
			name: "cross sign",
			setup: func(t *testing.T, m *Manager) (string, func(string) error) {
				signer := createRootForTest(t, m, "guarded-cross-signer")
				target, err := cryptoca.NewRoot(cryptoca.CASpec{CommonName: "guarded-cross-target", MaxPathLen: 1, TTL: time.Hour})
				if err != nil {
					t.Fatalf("target root: %v", err)
				}
				t.Cleanup(target.Destroy)
				targetDER := target.CertificateDER()
				return PurposeCrossSign(signer.ID, targetDER), func(ceremonyID string) error {
					_, err := m.CrossSign(context.Background(), testTenant, ceremonyID, signer.ID, targetDER)
					return err
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/below quorum", func(t *testing.T) {
			m, _ := newHierarchyHarness(t)
			purpose, run := tc.setup(t, m)
			var probe caOperationProbe
			probe.install(m)

			ceremonyID := ceremonyWithApprovals(t, m, purpose, 2, 1)
			if err := run(ceremonyID); !errors.Is(err, ErrQuorumNotMet) {
				t.Fatalf("operation before quorum err = %v, want ErrQuorumNotMet", err)
			}
			if probe.total() != 0 {
				t.Fatalf("CA operation count before quorum = %+v, want no key/sign call", probe)
			}
		})

		t.Run(tc.name+"/purpose mismatch", func(t *testing.T) {
			m, _ := newHierarchyHarness(t)
			purpose, run := tc.setup(t, m)
			var probe caOperationProbe
			probe.install(m)

			ceremonyID := ceremonyWithApprovals(t, m, purpose+":wrong-purpose", 1, 1)
			if err := run(ceremonyID); !errors.Is(err, store.ErrKeyCeremonyPurposeMismatch) {
				t.Fatalf("operation with wrong purpose err = %v, want ErrKeyCeremonyPurposeMismatch", err)
			}
			if probe.total() != 0 {
				t.Fatalf("CA operation count with wrong purpose = %+v, want no key/sign call", probe)
			}
		})

		t.Run(tc.name+"/already consumed", func(t *testing.T) {
			m, s := newHierarchyHarness(t)
			purpose, run := tc.setup(t, m)
			ceremonyID := ceremonyWithApprovals(t, m, purpose, 1, 1)
			consumeCeremonyDirectly(t, s, ceremonyID, purpose)

			var probe caOperationProbe
			probe.install(m)
			if err := run(ceremonyID); !errors.Is(err, store.ErrKeyCeremonyNotPending) {
				t.Fatalf("operation with consumed ceremony err = %v, want ErrKeyCeremonyNotPending", err)
			}
			if probe.total() != 0 {
				t.Fatalf("CA operation count with consumed ceremony = %+v, want no key/sign call", probe)
			}
		})
	}
}

func TestApprovalWithoutEventEvidenceCannotReachQuorum(t *testing.T) {
	m, s := newHierarchyHarness(t)
	ctx := context.Background()
	spec := CASpec{CommonName: "evidence-root", MaxPathLen: 1, TTL: time.Hour}
	ceremonyID, err := m.StartCeremony(ctx, testTenant, PurposeRoot(spec), 1)
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}

	// Force the append after the approval-row reservation to fail. The row may exist
	// as retry state, but it has no event id/sequence and must not count.
	if err := m.log.Close(); err != nil {
		t.Fatalf("close event log: %v", err)
	}
	if count, err := m.Approve(ctx, testTenant, ceremonyID, "custodian-1"); err == nil {
		t.Fatal("Approve with a closed event log succeeded; want append failure")
	} else if count != 0 {
		t.Fatalf("Approve with failed event append returned count %d, want 0 evidence-backed approvals", count)
	}
	c, err := s.GetKeyCeremony(ctx, testTenant, ceremonyID)
	if err != nil {
		t.Fatalf("GetKeyCeremony: %v", err)
	}
	if c.Approvals != 0 {
		t.Fatalf("unevidenced approval count = %d, want 0", c.Approvals)
	}
	if _, err := m.CreateRoot(ctx, testTenant, ceremonyID, spec); !errors.Is(err, ErrQuorumNotMet) {
		t.Fatalf("CreateRoot with unevidenced approval = %v, want ErrQuorumNotMet", err)
	}

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("events.Open retry log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	m2 := NewManager(s, log)
	if count, err := m2.Approve(ctx, testTenant, ceremonyID, "custodian-1"); err != nil {
		t.Fatalf("Approve retry with event log: %v", err)
	} else if count != 1 {
		t.Fatalf("Approve retry count = %d, want 1", count)
	}
	root, err := m2.CreateRoot(ctx, testTenant, ceremonyID, spec)
	if err != nil {
		t.Fatalf("CreateRoot after evidenced approval: %v", err)
	}

	sk, err := jose.GenerateRSASigningKey("ceremony-evidence-key")
	if err != nil {
		t.Fatalf("GenerateRSASigningKey: %v", err)
	}
	svc := audit.NewService(log, sk)
	signed, err := svc.Export(ctx, audit.Query{TenantID: testTenant})
	if err != nil {
		t.Fatalf("Export audit bundle: %v", err)
	}
	bundle, err := audit.VerifyBundle(signed, svc.VerificationKeys())
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	sawApproval := false
	sawRoot := false
	for _, rec := range bundle.Records {
		switch rec.Type {
		case "ca.ceremony.approved":
			sawApproval = sawApproval || strings.Contains(string(rec.Data), "custodian-1")
		case "ca.root.created":
			sawRoot = true
		}
	}
	if !sawApproval {
		t.Fatal("signed audit bundle lacks ca.ceremony.approved for custodian-1")
	}
	if !sawRoot {
		t.Fatal("signed audit bundle lacks ca.root.created")
	}
	_ = root
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
