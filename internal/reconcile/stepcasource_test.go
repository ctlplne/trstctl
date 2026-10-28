// SPDX-License-Identifier: BUSL-1.1

package reconcile_test

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/reconcile"
	"trstctl.com/trstctl/internal/reconcile/canon"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"
)

// stepCALab is a PostgreSQL database laid out as step-ca's PostgreSQL backend
// lays it out (smallstep/nosql): each bucket a table of (nkey bytea, nvalue
// bytea); x509_certs maps the decimal serial to the DER and
// revoked_x509_certs maps a revoked serial to step-ca's JSON record.
type stepCALab struct {
	dsn     string
	dsnFile string
	caFile  string
	leaves  map[string][]byte
}

func newStepCALab(t *testing.T) *stepCALab {
	t.Helper()
	dir := t.TempDir()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)). // #nosec G115 -- a TCP port from the kernel (CWE-190)
		RuntimePath(filepath.Join(dir, "rt")).
		DataPath(filepath.Join(dir, "data")).
		BinariesPath(filepath.Join(dir, "bin")).
		Logger(io.Discard).
		StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		t.Skipf("embedded PostgreSQL unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pg.Stop() })
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres", port))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE stepca"); err != nil {
		t.Fatal(err)
	}
	_ = admin.Close(ctx)
	lab := &stepCALab{dsn: fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/stepca?sslmode=disable", port)}
	conn, err := pgx.Connect(ctx, lab.dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	for _, table := range []string{"x509_certs", "revoked_x509_certs", "x509_certs_data"} {
		// The statement smallstep/nosql's PostgreSQL driver runs per bucket.
		if _, err := conn.Exec(ctx, "CREATE TABLE IF NOT EXISTS "+pgx.Identifier{table}.Sanitize()+
			" (nkey BYTEA CHECK (octet_length(nkey) <= 255), nvalue BYTEA, PRIMARY KEY (nkey));"); err != nil {
			t.Fatal(err)
		}
	}
	newCA := func(cn string) (*crypto.LockedSigner, []byte) {
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		der, err := crypto.SelfSignedCACert(key, cn, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return key, der
	}
	issue := func(caKey *crypto.LockedSigner, caDER []byte, name string) []byte {
		hostKey, err := crypto.GenerateHostSubjectKey(name, []string{name})
		if err != nil {
			t.Fatal(err)
		}
		der, err := crypto.SignLeafFromCSR(caDER, caKey, hostKey.CSRDER, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	stepKey, stepDER := newCA("Lab step-ca Intermediate CA")
	otherKey, otherDER := newCA("Lab other CA")
	lab.leaves = map[string][]byte{
		"active":  issue(stepKey, stepDER, "active.stepca.lab.test"),
		"revoked": issue(stepKey, stepDER, "revoked.stepca.lab.test"),
		"other":   issue(otherKey, otherDER, "other.stepca.lab.test"),
	}
	for name, der := range lab.leaves {
		if _, err := conn.Exec(ctx, `INSERT INTO x509_certs (nkey, nvalue) VALUES ($1, $2)`, []byte(lab.decimalSerial(t, name)), der); err != nil {
			t.Fatal(err)
		}
	}
	revoked := lab.decimalSerial(t, "revoked")
	record := `{"Serial":"` + revoked + `","ProvisionerID":"admin:lab","ReasonCode":0,"Reason":"lab","RevokedAt":"2026-10-28T14:01:00Z","ExpiresAt":"2026-10-29T14:00:42Z","TokenID":"","MTLS":true,"ACME":false}`
	if _, err := conn.Exec(ctx, `INSERT INTO revoked_x509_certs (nkey, nvalue) VALUES ($1, $2)`, []byte(revoked), []byte(record)); err != nil {
		t.Fatal(err)
	}
	lab.caFile = filepath.Join(dir, "issuers.pem")
	if err := os.WriteFile(lab.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: stepDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	lab.dsnFile = filepath.Join(dir, "stepca.dsn")
	if err := os.WriteFile(lab.dsnFile, []byte(lab.dsn+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return lab
}

func (lab *stepCALab) decimalSerial(t *testing.T, name string) string {
	t.Helper()
	facts, err := crypto.CertificateFactsFromDER(lab.leaves[name])
	if err != nil {
		t.Fatal(err)
	}
	serial, ok := new(big.Int).SetString(facts.SerialHex, 16)
	if !ok {
		t.Fatalf("serial %q", facts.SerialHex)
	}
	return serial.String()
}

func (lab *stepCALab) config() reconcile.StepCASourceConfig {
	return reconcile.StepCASourceConfig{AuthorityID: "stepca-lab", DSNFile: lab.dsnFile, IssuerCertificatesFile: lab.caFile, AllowLoopback: true}
}

func observeStepCA(t *testing.T, cfg reconcile.StepCASourceConfig) (canon.Set, error) {
	t.Helper()
	rt, err := reconcile.NewRuntime(reconcile.RuntimeConfig{StepCASources: []reconcile.StepCASourceConfig{cfg}})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	obs, err := rt.Reducers.Observe(context.Background(), cfg.AuthorityID, "11111111-1111-1111-1111-111111111111")
	return obs.Set, err
}

// A218: the step-ca source reads both ledger tables in one read-only
// transaction and asserts the intermediate's certificates with their standing;
// another CA's certificate in the same database stays outside the
// jurisdiction.
func TestStepCASourceObservesTheLedgerTables(t *testing.T) {
	lab := newStepCALab(t)
	set, err := observeStepCA(t, lab.config())
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	statuses := map[string]string{}
	for _, rec := range set.Records {
		statuses[rec.Provenance.NativeID] = rec.Status
	}
	want := map[string]string{lab.decimalSerial(t, "active"): canon.StatusActive, lab.decimalSerial(t, "revoked"): canon.StatusRevoked}
	if len(statuses) != len(want) || statuses[lab.decimalSerial(t, "active")] != canon.StatusActive || statuses[lab.decimalSerial(t, "revoked")] != canon.StatusRevoked {
		t.Fatalf("observed %v, want %v", statuses, want)
	}
}

// A row whose key is not its certificate's serial, more rows than
// max_objects, a database without step-ca's tables and a database address
// outside the allowed egress each fail the observation.
func TestStepCASourceFailsClosed(t *testing.T) {
	lab := newStepCALab(t)
	ctx := context.Background()

	cfg := lab.config()
	cfg.MaxCertificates = 2
	if _, err := observeStepCA(t, cfg); err == nil || !strings.Contains(err.Error(), "more than max_objects") {
		t.Fatalf("too large = %v", err)
	}

	cfg = lab.config()
	cfg.AllowLoopback = false
	if _, err := observeStepCA(t, cfg); !errors.Is(err, netsec.ErrSSRFBlocked) {
		t.Fatalf("loopback without allow_insecure_loopback = %v; want the SSRF refusal", err)
	}

	elsewhere := filepath.Join(t.TempDir(), "postgres.dsn")
	if err := os.WriteFile(elsewhere, []byte(strings.Replace(lab.dsn, "/stepca?", "/postgres?", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = lab.config()
	cfg.DSNFile = elsewhere
	if _, err := observeStepCA(t, cfg); err == nil || !strings.Contains(err.Error(), "dsn_file must name step-ca's PostgreSQL database") {
		t.Fatalf("wrong database = %v", err)
	}

	conn, err := pgx.Connect(ctx, lab.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `UPDATE x509_certs SET nkey = $1 WHERE nkey = $2`, []byte("12345"), []byte(lab.decimalSerial(t, "active"))); err != nil {
		t.Fatal(err)
	}
	if _, err := observeStepCA(t, lab.config()); err == nil || !strings.Contains(err.Error(), "does not match its certificate's serial") {
		t.Fatalf("mismatched key = %v", err)
	}
}
