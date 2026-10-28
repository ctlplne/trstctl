// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers"
)

// step-ca authority source (A218).
//
// step-ca has no API that lists what it issued; its ledger is its database.
// With the PostgreSQL backend each bucket is a table of (nkey bytea, nvalue
// bytea): x509_certs maps a certificate's decimal serial to its DER, and
// revoked_x509_certs maps a revoked serial to a JSON record. The source reads
// both in one read-only, repeatable-read transaction, so they describe the
// same moment, as a database role the operator grants SELECT on those two
// tables. File-based backends (Badger, BoltDB) and MySQL are not read.

const (
	stepCADefaultMaxCerts = 20000
	stepCAConnectTimeout  = 10 * time.Second
)

// StepCASourceConfig is the core-owned shape operator config maps onto.
type StepCASourceConfig struct {
	AuthorityID string
	// DSNFile holds the PostgreSQL connection string of step-ca's database,
	// read at each observation and never kept.
	DSNFile                string
	IssuerCertificatesFile string
	MaxCertificates        int
	// AllowLoopback permits a loopback database address; PrivateEndpointCIDRs
	// widens the SSRF-safe dialer to operator ranges.
	AllowLoopback        bool
	PrivateEndpointCIDRs []netip.Prefix
}

type stepCASource struct {
	cfg StepCASourceConfig
	now func() time.Time
}

func newStepCASource(cfg StepCASourceConfig) (*stepCASource, error) {
	cfg.AuthorityID = strings.TrimSpace(cfg.AuthorityID)
	if cfg.AuthorityID == "" {
		return nil, fmt.Errorf("%w: stepca authority id required", errCASourceConfig)
	}
	if strings.TrimSpace(cfg.DSNFile) == "" || strings.TrimSpace(cfg.IssuerCertificatesFile) == "" {
		return nil, fmt.Errorf("%w: stepca needs dsn_file and issuer_certificates_file", errCASourceConfig)
	}
	if cfg.MaxCertificates <= 0 {
		cfg.MaxCertificates = stepCADefaultMaxCerts
	}
	return &stepCASource{cfg: cfg, now: time.Now}, nil
}

// SelfSnapshot implements reducers.SelfInventorySource.
func (s *stepCASource) SelfSnapshot(ctx context.Context, _ string) (reducers.SelfSnapshot, error) {
	jurisdiction, err := loadCAJurisdiction(s.cfg.IssuerCertificatesFile)
	if err != nil {
		return reducers.SelfSnapshot{}, err
	}
	sb := reducers.NewObservationSandbox(reducers.ReadOnlyObservationGrant(s.cfg.AuthorityID), nil)
	for _, table := range []string{"x509_certs", "revoked_x509_certs"} {
		if _, err := sb.List(ctx, s.cfg.AuthorityID+"/"+table); err != nil {
			return reducers.SelfSnapshot{}, err
		}
	}
	conn, err := s.connect(ctx)
	if err != nil {
		return reducers.SelfSnapshot{}, err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return reducers.SelfSnapshot{}, fmt.Errorf("xrec stepca source %s: begin read: %w", s.cfg.AuthorityID, err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	revoked := map[string]bool{}
	if err := s.readTable(ctx, tx, "revoked_x509_certs", func(key, _ []byte) error {
		revoked[string(key)] = true
		return nil
	}); err != nil {
		return reducers.SelfSnapshot{}, err
	}
	now := s.now().UTC()
	snap := reducers.SelfSnapshot{Watermark: storeWatermark("stepca:"+s.cfg.AuthorityID, now)}
	err = s.readTable(ctx, tx, "x509_certs", func(key, value []byte) error {
		serial, ok := new(big.Int).SetString(string(key), 10)
		if !ok {
			return fmt.Errorf("x509_certs key %q is not a decimal serial", truncateKey(key))
		}
		facts, err := crypto.CertificateFactsFromDER(value)
		if err != nil {
			return fmt.Errorf("x509_certs %s: %w", serial, err)
		}
		if serial.Text(16) != facts.SerialHex {
			return fmt.Errorf("x509_certs key %s does not match its certificate's serial", serial)
		}
		if _, in := jurisdiction[string(facts.IssuerNameDER)]; !in || facts.NotAfter.Before(now) {
			return nil
		}
		status := canonStatusActive
		if revoked[string(key)] {
			status = canonStatusRevoked
		}
		snap.Certificates = append(snap.Certificates, reducers.SelfCertificate{
			IssuerNameDER: facts.IssuerNameDER,
			SerialHex:     facts.SerialHex,
			Status:        status,
			NativeID:      string(key),
		})
		return nil
	})
	if err != nil {
		return reducers.SelfSnapshot{}, err
	}
	return snap, nil
}

// readTable reads one bucket table, failing closed past MaxCertificates rows
// so an observation is never a silent prefix of the ledger.
func (s *stepCASource) readTable(ctx context.Context, tx pgx.Tx, table string, row func(key, value []byte) error) error {
	rows, err := tx.Query(ctx, "SELECT nkey, nvalue FROM "+pgx.Identifier{table}.Sanitize()+" LIMIT $1", s.cfg.MaxCertificates+1)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			return fmt.Errorf("xrec stepca source %s: no %s table: dsn_file must name step-ca's PostgreSQL database", s.cfg.AuthorityID, table)
		}
		return fmt.Errorf("xrec stepca source %s: read %s: %w", s.cfg.AuthorityID, table, err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
		if n > s.cfg.MaxCertificates {
			return fmt.Errorf("xrec stepca source %s: %s has more than max_objects %d rows; the observation would be partial",
				s.cfg.AuthorityID, table, s.cfg.MaxCertificates)
		}
		var key, value []byte
		if err := rows.Scan(&key, &value); err != nil {
			return fmt.Errorf("xrec stepca source %s: scan %s: %w", s.cfg.AuthorityID, table, err)
		}
		if err := row(key, value); err != nil {
			return fmt.Errorf("xrec stepca source %s: %w", s.cfg.AuthorityID, err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("xrec stepca source %s: read %s: %w", s.cfg.AuthorityID, table, err)
	}
	return nil
}

// connect reads the DSN at each observation and dials through the SSRF-safe
// dialer: a database address outside the allowed ranges is refused like any
// other egress.
func (s *stepCASource) connect(ctx context.Context) (*pgx.Conn, error) {
	raw, err := os.ReadFile(s.cfg.DSNFile) // #nosec G304 -- operator-configured step-ca database DSN file (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("xrec stepca source %s: read dsn_file: %w", s.cfg.AuthorityID, err)
	}
	connString := strings.TrimSpace(string(raw))
	secret.Wipe(raw)
	cfg, err := pgx.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("xrec stepca source %s: dsn_file does not hold a PostgreSQL connection string", s.cfg.AuthorityID)
	}
	opts := netsec.SafeClientOptions{AllowPrivateCIDRs: append([]netip.Prefix(nil), s.cfg.PrivateEndpointCIDRs...)}
	if s.cfg.AllowLoopback {
		opts.AllowPrivateCIDRs = append(opts.AllowPrivateCIDRs, netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"))
	}
	dialer := &net.Dialer{Timeout: stepCAConnectTimeout, Control: netsec.SafeDialControlWithOptions(opts)}
	cfg.DialFunc = dialer.DialContext
	cfg.ConnectTimeout = stepCAConnectTimeout
	cfg.RuntimeParams["application_name"] = "trstctl-xrec"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("xrec stepca source %s: connect: %w", s.cfg.AuthorityID, err)
	}
	return conn, nil
}

func truncateKey(key []byte) string {
	if len(key) > 40 {
		return string(key[:40]) + "…"
	}
	return string(key)
}
