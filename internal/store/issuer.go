package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// IssuerKind distinguishes an X.509 certificate authority from the SSH CA.
type IssuerKind string

const (
	// IssuerX509CA is an X.509 CA: it carries a certificate chain (its CA cert
	// plus any intermediates). It may be an external CA or an internal authority
	// (see Issuer.Internal).
	IssuerX509CA IssuerKind = "x509_ca"
	// IssuerSSHCA is the SSH CA: a single trusted signing key with no chain. SSH
	// has no PKI hierarchy — trust is the CA public key alone.
	IssuerSSHCA IssuerKind = "ssh_ca"
)

// Issuer is a signing authority. An X.509 CA carries a PEM Chain; the SSH CA is
// chainless and carries only its PublicKey. This distinction is structural: the
// two are not interchangeable.
type Issuer struct {
	ID        string
	TenantID  string
	Kind      IssuerKind
	Name      string
	Chain     []string // X.509 CA: PEM chain (CA cert + intermediates). Empty for SSH.
	PublicKey string   // SSH CA: the trusted signing key. Empty for X.509.
	Internal  bool     // X.509: an authority trstctl operates itself.
	CreatedAt time.Time
}

// Chainless reports whether the issuer has no certificate chain — true exactly
// for the SSH CA, whose trust is a single signing key rather than a chain.
func (i Issuer) Chainless() bool { return i.Kind == IssuerSSHCA }

// Validate enforces the structural distinction between the issuer kinds: an
// X.509 CA must carry a chain and no SSH key; the SSH CA must carry a signing key
// and no chain.
func (i Issuer) Validate() error {
	switch i.Kind {
	case IssuerX509CA:
		if len(i.Chain) == 0 {
			return fmt.Errorf("issuer: x509 CA %q must carry a certificate chain", i.Name)
		}
		if i.PublicKey != "" {
			return fmt.Errorf("issuer: x509 CA %q must not carry a standalone SSH signing key", i.Name)
		}
	case IssuerSSHCA:
		if len(i.Chain) != 0 {
			return fmt.Errorf("issuer: ssh CA %q is chainless and must not carry a chain", i.Name)
		}
		if i.PublicKey == "" {
			return fmt.Errorf("issuer: ssh CA %q must carry its trusted signing key", i.Name)
		}
	default:
		return fmt.Errorf("issuer: unknown kind %q", i.Kind)
	}
	return nil
}

// UpsertIssuer validates and then inserts or updates an issuer in its tenant
// context (RLS-enforced).
func (s *Store) UpsertIssuer(ctx context.Context, i Issuer) error {
	if err := i.Validate(); err != nil {
		return err
	}
	// A nil slice would be sent as SQL NULL, violating the NOT NULL chain column
	// (the DEFAULT applies only to an omitted column); send an empty array.
	chain := i.Chain
	if chain == nil {
		chain = []string{}
	}
	return s.WithTenant(ctx, i.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO issuers (id, tenant_id, kind, name, chain, public_key, internal)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)
			 ON CONFLICT (id) DO UPDATE
			    SET kind = EXCLUDED.kind, name = EXCLUDED.name, chain = EXCLUDED.chain,
			        public_key = EXCLUDED.public_key, internal = EXCLUDED.internal`,
			i.ID, i.TenantID, string(i.Kind), i.Name, chain, i.PublicKey, i.Internal)
		return err
	})
}

// CreateIssuer validates and inserts a new issuer with a server-generated id,
// returning it populated with that id and created_at.
func (s *Store) CreateIssuer(ctx context.Context, i Issuer) (Issuer, error) {
	if err := i.Validate(); err != nil {
		return Issuer{}, err
	}
	chain := i.Chain
	if chain == nil {
		chain = []string{}
	}
	err := s.WithTenant(ctx, i.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO issuers (id, tenant_id, kind, name, chain, public_key, internal)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6)
			 RETURNING id::text, created_at`,
			i.TenantID, string(i.Kind), i.Name, chain, i.PublicKey, i.Internal).Scan(&i.ID, &i.CreatedAt)
	})
	return i, err
}

// ListIssuersPage returns up to limit issuers with id greater than afterID
// (keyset pagination; pass ZeroUUID for the first page).
func (s *Store) ListIssuersPage(ctx context.Context, tenantID, afterID string, limit int) ([]Issuer, error) {
	var out []Issuer
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, kind, name, chain, public_key, internal, created_at
			   FROM issuers WHERE tenant_id = $1 AND id > $2 ORDER BY id LIMIT $3`,
			tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				i    Issuer
				kind string
			)
			if err := rows.Scan(&i.ID, &i.TenantID, &kind, &i.Name, &i.Chain, &i.PublicKey, &i.Internal, &i.CreatedAt); err != nil {
				return err
			}
			i.Kind = IssuerKind(kind)
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}

// GetIssuer loads an issuer in its tenant context.
func (s *Store) GetIssuer(ctx context.Context, tenantID, id string) (Issuer, error) {
	var (
		i    Issuer
		kind string
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, kind, name, chain, public_key, internal, created_at
			   FROM issuers WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&i.ID, &i.TenantID, &kind, &i.Name, &i.Chain, &i.PublicKey, &i.Internal, &i.CreatedAt)
	})
	i.Kind = IssuerKind(kind)
	return i, err
}

// ListIssuers returns all issuers for a tenant.
func (s *Store) ListIssuers(ctx context.Context, tenantID string) ([]Issuer, error) {
	var out []Issuer
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, kind, name, chain, public_key, internal, created_at
			   FROM issuers WHERE tenant_id = $1 ORDER BY created_at, id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				i    Issuer
				kind string
			)
			if err := rows.Scan(&i.ID, &i.TenantID, &kind, &i.Name, &i.Chain, &i.PublicKey, &i.Internal, &i.CreatedAt); err != nil {
				return err
			}
			i.Kind = IssuerKind(kind)
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}
