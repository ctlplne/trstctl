// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package brokerstore is the CONTROL-PLANE-ONLY datastore backing for the AGID-07b
// chain-bound issuance recorder: it persists the verified attestation binding + the
// issued-credential registry row + the AN-6 outbox publish intent in ONE RLS-scoped
// transaction, and refuses a REPLAY of the same attestation evidence via the AGID-02
// agent_attestation_bindings unique index (claim 9 / INV-A6).
//
// It lives in its OWN package, SEPARATE from the signer-linked `delegation` package,
// precisely so the isolated AN-4 signer (which imports delegation.NewSignerGate) never
// links a SQL driver or a message bus. The broker/control plane imports THIS package; the
// signer never does. It satisfies delegation.IssuanceBindingRecorder, so the
// BrokerPrecondition holds it behind that datastore-free interface.
//
// It writes raw per-tenant DML against tenant tables, so it opts into the AN-1
// tenant-filter rule with the //trstctl:repository marker.
//
//trstctl:repository
package brokerstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/ee/agentid/delegation"
	corestore "trstctl.com/trstctl/internal/store"
)

// Recorder persists chain-bound issuance bindings and refuses replays over the core
// store + AN-6 outbox. Construct it with New over the core store; a Recorder with a nil
// store is fail-closed (every persist refuses with delegation.ErrNoBindingStore).
type Recorder struct {
	core  *corestore.Store
	clock func() time.Time
}

// Compile-time proof the recorder satisfies the datastore-free seam the precondition
// holds (so the signer-linked delegation package never needs to import this one).
var _ delegation.IssuanceBindingRecorder = (*Recorder)(nil)

// New builds a recorder over the core store (which the AGID-02 migrations extended with
// agent_attestation_bindings + agent_issuances + outbox). A nil core is permitted so the
// fail-closed default wiring (before AGID-INT-WIRE provisions a store) constructs a
// recorder that refuses every persist.
func New(core *corestore.Store) *Recorder {
	return &Recorder{core: core, clock: time.Now}
}

// WithClock overrides the recorder clock (for deterministic tests). It returns the
// recorder for chaining.
func (r *Recorder) WithClock(clock func() time.Time) *Recorder {
	if clock != nil {
		r.clock = clock
	}
	return r
}

// RecordIssuanceBinding persists the issuance registry row and the verified attestation
// binding, and appends the AN-6 outbox publish intent, in ONE RLS-scoped transaction
// (AN-1/AN-6). A duplicate attestation evidence digest is rejected by the UNIQUE index
// and surfaced as delegation.ErrAttestationReplay (claim 9 / INV-A6) — the transaction
// rolls back, so NO issuance row, NO binding, and NO outbox intent are written for a
// replay. It performs no key operation.
//
// When b.EvidenceDigest is empty (the chain-only fallback that required no attestation),
// the issuance row and the outbox intent are still written, but no attestation-binding
// row is (there is no evidence to bind or to replay-guard).
func (r *Recorder) RecordIssuanceBinding(ctx context.Context, b delegation.IssuanceBinding) error {
	if r == nil || r.core == nil {
		return delegation.ErrNoBindingStore
	}
	if b.TenantID == "" {
		return fmt.Errorf("brokerstore: RecordIssuanceBinding requires a tenant (AN-1)")
	}
	if b.IdempotencyKey == "" {
		return fmt.Errorf("brokerstore: RecordIssuanceBinding requires an idempotency key (AN-5)")
	}
	if b.CredentialID == "" {
		return fmt.Errorf("brokerstore: RecordIssuanceBinding requires a credential id")
	}
	verifiedAt := r.clock().Unix()
	err := r.core.WithTenant(ctx, b.TenantID, func(tx pgx.Tx) error {
		// Issuance registry row (INV-A3): binds the verified chain + agent-stack + the
		// attestation reference. The tenant_id column is bound from the RLS session
		// setting so the row is always the caller's tenant.
		if _, err := tx.Exec(ctx,
			`INSERT INTO agent_issuances
			   (tenant_id, credential_id, subject_id, chain_head_digest, chain_digest, agent_stack_digest,
			    task_envelope_digest, not_before, not_after, attestation_ref, seq)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9, 0)`,
			b.CredentialID, b.SubjectID, notNilBytes(b.ChainHeadDigest), notNilBytes(b.ChainDigest),
			notNilBytes(b.AgentStackDigest), nilIfEmptyBytes(b.TaskEnvelopeDigest),
			b.NotBefore, b.NotAfter, nilIfEmptyBytes(b.EvidenceDigest)); err != nil {
			return fmt.Errorf("record issuance: %w", err)
		}

		// Attestation binding (claim 9 / INV-A6): bound to the issuance it justified. The
		// evidence_digest UNIQUE index is what refuses a replay — a second issuance
		// presenting the same evidence violates it, and we surface ErrAttestationReplay.
		if len(b.EvidenceDigest) > 0 {
			bindingID := "attbind:" + b.CredentialID
			if _, err := tx.Exec(ctx,
				`INSERT INTO agent_attestation_bindings
				   (tenant_id, binding_id, credential_id, evidence_digest, attestation_class, verified_at, seq)
				 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, 0)`,
				bindingID, b.CredentialID, b.EvidenceDigest, b.AttestationClass, verifiedAt); err != nil {
				if isUniqueViolation(err) {
					return delegation.ErrAttestationReplay
				}
				return fmt.Errorf("record attestation binding: %w", err)
			}
		}

		// AN-6 outbox publish intent, SAME transaction (transactional outbox). The
		// idempotency key is carried so at-least-once delivery is exactly-once downstream.
		if _, err := tx.Exec(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3)`,
			delegation.AttestationBindingDestination, notNilBytes(b.ChainDigest), b.IdempotencyKey); err != nil {
			return fmt.Errorf("enqueue attestation-binding outbox: %w", err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, delegation.ErrAttestationReplay) {
			return delegation.ErrAttestationReplay
		}
		return fmt.Errorf("brokerstore: record issuance binding: %w", err)
	}
	return nil
}

// isUniqueViolation reports whether err is a PostgreSQL unique-constraint violation
// (SQLSTATE 23505) -- the evidence_digest UNIQUE index rejecting a replayed attestation.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// notNilBytes returns a non-nil, possibly-empty slice so a NOT NULL bytea column accepts
// it (chain_head_digest / chain_digest / agent_stack_digest are NOT NULL).
func notNilBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// nilIfEmptyBytes maps an empty slice to nil so an optional bytea column stores SQL NULL
// (task_envelope_digest / attestation_ref are nullable).
func nilIfEmptyBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}
