// SPDX-License-Identifier: LicenseRef-trstctl-EE

//trstctl:repository
package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/internal/eventspec"
	corestore "trstctl.com/trstctl/internal/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

const (
	CompletionKindReprotection = "reprotection"
	CompletionKindRevocation   = "revocation"
)

// MigrationsFS returns the VDEC DDL as a migration source for the core store's
// feature-neutral WithExtraMigrations seam.
func MigrationsFS() fs.FS { return migrationsFS }

type Repo struct {
	core *corestore.Store
}

func New(core *corestore.Store) *Repo { return &Repo{core: core} }

type CompletionEvent struct {
	KeyID          string
	Dependent      depstate.Dependent
	Kind           string
	JobID          string
	SuccessorKeyID string
	Destination    string
	LedgerPosition uint64
}

type RevocationCompletion struct {
	KeyID          string
	Dependent      depstate.Dependent
	Destination    string
	JobID          string
	LedgerPosition uint64
}

// RebuildTenant folds a ledger prefix into the tenant-scoped VDEC serving read
// model. The ledger remains the source of truth; these tables are rebuilt from
// events and read by the control plane when assembling a signer-gate request.
func (r *Repo) RebuildTenant(ctx context.Context, tenantID string, seq []eventspec.Event) error {
	proj, err := depstate.Fold(seq)
	if err != nil {
		return fmt.Errorf("decommission store: fold dependency state: %w", err)
	}
	states := statesForTenant(proj, tenantID)

	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := clearTenant(ctx, tx); err != nil {
			return err
		}
		for _, state := range states {
			if err := insertKeyState(ctx, tx, state); err != nil {
				return err
			}
			if err := insertDependents(ctx, tx, state); err != nil {
				return err
			}
		}
		for i, e := range seq {
			if err := insertCompletionFromEvent(ctx, tx, tenantID, e, ledgerPosition(e, i)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *Repo) FetchKeyState(ctx context.Context, tenantID, keyID string) (depstate.KeyState, bool, error) {
	var out depstate.KeyState
	found := false
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT key_id, ledger_position
			   FROM decommission_key_states
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND key_id = $1`, keyID).
			Scan(&out.KeyID, &out.LedgerPosition); err != nil {
			if err == pgx.ErrNoRows {
				return nil
			}
			return fmt.Errorf("decommission store: fetch key state: %w", err)
		}
		found = true
		out.TenantID = tenantID
		registered, err := fetchRegistered(ctx, tx, keyID)
		if err != nil {
			return err
		}
		accounted, err := fetchAccounted(ctx, tx, keyID)
		if err != nil {
			return err
		}
		released, err := fetchReleased(ctx, tx, keyID)
		if err != nil {
			return err
		}
		erased, err := fetchErasureDesignated(ctx, tx, keyID)
		if err != nil {
			return err
		}
		out.Registered = registered
		out.Accounted = accounted
		out.Released = released
		out.ErasureDesignated = erased
		return nil
	})
	if err != nil {
		return depstate.KeyState{}, false, err
	}
	return out, found, nil
}

func (r *Repo) UnaccountedDependents(ctx context.Context, tenantID, keyID string) ([]depstate.Dependent, error) {
	var out []depstate.Dependent
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT dependent_class, dependent_id
			   FROM decommission_dependents
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			    AND key_id = $1
			    AND accounted_ordinal IS NULL
			  ORDER BY registered_ordinal ASC`, keyID)
		if err != nil {
			return fmt.Errorf("decommission store: unaccounted dependents: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			dep, err := scanDependent(rows)
			if err != nil {
				return err
			}
			out = append(out, dep)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repo) ListCompletionEvents(ctx context.Context, tenantID, keyID string) ([]CompletionEvent, error) {
	var out []CompletionEvent
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT key_id, dependent_class, dependent_id, completion_kind, job_id,
			        successor_key_id, destination, ledger_position
			   FROM decommission_completion_events
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND key_id = $1
			  ORDER BY ledger_position ASC, completion_kind ASC, job_id ASC`, keyID)
		if err != nil {
			return fmt.Errorf("decommission store: list completion events: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var ev CompletionEvent
			var class string
			if err := rows.Scan(&ev.KeyID, &class, &ev.Dependent.ID, &ev.Kind, &ev.JobID, &ev.SuccessorKeyID, &ev.Destination, &ev.LedgerPosition); err != nil {
				return fmt.Errorf("decommission store: scan completion event: %w", err)
			}
			ev.Dependent.Class = depstate.DependentClass(class)
			out = append(out, ev)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repo) ListRevocationCompletions(ctx context.Context, tenantID, keyID string) ([]RevocationCompletion, error) {
	var out []RevocationCompletion
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT key_id, dependent_class, dependent_id, destination, completion_job_id, completion_ledger_position
			   FROM decommission_revocations
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			    AND key_id = $1
			    AND completed = true
			  ORDER BY dependent_class ASC, dependent_id ASC, destination ASC`, keyID)
		if err != nil {
			return fmt.Errorf("decommission store: list revocation completions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var rc RevocationCompletion
			var class string
			if err := rows.Scan(&rc.KeyID, &class, &rc.Dependent.ID, &rc.Destination, &rc.JobID, &rc.LedgerPosition); err != nil {
				return fmt.Errorf("decommission store: scan revocation completion: %w", err)
			}
			rc.Dependent.Class = depstate.DependentClass(class)
			out = append(out, rc)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func clearTenant(ctx context.Context, tx pgx.Tx) error {
	for _, stmt := range []string{
		`DELETE FROM decommission_revocations WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`,
		`DELETE FROM decommission_completion_events WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`,
		`DELETE FROM decommission_dependents WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`,
		`DELETE FROM decommission_key_states WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`,
	} {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("decommission store: clear tenant read model: %w", err)
		}
	}
	return nil
}

func insertKeyState(ctx context.Context, tx pgx.Tx, state depstate.KeyState) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO decommission_key_states (tenant_id, key_id, ledger_position)
		 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2)
		 ON CONFLICT (tenant_id, key_id)
		 DO UPDATE SET ledger_position = EXCLUDED.ledger_position, updated_at = now()`,
		state.KeyID, state.LedgerPosition)
	if err != nil {
		return fmt.Errorf("decommission store: insert key state: %w", err)
	}
	return nil
}

type dependentRow struct {
	dep               depstate.Dependent
	registeredOrdinal int64
	accountedOrdinal  *int64
	releasedOrdinal   *int64
	erasureOrdinal    *int64
}

func insertDependents(ctx context.Context, tx pgx.Tx, state depstate.KeyState) error {
	rows := dependentRows(state)
	for _, row := range rows {
		_, err := tx.Exec(ctx,
			`INSERT INTO decommission_dependents
			   (tenant_id, key_id, dependent_class, dependent_id, registered_ordinal,
			    accounted_ordinal, released_ordinal, erasure_ordinal, ledger_position)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8)
			 ON CONFLICT (tenant_id, key_id, dependent_class, dependent_id)
			 DO UPDATE SET registered_ordinal = EXCLUDED.registered_ordinal,
			               accounted_ordinal = EXCLUDED.accounted_ordinal,
			               released_ordinal = EXCLUDED.released_ordinal,
			               erasure_ordinal = EXCLUDED.erasure_ordinal,
			               ledger_position = EXCLUDED.ledger_position`,
			state.KeyID, string(row.dep.Class), row.dep.ID, row.registeredOrdinal, row.accountedOrdinal, row.releasedOrdinal, row.erasureOrdinal, state.LedgerPosition)
		if err != nil {
			return fmt.Errorf("decommission store: insert dependent %s/%s: %w", row.dep.Class, row.dep.ID, err)
		}
	}
	return nil
}

func insertCompletionFromEvent(ctx context.Context, tx pgx.Tx, tenantID string, e eventspec.Event, pos uint64) error {
	payload, err := depstate.Decode(e)
	if err != nil {
		return fmt.Errorf("decommission store: decode completion event %s: %w", e.Type, err)
	}
	switch v := payload.(type) {
	case depstate.ReprotectionCompletedV1:
		if v.TenantID != tenantID {
			return nil
		}
		return insertCompletion(ctx, tx, CompletionEvent{
			KeyID: v.KeyID, Dependent: v.Dependent, Kind: CompletionKindReprotection,
			JobID: v.JobID, SuccessorKeyID: v.SuccessorKeyID, LedgerPosition: pos,
		})
	case depstate.RevocationCompletedV1:
		if v.TenantID != tenantID {
			return nil
		}
		if err := insertCompletion(ctx, tx, CompletionEvent{
			KeyID: v.KeyID, Dependent: v.Dependent, Kind: CompletionKindRevocation,
			JobID: v.JobID, Destination: v.Destination, LedgerPosition: pos,
		}); err != nil {
			return err
		}
		return insertRevocationCompletion(ctx, tx, RevocationCompletion{
			KeyID: v.KeyID, Dependent: v.Dependent, Destination: v.Destination,
			JobID: v.JobID, LedgerPosition: pos,
		})
	default:
		return nil
	}
}

func insertCompletion(ctx context.Context, tx pgx.Tx, ev CompletionEvent) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO decommission_completion_events
		   (tenant_id, key_id, dependent_class, dependent_id, completion_kind,
		    job_id, successor_key_id, destination, ledger_position)
		 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (tenant_id, key_id, dependent_class, dependent_id, completion_kind, destination, job_id) DO NOTHING`,
		ev.KeyID, string(ev.Dependent.Class), ev.Dependent.ID, ev.Kind, ev.JobID, ev.SuccessorKeyID, ev.Destination, ev.LedgerPosition)
	if err != nil {
		return fmt.Errorf("decommission store: insert completion event: %w", err)
	}
	return nil
}

func insertRevocationCompletion(ctx context.Context, tx pgx.Tx, rc RevocationCompletion) error {
	destination := rc.Destination
	if destination == "" {
		destination = "default"
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO decommission_revocations
		   (tenant_id, key_id, dependent_class, dependent_id, destination,
		    completion_job_id, completion_ledger_position, completed)
		 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, true)
		 ON CONFLICT (tenant_id, key_id, dependent_class, dependent_id, destination)
		 DO UPDATE SET completion_job_id = EXCLUDED.completion_job_id,
		               completion_ledger_position = EXCLUDED.completion_ledger_position,
		               completed = true,
		               updated_at = now()`,
		rc.KeyID, string(rc.Dependent.Class), rc.Dependent.ID, destination, rc.JobID, rc.LedgerPosition)
	if err != nil {
		return fmt.Errorf("decommission store: insert revocation completion: %w", err)
	}
	return nil
}

func fetchRegistered(ctx context.Context, tx pgx.Tx, keyID string) ([]depstate.Dependent, error) {
	rows, err := tx.Query(ctx,
		`SELECT dependent_class, dependent_id
		   FROM decommission_dependents
		  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND key_id = $1
		  ORDER BY registered_ordinal ASC`, keyID)
	if err != nil {
		return nil, fmt.Errorf("decommission store: fetch registered dependents: %w", err)
	}
	return collectDependents(rows)
}

func fetchAccounted(ctx context.Context, tx pgx.Tx, keyID string) ([]depstate.Dependent, error) {
	rows, err := tx.Query(ctx,
		`SELECT dependent_class, dependent_id
		   FROM decommission_dependents
		  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
		    AND key_id = $1
		    AND accounted_ordinal IS NOT NULL
		  ORDER BY accounted_ordinal ASC`, keyID)
	if err != nil {
		return nil, fmt.Errorf("decommission store: fetch accounted dependents: %w", err)
	}
	return collectDependents(rows)
}

func fetchReleased(ctx context.Context, tx pgx.Tx, keyID string) ([]depstate.Dependent, error) {
	rows, err := tx.Query(ctx,
		`SELECT dependent_class, dependent_id
		   FROM decommission_dependents
		  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
		    AND key_id = $1
		    AND released_ordinal IS NOT NULL
		  ORDER BY released_ordinal ASC`, keyID)
	if err != nil {
		return nil, fmt.Errorf("decommission store: fetch released dependents: %w", err)
	}
	return collectDependents(rows)
}

func fetchErasureDesignated(ctx context.Context, tx pgx.Tx, keyID string) ([]depstate.Dependent, error) {
	rows, err := tx.Query(ctx,
		`SELECT dependent_class, dependent_id
		   FROM decommission_dependents
		  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
		    AND key_id = $1
		    AND erasure_ordinal IS NOT NULL
		  ORDER BY erasure_ordinal ASC`, keyID)
	if err != nil {
		return nil, fmt.Errorf("decommission store: fetch erasure-designated dependents: %w", err)
	}
	return collectDependents(rows)
}

func collectDependents(rows pgx.Rows) ([]depstate.Dependent, error) {
	defer rows.Close()
	var out []depstate.Dependent
	for rows.Next() {
		dep, err := scanDependent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, dep)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type dependentScanner interface {
	Scan(dest ...any) error
}

func scanDependent(row dependentScanner) (depstate.Dependent, error) {
	var class string
	var id string
	if err := row.Scan(&class, &id); err != nil {
		return depstate.Dependent{}, fmt.Errorf("decommission store: scan dependent: %w", err)
	}
	return depstate.Dependent{Class: depstate.DependentClass(class), ID: id}, nil
}

func statesForTenant(proj depstate.Projection, tenantID string) []depstate.KeyState {
	states := make([]depstate.KeyState, 0)
	for key, state := range proj {
		if key.TenantID == tenantID {
			states = append(states, state)
		}
	}
	sort.Slice(states, func(i, j int) bool { return states[i].KeyID < states[j].KeyID })
	return states
}

func dependentRows(state depstate.KeyState) []dependentRow {
	rows := make(map[string]*dependentRow, len(state.Registered))
	for i, dep := range state.Registered {
		cp := dep
		rows[dependentKey(dep)] = &dependentRow{dep: cp, registeredOrdinal: int64(i)}
	}
	setOrdinal := func(deps []depstate.Dependent, set func(*dependentRow, int64)) {
		for i, dep := range deps {
			row := rows[dependentKey(dep)]
			if row == nil {
				continue
			}
			set(row, int64(i))
		}
	}
	setOrdinal(state.Accounted, func(row *dependentRow, ord int64) { row.accountedOrdinal = int64Ptr(ord) })
	setOrdinal(state.Released, func(row *dependentRow, ord int64) { row.releasedOrdinal = int64Ptr(ord) })
	setOrdinal(state.ErasureDesignated, func(row *dependentRow, ord int64) { row.erasureOrdinal = int64Ptr(ord) })

	out := make([]dependentRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].registeredOrdinal < out[j].registeredOrdinal })
	return out
}

func int64Ptr(v int64) *int64 { return &v }

func dependentKey(dep depstate.Dependent) string {
	return string(dep.Class) + "\x00" + dep.ID
}

func ledgerPosition(e eventspec.Event, index int) uint64 {
	if e.Sequence != 0 {
		return e.Sequence
	}
	return uint64(index + 1)
}
