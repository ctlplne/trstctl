// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These two already-shipped files are immutable. A pending upgrade uses a
// checksum-bound online execution plan; an applied ledger row is never rerun.
// Unknown bytes cannot fall back to the unsafe historical execution path.
type onlineCompatibilityPlan struct {
	name, digest, table, expandSQL, index, createSQL, predicate, validateSQL string
	columns                                                                  []onlineCompatibilityColumn
	indexColumns                                                             []string
}

type onlineCompatibilityColumn struct {
	name, dataType, defaultExpression string
	notNull                           bool
}

func historicalOnlinePlan(name string, body []byte) (*onlineCompatibilityPlan, error) {
	var p onlineCompatibilityPlan
	switch name {
	case "0211_connector_rollback_projection_order.sql":
		p = onlineCompatibilityPlan{
			name: name, digest: "sha256:1be56c768b33cbab18afb11f83d3663bd2e29cd72eca59b24d1896451401484b",
			table: "public.connector_delivery_receipts", index: "connector_rollback_receipts_unordered",
			columns: []onlineCompatibilityColumn{{name: "latest_event_sequence", dataType: "bigint", defaultExpression: "0"}},
			expandSQL: `ALTER TABLE public.connector_delivery_receipts ADD COLUMN latest_event_sequence bigint DEFAULT 0;
			 ALTER TABLE public.connector_delivery_receipts ADD CONSTRAINT connector_delivery_receipts_latest_event_sequence_check
			 CHECK (latest_event_sequence >= 0) NOT VALID;`,
			indexColumns: []string{"tenant_id", "id"},
			predicate:    "destination = 'connector.rollback'::text AND COALESCE(latest_event_sequence, 0::bigint) = 0",
			createSQL: `CREATE INDEX CONCURRENTLY connector_rollback_receipts_unordered
			 ON public.connector_delivery_receipts (tenant_id,id)
			 WHERE destination='connector.rollback' AND coalesce(latest_event_sequence,0)=0`,
			validateSQL: `ALTER TABLE public.connector_delivery_receipts VALIDATE CONSTRAINT connector_delivery_receipts_latest_event_sequence_check`,
		}
	case "0219_notification_delivery_routing.sql":
		p = onlineCompatibilityPlan{
			name: name, digest: "sha256:32310f4bc7d24c07f9a5b37c4686dbb577460328d2710e90e178fa2b3b8a3bac",
			table: "public.notification_delivery_receipts", index: "notification_delivery_receipts_command_idx",
			columns: []onlineCompatibilityColumn{
				{name: "routing_source", dataType: "text", defaultExpression: "''::text", notNull: true},
				{name: "routing_policy_id", dataType: "text", defaultExpression: "''::text", notNull: true},
				{name: "routing_policy_scope", dataType: "text", defaultExpression: "''::text", notNull: true},
				{name: "routing_policy_digest", dataType: "text", defaultExpression: "''::text", notNull: true},
			},
			expandSQL: `ALTER TABLE public.notification_delivery_receipts
			 ADD COLUMN routing_source text NOT NULL DEFAULT '', ADD COLUMN routing_policy_id text NOT NULL DEFAULT '',
			 ADD COLUMN routing_policy_scope text NOT NULL DEFAULT '', ADD COLUMN routing_policy_digest text NOT NULL DEFAULT '';`,
			indexColumns: []string{"tenant_id", "destination", "notification_key_digest"},
			createSQL: `CREATE INDEX CONCURRENTLY notification_delivery_receipts_command_idx
			 ON public.notification_delivery_receipts (tenant_id,destination,notification_key_digest)`,
		}
	default:
		return nil, nil
	}
	if migrationChecksum(body) != p.digest {
		return nil, fmt.Errorf("%w: online execution of %s requires its immutable shipped bytes", ErrMigrationChecksumMismatch, name)
	}
	return &p, nil
}

type onlineCompatibilityQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Only schema metadata is read. A partial/mismatched expansion is refused,
// rather than trusting IF NOT EXISTS to mean the existing shape is correct.
func (p *onlineCompatibilityPlan) columnsPresent(ctx context.Context, q onlineCompatibilityQuery) (bool, error) {
	present := 0
	for _, column := range p.columns {
		var dataType, expression, identity, generated string
		var notNull, ordinary bool
		err := q.QueryRow(ctx,
			//trstctl:system-query — cross-tenant system migration recovery reads only exact PostgreSQL column catalog metadata; no tenant_id or tenant payload is returned (AN-1 exemption).
			`SELECT a.atttypid::regtype::text,a.attnotnull,coalesce(pg_get_expr(d.adbin,d.adrelid),''),
			 a.attidentity::text,a.attgenerated::text,
			 a.atttypmod=-1 AND a.attndims=0 AND a.attislocal AND a.attinhcount=0 AND a.attcollation=t.typcollation
			 FROM pg_attribute a JOIN pg_type t ON t.oid=a.atttypid
			 LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
			 WHERE a.attrelid=$1::regclass AND a.attname=$2 AND a.attnum>0 AND NOT a.attisdropped`, p.table, column.name).
			Scan(&dataType, &notNull, &expression, &identity, &generated, &ordinary)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return false, err
		}
		if dataType != column.dataType || notNull != column.notNull || expression != column.defaultExpression || identity != "" || generated != "" || !ordinary {
			return false, fmt.Errorf("store: online migration %s refuses mismatched column %s", p.name, column.name)
		}
		present++
	}
	if present != 0 && present != len(p.columns) {
		return false, fmt.Errorf("store: online migration %s refuses a partial column expansion", p.name)
	}
	return present == len(p.columns), nil
}

func (p *onlineCompatibilityPlan) checkConstraint(ctx context.Context, q onlineCompatibilityQuery) (bool, error) {
	if p.validateSQL == "" {
		return true, nil
	}
	var kind, expression string
	var valid, noInherit bool
	err := q.QueryRow(ctx,
		//trstctl:system-query — cross-tenant system migration recovery checks the exact catalog constraint and its validation bit; no tenant_id or row values leave PostgreSQL (AN-1 exemption).
		`SELECT contype::text,convalidated,connoinherit,pg_get_expr(conbin,conrelid,true)
		 FROM pg_constraint WHERE conrelid=$1::regclass AND conname='connector_delivery_receipts_latest_event_sequence_check'`, p.table).
		Scan(&kind, &valid, &noInherit, &expression)
	if err != nil {
		return false, fmt.Errorf("store: online migration %s cannot verify its constraint: %w", p.name, err)
	}
	if kind != "c" || noInherit || expression != "latest_event_sequence >= 0" {
		return false, fmt.Errorf("store: online migration %s refuses a mismatched constraint", p.name)
	}
	return valid, nil
}

func (p *onlineCompatibilityPlan) expand(ctx context.Context, conn *pgxpool.Conn) error {
	present, err := p.columnsPresent(ctx, conn)
	if err != nil {
		return err
	}
	if present {
		_, err := p.checkConstraint(ctx, conn)
		return err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, p.expandSQL); err != nil {
		return err
	}
	present, err = p.columnsPresent(ctx, tx)
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("store: online migration %s did not establish its exact columns", p.name)
	}
	if _, err := p.checkConstraint(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *onlineCompatibilityPlan) indexState(ctx context.Context, conn *pgxpool.Conn) (exists, valid bool, err error) {
	var kind, method, predicate string
	var rightTable, unique, primary, exclusion, noExpressions, ready bool
	var keyCount, totalCount int
	var columns []string
	err = conn.QueryRow(ctx,
		//trstctl:system-query — cross-tenant system online-DDL recovery reads one schema-qualified index's definition and readiness; it exposes only catalog data, never tenant_id values or application payloads (AN-1 exemption).
		`SELECT c.relkind::text,i.indrelid=$1::regclass,a.amname,i.indisunique,i.indisprimary,i.indisexclusion,
		 i.indnkeyatts,i.indnatts,i.indexprs IS NULL,
		 ARRAY(SELECT pg_get_indexdef(i.indexrelid,n,false) FROM generate_series(1,i.indnkeyatts) n),
		 coalesce(pg_get_expr(i.indpred,i.indrelid,true),''),i.indisvalid,i.indisready
		 FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace
		 LEFT JOIN pg_index i ON i.indexrelid=c.oid LEFT JOIN pg_am a ON a.oid=c.relam
		 WHERE ns.nspname='public' AND c.relname=$2`, p.table, p.index).
		Scan(&kind, &rightTable, &method, &unique, &primary, &exclusion, &keyCount, &totalCount, &noExpressions, &columns, &predicate, &valid, &ready)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if kind != "i" || !rightTable || method != "btree" || unique || primary || exclusion || !noExpressions || keyCount != len(p.indexColumns) || totalCount != keyCount || !slices.Equal(columns, p.indexColumns) || strings.Join(strings.Fields(predicate), " ") != p.predicate {
		return true, false, fmt.Errorf("store: online migration %s refuses same-name index with a different definition", p.name)
	}
	return true, valid && ready, nil
}

func (p *onlineCompatibilityPlan) apply(ctx context.Context, conn *pgxpool.Conn) error {
	if err := p.expand(ctx, conn); err != nil {
		return err
	}
	exists, valid, err := p.indexState(ctx, conn)
	if err != nil {
		return err
	}
	if exists && !valid {
		if _, err := conn.Exec(ctx, p.dropSQL()); err != nil {
			return err
		}
	}
	if !valid {
		if _, err := conn.Exec(ctx, p.createSQL); err != nil {
			return err
		}
	}
	exists, valid, err = p.indexState(ctx, conn)
	if err != nil {
		return err
	}
	if !exists || !valid {
		return fmt.Errorf("store: online migration %s index is not ready", p.name)
	}
	validated, err := p.checkConstraint(ctx, conn)
	if err != nil {
		return err
	}
	if !validated {
		if _, err := conn.Exec(ctx, p.validateSQL); err != nil {
			return err
		}
		validated, err = p.checkConstraint(ctx, conn)
		if err != nil {
			return err
		}
		if !validated {
			return fmt.Errorf("store: online migration %s constraint remains unvalidated", p.name)
		}
	}
	return nil
}

// The original checksum still identifies the immutable shipped migration.
// This is the ordered DDL plan, including conditional recovery steps, not a
// claim that a retry re-executed every statement. The ledger records its digest.
func (p *onlineCompatibilityPlan) executionSQL() string {
	return p.expandSQL + "\n" + p.dropSQL() + ";\n" + p.createSQL + ";\n" + p.validateSQL + ";\n"
}

func (p *onlineCompatibilityPlan) dropSQL() string {
	return "DROP INDEX CONCURRENTLY public." + pgx.Identifier{p.index}.Sanitize()
}
