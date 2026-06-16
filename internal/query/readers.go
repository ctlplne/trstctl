package query

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

// Each reader is tenant-scoped by construction: it is only ever called with the
// authenticated principal's tenant, and the underlying store reads run under
// PostgreSQL RLS for that tenant (AN-1). Equality predicates are applied in-process
// against typed fields — values are never spliced into a statement.

func (e *Engine) readOwners(ctx context.Context, tenant string, eq map[Field]string, add func(Row) bool) error {
	owners, err := e.store.ListOwners(ctx, tenant)
	if err != nil {
		return err
	}
	want, filter := eq[FieldOwnerName]
	for _, o := range owners {
		if filter && o.Name != want {
			continue
		}
		if !add(Row{Surface: SurfaceOwners, Columns: map[string]string{"id": o.ID, "name": o.Name}}) {
			return nil
		}
	}
	return nil
}

func (e *Engine) readCertificates(ctx context.Context, tenant string, eq map[Field]string, add func(Row) bool) error {
	certs, err := e.store.ListCertificatesPage(ctx, tenant, store.ZeroUUID, nil, e.cfg.MaxRows, nil)
	if err != nil {
		return err
	}
	wantOwner, byOwner := eq[FieldOwnerID]
	wantSerial, bySerial := eq[FieldCertSerial]
	for _, c := range certs {
		owner := ""
		if c.OwnerID != nil {
			owner = *c.OwnerID
		}
		if byOwner && owner != wantOwner {
			continue
		}
		if bySerial && c.Serial != wantSerial {
			continue
		}
		if !add(Row{Surface: SurfaceCertificates, Columns: map[string]string{
			"id": c.ID, "owner_id": owner, "serial": c.Serial,
			"subject": c.Subject, "fingerprint": c.Fingerprint,
		}}) {
			return nil
		}
	}
	return nil
}

func (e *Engine) readGraph(ctx context.Context, tenant string, eq map[Field]string, add func(Row) bool) error {
	// The graph is built from the tenant's own inventory (per-tenant, under RLS), so
	// its nodes cannot reference another tenant's rows — a traversal cannot escape
	// the boundary (design V7).
	g, err := graph.Build(ctx, e.store, tenant)
	if err != nil {
		return err
	}
	want, filter := eq[FieldGraphNodeKind]
	for _, n := range g.Nodes() {
		if filter && string(n.Kind) != want {
			continue
		}
		if !add(Row{Surface: SurfaceGraph, Columns: map[string]string{
			"id": n.ID, "kind": string(n.Kind), "name": n.Name,
		}}) {
			return nil
		}
	}
	return nil
}

func (e *Engine) readCBOM(ctx context.Context, tenant string, eq map[Field]string, add func(Row) bool) error {
	assets, err := e.store.ListCryptoAssets(ctx, tenant)
	if err != nil {
		return err
	}
	want, filter := eq[FieldCBOMAlgorithm]
	for _, a := range assets {
		if filter && a.Algorithm != want {
			continue
		}
		if !add(Row{Surface: SurfaceCBOM, Columns: map[string]string{
			"kind": a.Kind, "location": a.Location, "algorithm": a.Algorithm,
			"library": a.Library, "strength": a.Strength,
		}}) {
			return nil
		}
	}
	return nil
}

// errEnough stops a log replay early once the row budget is met.
var errEnough = errors.New("query: row budget met")

func (e *Engine) readLog(ctx context.Context, tenant string, eq map[Field]string, limit int, offset *uint64, add func(Row) bool) error {
	if e.log == nil {
		return nil
	}
	want, filter := eq[FieldLogType]
	err := e.log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.Sequence > *offset {
			*offset = ev.Sequence // AN-2: pin the result to the log offset observed
		}
		// Tenant floor in-process: the event log is not RLS-backed, so the engine
		// drops any event not belonging to the caller's tenant. Combined with the
		// Postgres RLS floor on the other surfaces, no cross-tenant row is reachable.
		if ev.TenantID != tenant {
			return nil
		}
		if filter && ev.Type != want {
			return nil
		}
		if !add(Row{Surface: SurfaceLog, Columns: map[string]string{
			"id": ev.ID, "type": ev.Type, "tenant_id": ev.TenantID,
		}}) {
			return errEnough
		}
		return nil
	})
	if errors.Is(err, errEnough) {
		return nil
	}
	return err
}
