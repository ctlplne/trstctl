// SPDX-License-Identifier: BUSL-1.1

package query

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/aimodel"
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

func (e *Engine) readCertificates(ctx context.Context, tenant string, eq map[Field]string, window *CertificateExpiryWindow, limit int, add func(Row) bool) (bool, error) {
	pageSize := e.cfg.MaxRows
	var after, before *time.Time
	if window != nil {
		// Fetch one extra row to know whether the answer is complete. An exact
		// serial predicate may skip rows, so cap its scan at MaxRows+1 and report
		// that limit rather than making an unsupported completeness claim.
		pageSize = limit + 1
		if _, bySerial := eq[FieldCertSerial]; bySerial {
			pageSize = e.cfg.MaxRows + 1
		}
		after, before = &window.After, &window.Before
	}
	certs, err := e.store.ListCertificatesPage(ctx, tenant, store.ZeroUUID, after, pageSize, before)
	if err != nil {
		return false, err
	}
	scanTruncated := window != nil && pageSize == e.cfg.MaxRows+1 && len(certs) == pageSize
	wantOwner, byOwner := eq[FieldOwnerID]
	wantSerial, bySerial := eq[FieldCertSerial]
	for _, c := range certs {
		row := certificateRow(c)
		if byOwner && row.Columns["owner_id"] != wantOwner {
			continue
		}
		if bySerial && c.Serial != wantSerial {
			continue
		}
		if !add(row) {
			return true, nil
		}
	}
	return scanTruncated, nil
}

// readFilteredCertificates answers a typed certificate filter inside the store,
// fetching one row beyond the limit to know whether the answer is complete.
func (e *Engine) readFilteredCertificates(ctx context.Context, tenant string, f CertificateFilter, limit int, add func(Row) bool) (bool, error) {
	certs, err := e.store.FilterCertificates(ctx, tenant, f.store(), limit+1)
	if err != nil {
		return false, err
	}
	for i, c := range certs {
		if i == limit || !add(certificateRow(c)) {
			return true, nil
		}
	}
	return false, nil
}

func (f CertificateFilter) store() store.CertificateFilter {
	return store.CertificateFilter{
		Status: f.Status, ExpiresAfter: f.ExpiresAfter, ExpiresBefore: f.ExpiresBefore,
		IssuerContains: f.IssuerContains, NameContains: f.NameContains, KeyAlgorithm: f.KeyAlgorithm,
		OwnerName: f.OwnerName, Unowned: f.Unowned, Serial: f.Serial, Fingerprint: f.Fingerprint,
	}
}

func certificateRow(c store.Certificate) Row {
	owner := ""
	if c.OwnerID != nil {
		owner = *c.OwnerID
	}
	return Row{Surface: SurfaceCertificates, Columns: map[string]string{
		"id": c.ID, "owner_id": owner, "serial": c.Serial,
		"subject": c.Subject, "fingerprint": c.Fingerprint, "status": c.Status,
		"issuer": c.Issuer, "key_algorithm": c.KeyAlgorithm,
		"not_after": certificateExpiry(c.NotAfter),
	}}
}

func certificateExpiry(t *time.Time) string {
	if t == nil {
		return "unknown"
	}
	return t.UTC().Format(time.RFC3339)
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

// readCBOM reads the tenant's crypto assets and returns how many matched. The
// whole inventory is read, so the count is exact even past the row limit.
func (e *Engine) readCBOM(ctx context.Context, tenant string, eq map[Field]string, f *CryptoAssetFilter, add func(Row) bool) (int, error) {
	assets, err := e.store.ListCryptoAssets(ctx, tenant)
	if err != nil {
		return 0, err
	}
	want, filter := eq[FieldCBOMAlgorithm]
	matches, full := 0, false
	for _, a := range assets {
		if filter && a.Algorithm != want {
			continue
		}
		if f != nil && !f.matches(a) {
			continue
		}
		matches++
		if full {
			continue
		}
		full = !add(Row{Surface: SurfaceCBOM, Columns: map[string]string{
			"kind": a.Kind, "location": a.Location, "algorithm": a.Algorithm,
			"library": a.Library, "strength": a.Strength, "key_bits": strconv.Itoa(a.KeyBits),
			"quantum_vulnerable": strconv.FormatBool(a.QuantumVulnerable),
		}})
	}
	return matches, nil
}

func (f CryptoAssetFilter) matches(a store.CryptoAsset) bool {
	if f.Algorithm != "" && !algorithmFamily(a.Algorithm, f.Algorithm) {
		return false
	}
	if f.KeyBitsBelow > 0 && (a.KeyBits <= 0 || a.KeyBits >= f.KeyBitsBelow) {
		return false
	}
	return (!f.QuantumVulnerable || a.QuantumVulnerable) && (!f.OutOfPolicy || a.OutOfPolicy)
}

// algorithmFamily reports whether recorded names the family: equal, case aside,
// or the family followed by a dash ("ECDSA-P256", "ML-DSA-65").
func algorithmFamily(recorded, family string) bool {
	r, f := strings.ToLower(recorded), strings.ToLower(family)
	return r == f || strings.HasPrefix(r, f+"-")
}

// errEnough stops a log replay early once the row budget is met.
var errEnough = errors.New("query: row budget met")

func (e *Engine) readLog(ctx context.Context, tenant string, eq map[Field]string, limit int, offset *uint64, add func(Row) bool) error {
	if e.log == nil {
		return nil
	}
	want, filter := eq[FieldLogType]
	var tenantOffset uint64
	err := e.log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		head, err := e.log.LastSequence(readCtx)
		if err != nil {
			return err
		}
		return e.log.ReplayTenantThrough(readCtx, tenant, 1, head, func(ev events.Event) error {
			// Tenant floor in-process: the event log is not RLS-backed, so the engine
			// drops any event not belonging to the caller's tenant. Combined with the
			// Postgres RLS floor on the other surfaces, no cross-tenant row is reachable.
			if ev.TenantID != tenant {
				return nil
			}
			tenantOffset++
			if tenantOffset > *offset {
				*offset = tenantOffset // AN-2: tenant-local high-water mark observed.
			}
			if filter && ev.Type != want {
				return nil
			}
			columns := map[string]string{"id": ev.ID, "type": ev.Type, "tenant_id": ev.TenantID, "at": ev.Time.UTC().Format(time.RFC3339Nano)}
			if reason := renewalFailureReason(ev); reason != "" {
				columns["reason"] = reason
			}
			if !add(Row{Surface: SurfaceLog, Columns: columns}) {
				return errEnough
			}
			return nil
		})
	})
	if errors.Is(err, errEnough) {
		return nil
	}
	return err
}

// renewalFailureReason exposes only the recorded reason of a renewal failure,
// never arbitrary event payload. Audit readers already have access to this
// tenant's event, but the query/RCA seam must keep its evidence small and redact
// accidental key material before it can reach an answer or model prompt.
func renewalFailureReason(ev events.Event) string {
	if ev.Type != "identity.renewal_failed" && ev.Type != "credential.renewal.failed" {
		return ""
	}
	var payload struct {
		Reason string `json:"reason"`
	}
	if json.Unmarshal(ev.Data, &payload) != nil {
		return ""
	}
	reason := aimodel.DefaultRedactor(strings.Join(strings.Fields(payload.Reason), " "))
	runes := []rune(reason)
	if len(runes) > 200 {
		reason = string(runes[:200]) + "…"
	}
	return reason
}
