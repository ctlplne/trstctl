// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/crypto/windependents"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/servicedependents"
)

var ErrServiceDependentManifestNotFound = errors.New("store: service-account rotation review not found")
var ErrServiceDependentManifestEvidence = errors.New("store: service-account manifest projection differs from its retained digest; rebuild projections")

type ServiceDependentManifest struct {
	Header       servicedependents.RotationManifestHeader `json:"header"`
	HeaderDigest string                                   `json:"header_digest"`
	Actor        string                                   `json:"actor"`
	PageCount    int64                                    `json:"page_count"`
	EntryCount   int64                                    `json:"entry_count"`
	HostCount    int64                                    `json:"host_count"`
	Seal         *servicedependents.RotationManifestSeal  `json:"seal,omitempty"`
}

const dependentManifestColumns = `header,header_digest,actor,page_count,entry_count,host_count,seal`

func scanServiceDependentManifest(row pgx.Row) (ServiceDependentManifest, error) {
	var value ServiceDependentManifest
	var header, seal []byte
	err := row.Scan(&header, &value.HeaderDigest, &value.Actor, &value.PageCount, &value.EntryCount, &value.HostCount, &seal)
	if errors.Is(err, pgx.ErrNoRows) {
		return value, ErrServiceDependentManifestNotFound
	}
	if err != nil {
		return value, err
	}
	if json.Unmarshal(header, &value.Header) != nil {
		return value, ErrServiceDependentManifestEvidence
	}
	digest, err := value.Header.Digest()
	if err != nil || digest != value.HeaderDigest || value.Actor == "" || value.PageCount < 0 || value.EntryCount < 0 || value.HostCount < 0 || value.PageCount > 0 && value.HostCount < 1 {
		return value, ErrServiceDependentManifestEvidence
	}
	if len(seal) > 0 {
		var v servicedependents.RotationManifestSeal
		if json.Unmarshal(seal, &v) != nil || v.Validate(value.Header) != nil || v.PageCount != value.PageCount || v.EntryCount != value.EntryCount || v.HostCount != value.HostCount {
			return value, ErrServiceDependentManifestEvidence
		}
		value.Seal = &v
	}
	return value, nil
}
func (s *Store) GetServiceDependentManifestTx(ctx context.Context, tx pgx.Tx, tenantID, id string, lock bool) (ServiceDependentManifest, error) {
	query := "SELECT " + dependentManifestColumns + " FROM service_account_rotation_manifests WHERE tenant_id=$1 AND id=$2"
	if lock {
		query += " FOR UPDATE"
	}
	return scanServiceDependentManifest(tx.QueryRow(ctx, query, tenantID, id))
}
func (s *Store) GetServiceDependentManifest(ctx context.Context, tenantID, id string) (ServiceDependentManifest, error) {
	var value ServiceDependentManifest
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		value, err = s.GetServiceDependentManifestTx(ctx, tx, tenantID, id, false)
		return err
	})
	return value, err
}
func (s *Store) ApplyServiceDependentManifestOpenedTx(ctx context.Context, tx pgx.Tx, tenantID string, header servicedependents.RotationManifestHeader, actor string, at time.Time) error {
	digest, err := header.Digest()
	if err != nil {
		return err
	}
	if actor == "" || len(actor) > 512 || at.IsZero() || !at.Equal(header.CreatedAt) {
		return errors.New("store: exact review author and opening time required")
	}
	raw, err := json.Marshal(header)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO service_account_rotation_manifests(tenant_id,id,header,header_digest,actor,created_at,expires_at) VALUES($1,$2,$3::jsonb,$4,$5,$6,$7) ON CONFLICT(tenant_id,id) DO NOTHING`, tenantID, header.ID, raw, digest, actor, at, header.ExpiresAt)
	if err != nil {
		return err
	}
	existing, err := s.GetServiceDependentManifestTx(ctx, tx, tenantID, header.ID, false)
	if err != nil {
		return err
	}
	if existing.HeaderDigest != digest || existing.Actor != actor {
		return ErrIdempotencyConflict
	}
	return nil
}
func (s *Store) getServiceDependentManifestPageTx(ctx context.Context, tx pgx.Tx, tenantID string, header servicedependents.RotationManifestHeader, number int64) (servicedependents.RotationManifestPage, error) {
	var raw []byte
	var digest string
	err := tx.QueryRow(ctx, `SELECT page,digest FROM service_account_rotation_manifest_pages WHERE tenant_id=$1 AND manifest_id=$2 AND page_number=$3`, tenantID, header.ID, number).Scan(&raw, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return servicedependents.RotationManifestPage{}, ErrServiceDependentManifestNotFound
	}
	if err != nil {
		return servicedependents.RotationManifestPage{}, err
	}
	page, err := servicedependents.DecodeRotationManifestPage(header, raw)
	if err != nil || page.Number != number || page.Digest != digest {
		return page, ErrServiceDependentManifestEvidence
	}
	return page, nil
}
func (s *Store) GetServiceDependentManifestPage(ctx context.Context, tenantID, id string, number int64) (servicedependents.RotationManifestPage, error) {
	var page servicedependents.RotationManifestPage
	if number < 0 {
		return page, errors.New("store: nonnegative manifest page number required")
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		header, err := s.GetServiceDependentManifestTx(ctx, tx, tenantID, id, false)
		if err != nil {
			return err
		}
		page, err = s.getServiceDependentManifestPageTx(ctx, tx, tenantID, header.Header, number)
		return err
	})
	return page, err
}
func (s *Store) ApplyServiceDependentManifestPageTx(ctx context.Context, tx pgx.Tx, tenantID string, page servicedependents.RotationManifestPage, actor string, at time.Time) error {
	state, err := s.GetServiceDependentManifestTx(ctx, tx, tenantID, page.ID, true)
	if err != nil {
		return err
	}
	if page.Validate(state.Header) != nil || actor != state.Actor || at.Before(state.Header.CreatedAt) || !at.Before(state.Header.ExpiresAt) {
		return errors.New("store: manifest page has another author, native authority or review window")
	}
	existing, err := s.getServiceDependentManifestPageTx(ctx, tx, tenantID, state.Header, page.Number)
	if err == nil {
		if existing.Digest != page.Digest {
			return ErrIdempotencyConflict
		}
		return nil
	}
	if !errors.Is(err, ErrServiceDependentManifestNotFound) {
		return err
	}
	if state.Seal != nil || page.Number != state.PageCount || math.MaxInt64-state.EntryCount < int64(len(page.Entries)) || math.MaxInt64-state.HostCount < int64(len(page.Hosts)) {
		return ErrIdempotencyConflict
	}
	var previous *servicedependents.RotationManifestPage
	if state.PageCount > 0 {
		value, err := s.getServiceDependentManifestPageTx(ctx, tx, tenantID, state.Header, state.PageCount-1)
		if err != nil {
			return err
		}
		previous = &value
	}
	if err := servicedependents.ValidateRotationManifestLink(state.Header, page, previous); err != nil {
		return err
	}
	if err := s.validateManifestNativePageTx(ctx, tx, tenantID, page, at); err != nil {
		return err
	}
	newHosts := int64(0)
	for _, host := range page.Hosts {
		hostRaw, err := json.Marshal(host)
		if err != nil {
			return err
		}
		hostDigest := crypto.SHA256Hex(hostRaw)
		tag, err := tx.Exec(ctx, `INSERT INTO service_account_rotation_manifest_hosts(tenant_id,manifest_id,agent_id,host,digest) VALUES($1,$2,$3,$4::jsonb,$5) ON CONFLICT(tenant_id,manifest_id,agent_id) DO NOTHING`, tenantID, page.ID, host.Binding.AgentID, hostRaw, hostDigest)
		if err != nil {
			return err
		}
		newHosts += tag.RowsAffected()
		var firstRaw []byte
		var firstDigest string
		if err := tx.QueryRow(ctx, `SELECT host,digest FROM service_account_rotation_manifest_hosts WHERE tenant_id=$1 AND manifest_id=$2 AND agent_id=$3`, tenantID, page.ID, host.Binding.AgentID).Scan(&firstRaw, &firstDigest); err != nil {
			return err
		}
		var first servicedependents.RotationManifestHost
		if json.Unmarshal(firstRaw, &first) != nil {
			return ErrServiceDependentManifestEvidence
		}
		canonicalFirst, err := json.Marshal(first)
		if err != nil {
			return err
		}
		if firstDigest != hostDigest || crypto.SHA256Hex(canonicalFirst) != hostDigest {
			return ErrIdempotencyConflict
		}
	}
	for index, entry := range page.Entries {
		raw, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		refDigest := servicedependents.RotationManifestReferenceDigest(entry.Ref)
		tag, err := tx.Exec(ctx, `INSERT INTO service_account_rotation_manifest_entries(tenant_id,manifest_id,ordinal,page_number,agent_id,ref_digest,entry) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb) ON CONFLICT DO NOTHING`, tenantID, page.ID, state.EntryCount+int64(index), page.Number, entry.Ref.AgentID, refDigest, raw)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrIdempotencyConflict
		}
	}
	raw, err := json.Marshal(page)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO service_account_rotation_manifest_pages(tenant_id,manifest_id,page_number,page,digest) VALUES($1,$2,$3,$4::jsonb,$5)`, tenantID, page.ID, page.Number, raw, page.Digest)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE service_account_rotation_manifests SET page_count=page_count+1,entry_count=entry_count+$3,host_count=host_count+$4 WHERE tenant_id=$1 AND id=$2`, tenantID, page.ID, len(page.Entries), newHosts)
	return err
}

// Read one bounded native scan at a time, even when a page interleaves hosts.
// The API additionally verifies these references against immutable signed sources.
func (s *Store) validateManifestNativePageTx(ctx context.Context, tx pgx.Tx, tenantID string, page servicedependents.RotationManifestPage, at time.Time) error {
	for _, host := range page.Hosts {
		scan, err := scanServiceDependentScan(tx.QueryRow(ctx, "SELECT "+serviceDependentScanColumns+" FROM service_account_host_scans WHERE tenant_id=$1 AND id=$2", tenantID, host.InventoryRunID))
		if err != nil {
			return err
		}
		refused := errors.New("store: manifest page differs from its exact retained signed native scan")
		if scan.Status != "complete" || scan.Report == nil || scan.ObservedEventID == "" || scan.Intent.Binding != host.Binding || scan.ReportDigest != host.InventoryDigest || scan.ReceiptStatement == "" || scan.ReceiptSignature == "" || scan.SignerFingerprint == "" || !scan.Report.ObservedAt.Equal(host.ObservedAt) || !at.Before(host.ObservedAt.Add(servicedependents.RotationInventoryMaxAge)) || scan.Report.Validate(scan.Intent) != nil {
			return refused
		}
		raw, err := json.Marshal(scan.Report)
		if err != nil {
			return err
		}
		if crypto.SHA256Hex(raw) != host.InventoryDigest {
			return refused
		}
		for _, candidate := range page.Entries {
			if candidate.Ref.AgentID == host.Binding.AgentID && !manifestReportHasRef(*scan.Report, candidate.Ref) {
				return refused
			}
		}
	}
	return nil
}
func manifestReportHasRef(report servicedependents.InventoryReport, ref servicedependents.DependentRef) bool {
	switch ref.Family {
	case "services":
		for _, target := range report.Services {
			if target.Name == ref.Name {
				return true
			}
		}
	case "tasks":
		for _, target := range report.Tasks {
			if target.Path == ref.Name {
				return true
			}
		}
	case "iis":
		for _, target := range report.Pools {
			if target.Name == ref.Name {
				return true
			}
		}
	}
	return false
}

// ValidateServiceDependentManifestCompletenessTx walks one host at a time. It
// derives the seal rather than accepting caller counts. Canonical page/source
// verification is an additional API/worker gate; these are projection checks.
func (s *Store) ValidateServiceDependentManifestCompletenessTx(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time, current bool) (servicedependents.RotationManifestSeal, error) {
	var none servicedependents.RotationManifestSeal
	state, err := s.GetServiceDependentManifestTx(ctx, tx, tenantID, id, false)
	if err != nil {
		return none, err
	}
	if state.PageCount < 1 || state.EntryCount < 1 || state.HostCount < 1 || at.Before(state.Header.CreatedAt) {
		return none, errors.New("store: complete nonempty native review required before sealing")
	}
	var pages, firstPage, lastPage int64
	if err := tx.QueryRow(ctx, `SELECT count(*),coalesce(min(page_number),0),coalesce(max(page_number),-1) FROM service_account_rotation_manifest_pages WHERE tenant_id=$1 AND manifest_id=$2`, tenantID, id).Scan(&pages, &firstPage, &lastPage); err != nil {
		return none, err
	}
	if pages != state.PageCount || firstPage != 0 || lastPage != pages-1 {
		return none, ErrServiceDependentManifestEvidence
	}
	var entries, firstEntry, lastEntry int64
	if err := tx.QueryRow(ctx, `SELECT count(*),coalesce(min(ordinal),0),coalesce(max(ordinal),-1) FROM service_account_rotation_manifest_entries WHERE tenant_id=$1 AND manifest_id=$2`, tenantID, id).Scan(&entries, &firstEntry, &lastEntry); err != nil {
		return none, err
	}
	if entries != state.EntryCount || firstEntry != 0 || lastEntry != entries-1 {
		return none, ErrServiceDependentManifestEvidence
	}
	tail, err := s.getServiceDependentManifestPageTx(ctx, tx, tenantID, state.Header, pages-1)
	if err != nil {
		return none, err
	}
	expires := state.Header.ExpiresAt
	var after any
	hosts := int64(0)
	for {
		var raw []byte
		var agentID, digest string
		err := tx.QueryRow(ctx, `SELECT agent_id::text,host,digest FROM service_account_rotation_manifest_hosts WHERE tenant_id=$1 AND manifest_id=$2 AND ($3::uuid IS NULL OR agent_id>$3::uuid) ORDER BY agent_id LIMIT 1`, tenantID, id, after).Scan(&agentID, &raw, &digest)
		if errors.Is(err, pgx.ErrNoRows) {
			break
		}
		if err != nil {
			return none, err
		}
		var host servicedependents.RotationManifestHost
		if json.Unmarshal(raw, &host) != nil || host.Validate(state.Header) != nil || host.Binding.AgentID != agentID {
			return none, ErrServiceDependentManifestEvidence
		}
		encoded, err := json.Marshal(host)
		if err != nil {
			return none, err
		}
		if crypto.SHA256Hex(encoded) != digest {
			return none, ErrServiceDependentManifestEvidence
		}
		scan, err := scanServiceDependentScan(tx.QueryRow(ctx, "SELECT "+serviceDependentScanColumns+" FROM service_account_host_scans WHERE tenant_id=$1 AND id=$2", tenantID, host.InventoryRunID))
		if err != nil {
			return none, err
		}
		refused := errors.New("store: complete native inventory and every selected host must remain in the manifest")
		if scan.Status != "complete" || scan.Report == nil || scan.ObservedEventID == "" || scan.Intent.Binding != host.Binding || scan.ReportDigest != host.InventoryDigest || !scan.Report.ObservedAt.Equal(host.ObservedAt) || scan.Report.Validate(scan.Intent) != nil || !scan.Report.Complete() {
			return none, refused
		}
		scanRaw, err := json.Marshal(scan.Report)
		if err != nil {
			return none, err
		}
		if crypto.SHA256Hex(scanRaw) != host.InventoryDigest {
			return none, refused
		}
		var nativeEntries int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM service_account_rotation_manifest_entries WHERE tenant_id=$1 AND manifest_id=$2 AND agent_id=$3`, tenantID, id, agentID).Scan(&nativeEntries); err != nil {
			return none, err
		}
		if nativeEntries != int64(len(scan.Report.Services)+len(scan.Report.Tasks)+len(scan.Report.Pools)) {
			return none, refused
		}
		if err := validateManifestServiceOrderTx(ctx, tx, tenantID, id, agentID, scan.Report.Services); err != nil {
			return none, err
		}
		if current {
			selected, err := getServiceDependentHostTx(ctx, tx, tenantID, state.Header.Account.AccountID, agentID)
			if err != nil {
				return none, err
			}
			if selected.Binding != host.Binding {
				return none, refused
			}
			var latest string
			if err := tx.QueryRow(ctx, `SELECT id::text FROM service_account_host_scans WHERE tenant_id=$1 AND account_id=$2 AND agent_id=$3 ORDER BY queued_at DESC,id DESC LIMIT 1`, tenantID, state.Header.Account.AccountID, agentID).Scan(&latest); err != nil {
				return none, err
			}
			if latest != host.InventoryRunID {
				return none, refused
			}
		}
		deadline := host.ObservedAt.Add(servicedependents.RotationInventoryMaxAge)
		if deadline.Before(expires) {
			expires = deadline
		}
		hosts++
		after = agentID
	}
	if hosts != state.HostCount || !at.Before(expires) {
		return none, errors.New("store: complete native manifest is missing hosts or its review expired")
	}
	if current {
		var selected int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM service_account_hosts WHERE tenant_id=$1 AND account_id=$2 AND enabled`, tenantID, state.Header.Account.AccountID).Scan(&selected); err != nil {
			return none, err
		}
		if selected != hosts {
			return none, errors.New("store: enabled host set changed while reviewing the complete account")
		}
	}
	return servicedependents.NewRotationManifestSeal(state.Header, tail, entries, hosts, expires)
}
func (s *Store) ApplyServiceDependentManifestSealedTx(ctx context.Context, tx pgx.Tx, tenantID string, seal servicedependents.RotationManifestSeal, actor string, at time.Time) error {
	state, err := s.GetServiceDependentManifestTx(ctx, tx, tenantID, seal.ID, true)
	if err != nil {
		return err
	}
	if seal.Validate(state.Header) != nil || actor != state.Actor || at.Before(state.Header.CreatedAt) || !at.Before(seal.ExpiresAt) {
		return errors.New("store: exact complete manifest, author and original review window required")
	}
	if state.Seal != nil {
		if state.Seal.Digest != seal.Digest {
			return ErrIdempotencyConflict
		}
		return nil
	}
	expected, err := s.ValidateServiceDependentManifestCompletenessTx(ctx, tx, tenantID, seal.ID, at, false)
	if err != nil {
		return err
	}
	if expected.Digest != seal.Digest {
		return ErrIdempotencyConflict
	}
	raw, err := json.Marshal(seal)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE service_account_rotation_manifests SET seal=$3::jsonb WHERE tenant_id=$1 AND id=$2`, tenantID, seal.ID, raw)
	return err
}

// VerifyServiceDependentManifestPageCacheTx binds normalized indices back to
// their canonical page. Indices may speed selection, never replace its authority.
func (s *Store) VerifyServiceDependentManifestPageCacheTx(ctx context.Context, tx pgx.Tx, tenantID string, page servicedependents.RotationManifestPage, entryOffset int64) error {
	for _, host := range page.Hosts {
		var raw []byte
		var digest string
		if err := tx.QueryRow(ctx, `SELECT host,digest FROM service_account_rotation_manifest_hosts WHERE tenant_id=$1 AND manifest_id=$2 AND agent_id=$3`, tenantID, page.ID, host.Binding.AgentID).Scan(&raw, &digest); err != nil {
			return err
		}
		var retained servicedependents.RotationManifestHost
		if json.Unmarshal(raw, &retained) != nil {
			return ErrServiceDependentManifestEvidence
		}
		wanted, err := json.Marshal(host)
		if err != nil {
			return err
		}
		actual, err := json.Marshal(retained)
		if err != nil {
			return err
		}
		if crypto.SHA256Hex(wanted) != digest || crypto.SHA256Hex(actual) != digest {
			return ErrServiceDependentManifestEvidence
		}
	}
	if entryOffset < 0 || math.MaxInt64-entryOffset < int64(len(page.Entries)) {
		return ErrServiceDependentManifestEvidence
	}
	rows, err := tx.Query(ctx, `SELECT ordinal,page_number,agent_id::text,ref_digest,entry FROM service_account_rotation_manifest_entries WHERE tenant_id=$1 AND manifest_id=$2 AND ordinal >= $3 AND ordinal < $4 ORDER BY ordinal`, tenantID, page.ID, entryOffset, entryOffset+int64(len(page.Entries)))
	if err != nil {
		return err
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		var ordinal, number int64
		var agentID, refDigest string
		var raw []byte
		if err := rows.Scan(&ordinal, &number, &agentID, &refDigest, &raw); err != nil {
			return err
		}
		if index >= len(page.Entries) {
			return ErrServiceDependentManifestEvidence
		}
		expected := page.Entries[index]
		var retained servicedependents.RotationManifestEntry
		if json.Unmarshal(raw, &retained) != nil {
			return ErrServiceDependentManifestEvidence
		}
		wanted, err := json.Marshal(expected)
		if err != nil {
			return err
		}
		actual, err := json.Marshal(retained)
		if err != nil {
			return err
		}
		digest := servicedependents.RotationManifestReferenceDigest(expected.Ref)
		if ordinal != entryOffset+int64(index) || number != page.Number || agentID != expected.Ref.AgentID || refDigest != digest || crypto.SHA256Hex(wanted) != crypto.SHA256Hex(actual) {
			return ErrServiceDependentManifestEvidence
		}
		index++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if index != len(page.Entries) {
		return ErrServiceDependentManifestEvidence
	}
	return nil
}

func validateManifestServiceOrderTx(ctx context.Context, tx pgx.Tx, tenantID, id, agentID string, services []windependents.Service) error {
	positions := make(map[string]int64, len(services))
	for _, service := range services {
		ref := servicedependents.DependentRef{AgentID: agentID, Family: "services", Name: service.Name}
		var ordinal int64
		if err := tx.QueryRow(ctx, `SELECT ordinal FROM service_account_rotation_manifest_entries WHERE tenant_id=$1 AND manifest_id=$2 AND ref_digest=$3`, tenantID, id, servicedependents.RotationManifestReferenceDigest(ref)).Scan(&ordinal); err != nil {
			return err
		}
		name := strings.ToLower(service.Name)
		if _, found := positions[name]; found {
			return ErrServiceDependentManifestEvidence
		}
		positions[name] = ordinal
	}
	for _, service := range services {
		own := positions[strings.ToLower(service.Name)]
		for _, dependency := range service.Dependencies {
			if position, selected := positions[strings.ToLower(dependency)]; selected && position >= own {
				return errors.New("store: reviewed service order violates native dependency graph across pages")
			}
		}
	}
	return nil
}
