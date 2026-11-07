// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"encoding/json"
	"errors"
	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

func TestManifestProjectionKeepsWholeAccountAtomicAndTenantBoundA267(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	intent := seedDependentRotation(t, s, tenantA)
	header := servicedependents.RotationManifestHeader{Version: 1, ID: googleuuid.NewString(), Account: intent.Plan.Account, SecretName: intent.Plan.SecretName, ExpectedVersion: intent.ExpectedVersion, ProviderBinding: intent.ProviderBinding, CreatedAt: intent.Plan.CreatedAt, ExpiresAt: intent.Plan.CreatedAt.Add(servicedependents.RotationInventoryMaxAge)}
	const actor = "owned-manifest-author"
	initialScan, err := s.GetServiceDependentScan(ctx, tenantA, intent.Plan.Hosts[0].InventoryRunID)
	if err != nil || initialScan.Report == nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyServiceDependentScanObservedTx(ctx, tx, tenantA, *initialScan.ReceiptJobID, *initialScan.Attempt, *initialScan.Report, initialScan.ReportDigest, initialScan.ReceiptStatement, initialScan.ReceiptSignature, initialScan.SignerFingerprint, header.CreatedAt, googleuuid.NewString())
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyServiceDependentManifestOpenedTx(ctx, tx, tenantA, header, actor, header.CreatedAt)
	}); err != nil {
		t.Fatal(err)
	}
	host := intent.Plan.Hosts[0]
	entry := servicedependents.RotationManifestEntry{Host: servicedependents.RotationManifestHost{Binding: host.Binding, InventoryRunID: host.InventoryRunID, InventoryDigest: host.InventoryDigest, ObservedAt: host.ObservedAt}, Ref: intent.Plan.Order[0], ProbeID: intent.Probes[0].ProbeID}
	digest, err := header.Digest()
	if err != nil {
		t.Fatal(err)
	}
	first, err := servicedependents.NewRotationManifestPage(header, 0, digest, []servicedependents.RotationManifestEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	interrupted := errors.New("owned page transaction interruption")
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.ApplyServiceDependentManifestPageTx(ctx, tx, tenantA, first, actor, header.CreatedAt); err != nil {
			return err
		}
		return interrupted
	}); !errors.Is(err, interrupted) {
		t.Fatal(err)
	}
	if _, err := s.GetServiceDependentManifestPage(ctx, tenantA, header.ID, 0); !errors.Is(err, store.ErrServiceDependentManifestNotFound) {
		t.Fatal("interrupted page leaked into review", err)
	}
	apply := func(page servicedependents.RotationManifestPage, author string) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyServiceDependentManifestPageTx(ctx, tx, tenantA, page, author, header.CreatedAt)
		})
	}
	if err := apply(first, actor); err != nil {
		t.Fatal(err)
	}
	if err := apply(first, actor); err != nil {
		t.Fatal("exact page retry changed first command", err)
	}
	duplicate, err := servicedependents.NewRotationManifestPage(header, 1, first.Digest, []servicedependents.RotationManifestEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(duplicate, actor); err == nil {
		t.Fatal("reference repeated across separate pages")
	}
	// A second canonical host source supplies a distinct native reference.
	binding := entry.Host.Binding
	binding.AgentID = googleuuid.NewString()
	binding.Revision = 9
	scan, err := servicedependents.NewInventoryIntent(googleuuid.NewString(), binding)
	if err != nil {
		t.Fatal(err)
	}
	report := servicedependents.InventoryReport{RunID: scan.RunID, BindingDigest: scan.BindingDigest, ObservedAt: header.CreatedAt, Coverage: []servicedependents.FamilyCoverage{{Family: "services", Status: "complete"}, {Family: "tasks", Status: "complete"}, {Family: "iis", Status: "complete"}}, Services: []windependents.Service{{Name: entry.Ref.Name, AccountSID: header.Account.SID, ConfigSHA256: strings.Repeat("a", 64)}}}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.ApplyServiceDependentHostSavedTx(ctx, tx, tenantA, header.Account, binding.AgentID, true, actor, header.CreatedAt, 9); err != nil {
			return err
		}
		if err := s.ApplyServiceDependentScanQueuedTx(ctx, tx, tenantA, scan.RunID, scan, actor, header.CreatedAt); err != nil {
			return err
		}
		return s.ApplyServiceDependentScanObservedTx(ctx, tx, tenantA, 2, 1, report, crypto.SHA256Hex(raw), "owned signed native statement", "c2ln", strings.Repeat("b", 64), header.CreatedAt, googleuuid.NewString())
	}); err != nil {
		t.Fatal(err)
	}
	nextEntry := entry
	nextEntry.Host = servicedependents.RotationManifestHost{Binding: binding, InventoryRunID: scan.RunID, InventoryDigest: crypto.SHA256Hex(raw), ObservedAt: report.ObservedAt}
	nextEntry.Ref.AgentID = binding.AgentID
	next, err := servicedependents.NewRotationManifestPage(header, 1, first.Digest, []servicedependents.RotationManifestEntry{nextEntry})
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(next, "different-author"); err == nil {
		t.Fatal("another author appended to the retained review")
	}
	if err := apply(next, actor); err != nil {
		t.Fatal(err)
	}
	emptyBinding := binding
	emptyBinding.AgentID = googleuuid.NewString()
	emptyBinding.Revision = 10
	emptyScan, err := servicedependents.NewInventoryIntent(googleuuid.NewString(), emptyBinding)
	if err != nil {
		t.Fatal(err)
	}
	emptyReport := servicedependents.InventoryReport{RunID: emptyScan.RunID, BindingDigest: emptyScan.BindingDigest, ObservedAt: header.CreatedAt, Coverage: report.Coverage}
	emptyRaw, err := json.Marshal(emptyReport)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.ApplyServiceDependentHostSavedTx(ctx, tx, tenantA, header.Account, emptyBinding.AgentID, true, actor, header.CreatedAt, 10); err != nil {
			return err
		}
		if err := s.ApplyServiceDependentScanQueuedTx(ctx, tx, tenantA, emptyScan.RunID, emptyScan, actor, header.CreatedAt); err != nil {
			return err
		}
		return s.ApplyServiceDependentScanObservedTx(ctx, tx, tenantA, 3, 1, emptyReport, crypto.SHA256Hex(emptyRaw), "owned empty-host signed statement", "c2ln", strings.Repeat("c", 64), header.CreatedAt, googleuuid.NewString())
	}); err != nil {
		t.Fatal(err)
	}
	emptyHost := servicedependents.RotationManifestHost{Binding: emptyBinding, InventoryRunID: emptyScan.RunID, InventoryDigest: crypto.SHA256Hex(emptyRaw), ObservedAt: emptyReport.ObservedAt}
	hostOnly, err := servicedependents.NewRotationManifestPageWithHosts(header, 2, next.Digest, []servicedependents.RotationManifestHost{emptyHost}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(hostOnly, actor); err != nil {
		t.Fatal("complete selected empty host could not remain in review", err)
	}
	state, err := s.GetServiceDependentManifest(ctx, tenantA, header.ID)
	if err != nil || state.PageCount != 3 || state.EntryCount != 2 || state.HostCount != 3 || state.Seal != nil {
		t.Fatal("manifest bookkeeping lost atomic/global native scope", err)
	}
	if _, err := s.GetServiceDependentManifest(ctx, tenantB, header.ID); !errors.Is(err, store.ErrServiceDependentManifestNotFound) {
		t.Fatal("foreign tenant read review", err)
	}
	if _, err := s.GetServiceDependentManifestPage(ctx, tenantB, header.ID, 0); !errors.Is(err, store.ErrServiceDependentManifestNotFound) {
		t.Fatal("foreign tenant read native page", err)
	}
	var sealed servicedependents.RotationManifestSeal
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var err error
		sealed, err = s.ValidateServiceDependentManifestCompletenessTx(ctx, tx, tenantA, header.ID, header.CreatedAt, true)
		return err
	}); err != nil {
		t.Fatal("complete ordered native/empty-host scope did not seal", err)
	}
	if sealed.EntryCount != 2 || sealed.HostCount != 3 || sealed.PageCount != 3 {
		t.Fatal("seal lost complete selected native scope")
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyServiceDependentManifestSealedTx(ctx, tx, tenantA, sealed, actor, header.CreatedAt)
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyServiceDependentManifestSealedTx(ctx, tx, tenantA, sealed, actor, header.CreatedAt)
	}); err != nil {
		t.Fatal("same seal retry changed first command", err)
	}
	extra, err := servicedependents.NewRotationManifestPage(header, 3, hostOnly.Digest, []servicedependents.RotationManifestEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(extra, actor); err == nil {
		t.Fatal("sealed account allowed extra native effect")
	}
	var mutations int
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM secret_static_rotation_commands WHERE tenant_id=$1`, tenantA).Scan(&mutations)
	}); err != nil || mutations != 0 {
		t.Fatal("collecting review queued a directory reset", err)
	}
	exported, err := s.SelectPrivacySubjectExport(ctx, tenantA, actor)
	if err != nil || exported.Counts["service_account_rotation_manifests"] != 1 {
		t.Fatal("review author missing from subject export", err, exported.Counts)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE service_account_rotation_manifests SET header=jsonb_set(header,'{expected_version}','99') WHERE tenant_id=$1 AND id=$2`, tenantA, header.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetServiceDependentManifest(ctx, tenantA, header.ID); err == nil {
		t.Fatal("changed SQL header retained its original manifest digest")
	}
}
