// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

func TestServedPagedDependentReviewPreservesCompleteScopeAndPrivacyA267(t *testing.T) {
	servedDependentRotationScenario(t, nil, false, dependentRotationOptions{ManifestReviewOnly: true})
}
func servedDependentManifestReview(t *testing.T, h *roleHarness, token, root string, binding servicedependents.HostBinding, inventory servicedependents.InventoryReport, directory *dependentDirectoryBoundary, projector *projections.Projector, badOrder bool) {
	t.Helper()
	ctx := t.Context()
	code, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/reviews", token, "owned-open-paged-review", map[string]any{"secret_name": "app/dependent"})
	var review store.ServiceDependentManifest
	if code != http.StatusCreated || json.Unmarshal(raw, &review) != nil || review.Header.ID == "" || review.HeaderDigest == "" || review.Seal != nil {
		t.Fatalf("bounded complete-account review unavailable: %d %s", code, raw)
	}
	path := "/api/v1/access/discovery/dependent-reviews/" + review.Header.ID
	scan, err := h.store.GetServiceDependentScan(ctx, h.tenant, inventory.RunID)
	if err != nil {
		t.Fatal(err)
	}
	host := servicedependents.RotationManifestHost{Binding: binding, InventoryRunID: inventory.RunID, InventoryDigest: scan.ReportDigest, ObservedAt: inventory.ObservedAt}
	var entries []servicedependents.RotationManifestEntry
	add := func(family, name string) {
		entries = append(entries, servicedependents.RotationManifestEntry{Host: host, Ref: servicedependents.DependentRef{AgentID: binding.AgentID, Family: family, Name: name}, ProbeID: "owned-functional-work"})
	}
	for _, target := range inventory.Services {
		add("services", target.Name)
	}
	for _, target := range inventory.Tasks {
		add("tasks", target.Path)
	}
	for _, target := range inventory.Pools {
		add("iis", target.Name)
	}
	if badOrder {
		code, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/reviews", token, "owned-bad-service-order-review", map[string]any{"secret_name": "app/dependent"})
		var bad store.ServiceDependentManifest
		if code != http.StatusCreated || json.Unmarshal(raw, &bad) != nil {
			t.Fatal("bad-order fixture failed to open")
		}
		badPath := "/api/v1/access/discovery/dependent-reviews/" + bad.Header.ID
		reversed := append([]servicedependents.RotationManifestEntry(nil), entries...)
		reversed[0], reversed[1] = reversed[1], reversed[0]
		previous := bad.HeaderDigest
		for i := 0; i < 2; i++ {
			part := reversed[:1]
			if i == 1 {
				part = reversed[1:]
			}
			code, raw = secretsReqKey(t, h.servedHarness, http.MethodPut, fmt.Sprintf("%s/pages/%d", badPath, i), token, fmt.Sprintf("owned-bad-order-page-%d", i), map[string]any{"header_digest": bad.HeaderDigest, "previous_digest": previous, "hosts": []servicedependents.RotationManifestHost{host}, "entries": part})
			var page servicedependents.RotationManifestPage
			if code != http.StatusCreated || json.Unmarshal(raw, &page) != nil {
				t.Fatal("bad-order page fixture failed")
			}
			previous = page.Digest
		}
		if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, badPath+"/seal", token, "refuse-native-service-order-across-pages", map[string]any{"header_digest": bad.HeaderDigest, "tail_digest": previous}); code != http.StatusConflict {
			t.Fatalf("sealed service restart order violates native dependency graph: %d", code)
		}
	}
	previous := review.HeaderDigest
	for number := 0; number < 2; number++ {
		selected := entries[:2]
		if number == 1 {
			selected = entries[2:]
		}
		input := map[string]any{"header_digest": review.HeaderDigest, "previous_digest": previous, "hosts": []servicedependents.RotationManifestHost{host}, "entries": selected}
		if number == 0 {
			interruptManifestProjection(t, h, token, http.MethodPut, path+"/pages/0", review.Header.ID, servicedependents.RotationManifestPageSourceID(h.tenant, review.Header.ID, 0), input)
			changed := append([]servicedependents.RotationManifestEntry(nil), selected...)
			changed[0].ProbeID = "owned-different-functional-work"
			invalid := map[string]any{"header_digest": review.HeaderDigest, "previous_digest": previous, "hosts": []servicedependents.RotationManifestHost{host}, "entries": changed}
			if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPut, path+"/pages/0", token, "refuse-new-effect-after-manifest-append", invalid); code != http.StatusConflict {
				t.Fatalf("first native page changed after projection loss: %d", code)
			}
		}
		code, raw = secretsReqKey(t, h.servedHarness, http.MethodPut, fmt.Sprintf("%s/pages/%d", path, number), token, fmt.Sprintf("owned-review-page-%d", number), input)
		var page servicedependents.RotationManifestPage
		if code != http.StatusCreated || json.Unmarshal(raw, &page) != nil || page.Number != int64(number) || page.Validate(review.Header) != nil {
			t.Fatalf("exact ordered native page unavailable: %d %s", code, raw)
		}
		code, retry := secretsReqKey(t, h.servedHarness, http.MethodPut, fmt.Sprintf("%s/pages/%d", path, number), token, fmt.Sprintf("owned-review-page-%d", number), input)
		var same servicedependents.RotationManifestPage
		if code != http.StatusCreated || json.Unmarshal(retry, &same) != nil || same.Digest != page.Digest {
			t.Fatal("page response-loss retry changed exact review")
		}
		previous = page.Digest
		if number == 0 {
			if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, path+"/seal", token, "refuse-omitted-native-ref", map[string]any{"header_digest": review.HeaderDigest, "tail_digest": previous}); code != http.StatusConflict {
				t.Fatalf("partial native manifest was sealed: %d", code)
			}
		}
	}
	interruptManifestProjection(t, h, token, http.MethodPost, path+"/seal", review.Header.ID, servicedependents.RotationManifestSealSourceID(h.tenant, review.Header.ID), map[string]any{"header_digest": review.HeaderDigest, "tail_digest": previous})
	code, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, path+"/seal", token, "owned-seal-paged-review", map[string]any{"header_digest": review.HeaderDigest, "tail_digest": previous})
	var sealed store.ServiceDependentManifest
	if code != http.StatusCreated || json.Unmarshal(raw, &sealed) != nil || sealed.Seal == nil || sealed.Seal.EntryCount != int64(len(entries)) || sealed.Seal.HostCount != 1 || sealed.Seal.PageCount != 2 {
		t.Fatalf("whole-account native seal unavailable: %d %s", code, raw)
	}
	if directory.applied != 0 || directory.restored != 0 {
		t.Fatal("collecting or sealing a review changed the native AD credential")
	}
	code, raw = secretsReq(t, h.servedHarness, http.MethodGet, path+"/pages/1", token, nil)
	var read servicedependents.RotationManifestPage
	if code != http.StatusOK || json.Unmarshal(raw, &read) != nil || read.Digest != previous {
		t.Fatal("paged review read lost exact final native effect")
	}
	other := uuid.NewString()
	registerServedTenantID(t, h.servedHarness, other, "Owned manifest isolation")
	foreign := seedScopedToken(t, h.store, other, "access:read", "secrets:read")
	if code, _ := secretsReq(t, h.servedHarness, http.MethodGet, path, foreign, nil); code != http.StatusNotFound {
		t.Fatalf("foreign tenant read native manifest: %d", code)
	}
	faultManifestCache(t, h, token, path, review.Header.ID, review.Header, entries)
	if err := projector.ProjectCatchUp(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, h.log); err != nil {
		t.Fatal("native review could not rebuild", err)
	}
	const subject = "owned-rotation-operator"
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "owned-manifest-privacy-operator", "privacy:read", "privacy:write", "access:read", "secrets:read")
	code, _ = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/privacy/subject-erasures", admin, "erase-owned-manifest-author", map[string]string{"subject": subject, "reason": "owned complete manifest privacy proof"})
	if code != http.StatusCreated {
		t.Fatalf("manifest author erasure failed: %d", code)
	}
	assertEventLogOmitsRawSubject(t, ctx, h.log, h.tenant, subject)
	if err := projector.Rebuild(ctx, h.log); err != nil {
		t.Fatal("erased native review could not rebuild", err)
	}
	code, raw = secretsReq(t, h.servedHarness, http.MethodGet, path, admin, nil)
	var erased store.ServiceDependentManifest
	if code != http.StatusOK || json.Unmarshal(raw, &erased) != nil || erased.Actor != privacy.Placeholder(privacy.SubjectRef(h.tenant, subject)) || erased.Seal == nil || erased.Seal.Digest != sealed.Seal.Digest {
		t.Fatal("privacy changed native effect or revived author")
	}
}

func TestServedPagedDependentReviewChecksServiceOrderAcrossPagesA267(t *testing.T) {
	servedDependentRotationScenario(t, nil, false, dependentRotationOptions{ManifestReviewOnly: true, ManifestDependencyOrder: true})
}

// Hold only this owned review row. The write appends its source before waiting
// at projection, so cancellation tests the real JetStream/PostgreSQL gap.
func interruptManifestProjection(t *testing.T, h *roleHarness, token, method, path, id, sourceID string, input any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	held, release, holderDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		holderDone <- h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			var digest string
			if err := tx.QueryRow(ctx, `SELECT header_digest FROM service_account_rotation_manifests WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, h.tenant, id).Scan(&digest); err != nil {
				return err
			}
			close(held)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-held:
	case err := <-holderDone:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	requestCtx, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(requestCtx, method, h.ts.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "owned-interrupted-manifest-"+method)
	returned := make(chan int, 1)
	go func() {
		response, err := h.ts.Client().Do(req)
		code := 0
		if err == nil {
			code = response.StatusCode
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			_ = response.Body.Close()
		}
		returned <- code
	}()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		_, found, err := h.log.EventByID(ctx, sourceID)
		if err != nil {
			t.Fatal(err)
		}
		if found {
			break
		}
		select {
		case code := <-returned:
			t.Fatalf("manifest returned before held projection: %d", code)
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	cancelRequest()
	select {
	case code := <-returned:
		if code == http.StatusCreated {
			t.Fatal("unprojected manifest write reported created")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if code, _ := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/dependent-reviews/"+id, token, nil); code != http.StatusConflict {
		t.Fatalf("pending canonical manifest source was hidden by old SQL coverage: %d", code)
	}
	close(release)
	select {
	case err := <-holderDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Client cancellation can precede the server's deferred catalogue release.
	for {
		err := h.store.WithPAMCatalogLock(ctx, h.tenant, func() error { return nil })
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrDatastoreBusy) {
			t.Fatal(err)
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func faultManifestCache(t *testing.T, h *roleHarness, token, path, id string, header servicedependents.RotationManifestHeader, entries []servicedependents.RotationManifestEntry) {
	t.Helper()
	ctx := t.Context()
	execute := func(query string, args ...any) {
		t.Helper()
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, query, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	refused := func() {
		t.Helper()
		if code, _ := secretsReq(t, h.servedHarness, http.MethodGet, path, token, nil); code != http.StatusConflict {
			t.Fatalf("changed SQL native scope retained source authority: %d", code)
		}
	}
	originalHeader, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	changedHeader := header
	changedHeader.ExpectedVersion++
	changedRaw, err := json.Marshal(changedHeader)
	if err != nil {
		t.Fatal(err)
	}
	execute(`UPDATE service_account_rotation_manifests SET header=$3::jsonb WHERE tenant_id=$1 AND id=$2`, h.tenant, id, changedRaw)
	refused()
	execute(`UPDATE service_account_rotation_manifests SET header=$3::jsonb WHERE tenant_id=$1 AND id=$2`, h.tenant, id, originalHeader)
	execute(`UPDATE service_account_rotation_manifests SET host_count=host_count+1 WHERE tenant_id=$1 AND id=$2`, h.tenant, id)
	refused()
	execute(`UPDATE service_account_rotation_manifests SET host_count=host_count-1 WHERE tenant_id=$1 AND id=$2`, h.tenant, id)
	originalEntry, err := json.Marshal(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	changedEntry := entries[0]
	changedEntry.ProbeID = "owned-forged-cache-probe"
	changedRaw, err = json.Marshal(changedEntry)
	if err != nil {
		t.Fatal(err)
	}
	execute(`UPDATE service_account_rotation_manifest_entries SET entry=$3::jsonb WHERE tenant_id=$1 AND manifest_id=$2 AND ordinal=0`, h.tenant, id, changedRaw)
	refused()
	execute(`UPDATE service_account_rotation_manifest_entries SET entry=$3::jsonb WHERE tenant_id=$1 AND manifest_id=$2 AND ordinal=0`, h.tenant, id, originalEntry)
	page, err := h.store.GetServiceDependentManifestPage(ctx, h.tenant, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	originalPage, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	replaced := append([]servicedependents.RotationManifestEntry(nil), page.Entries...)
	replaced[0].ProbeID = "owned-forged-page-probe"
	changedPage, err := servicedependents.NewRotationManifestPageWithHosts(header, 0, page.PreviousDigest, page.Hosts, replaced)
	if err != nil {
		t.Fatal(err)
	}
	changedRaw, err = json.Marshal(changedPage)
	if err != nil {
		t.Fatal(err)
	}
	execute(`UPDATE service_account_rotation_manifest_pages SET page=$3::jsonb,digest=$4 WHERE tenant_id=$1 AND manifest_id=$2 AND page_number=0`, h.tenant, id, changedRaw, changedPage.Digest)
	refused()
	execute(`UPDATE service_account_rotation_manifest_pages SET page=$3::jsonb,digest=$4 WHERE tenant_id=$1 AND manifest_id=$2 AND page_number=0`, h.tenant, id, originalPage, page.Digest)
	if code, _ := secretsReq(t, h.servedHarness, http.MethodGet, path, token, nil); code != http.StatusOK {
		t.Fatal("restored own cache did not match original native sources")
	}
	reader := seedScopedToken(t, h.store, h.tenant, "access:read", "secrets:read")
	if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPut, path+"/pages/0", reader, "refuse-readonly-manifest-write", map[string]any{}); code != http.StatusForbidden {
		t.Fatalf("readonly operator wrote native manifest: %d", code)
	}
	if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPut, path+"/pages/2", token, "refuse-oversized-native-page", map[string]any{"unknown": strings.Repeat("x", servicedependents.MaxRotationManifestPageBytes)}); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("manifest wire bound was not enforced: %d", code)
	}
}
