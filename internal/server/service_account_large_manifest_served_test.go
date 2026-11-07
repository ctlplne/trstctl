// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

func TestServedNativeReviewExceedsInlineFrameWithBoundedPagesA267(t *testing.T) {
	servedDependentRotationScenario(t, nil, false, dependentRotationOptions{ManifestLargeReview: true})
}

// These are validator-valid signed metadata fixtures, not native Windows objects.
func largeManifestInventory(report servicedependents.InventoryReport, sid string) servicedependents.InventoryReport {
	report.Services = nil
	report.Tasks = nil
	report.Pools = nil
	for i := 0; i < 256; i++ {
		report.Services = append(report.Services, windependents.Service{Name: fmt.Sprintf("owned-service-%03d-%s", i, strings.Repeat("s", 220)), AccountSID: sid, ConfigSHA256: strings.Repeat("b", 64), WasRunning: true})
		path := fmt.Sprintf("\\owned\\%s\\%s\\%s\\task-%03d-%s", strings.Repeat("t", 200), strings.Repeat("u", 200), strings.Repeat("v", 200), i, strings.Repeat("w", 200))
		report.Tasks = append(report.Tasks, windependents.Task{Path: path, AccountSID: sid, ConfigSHA256: strings.Repeat("c", 64), Enabled: true, LogonType: 1, ActionCount: 1})
		report.Pools = append(report.Pools, windependents.Pool{Name: fmt.Sprintf("owned-pool-%03d-%s", i, strings.Repeat("p", 220)), AccountSID: sid, ConfigSHA256: strings.Repeat("d", 64), EncryptionProvider: "native", PasswordProtected: true, WasStarted: true})
	}
	return report
}
func servedLargeDependentManifestReview(t *testing.T, h *roleHarness, token, root string, binding servicedependents.HostBinding, inventory servicedependents.InventoryReport, directory *dependentDirectoryBoundary, projector *projections.Projector, execute bool) {
	t.Helper()
	ctx := t.Context()
	scan, err := h.store.GetServiceDependentScan(ctx, h.tenant, inventory.RunID)
	if err != nil {
		t.Fatal(err)
	}
	host := servicedependents.RotationManifestHost{Binding: binding, InventoryRunID: inventory.RunID, InventoryDigest: scan.ReportDigest, ObservedAt: inventory.ObservedAt}
	var entries []servicedependents.RotationManifestEntry
	var order []servicedependents.DependentRef
	var probes []servicedependents.ProbeBinding
	add := func(family, name string) {
		ref := servicedependents.DependentRef{AgentID: binding.AgentID, Family: family, Name: name}
		order = append(order, ref)
		probes = append(probes, servicedependents.ProbeBinding{Ref: ref, ProbeID: "owned-functional-work"})
		entries = append(entries, servicedependents.RotationManifestEntry{Host: host, Ref: ref, ProbeID: "owned-functional-work"})
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
	raw, err := json.Marshal(inventory)
	if err != nil || len(raw) > servicedependents.MaxInventoryReportBytes {
		t.Fatal("signed native report fixture exceeds original native frame", err)
	}
	// A second real host identity is enrolled into the same tenant and signs
	// its own exact targeted inventory. It cannot borrow the first host's claim.
	const secondName = "dependent-large-second-host"
	secondIdentity := enrollAgentWithRoles(t, h.servedHarness, secondName, h.serverName, []string{mtls.AgentRoleHost})
	creds, err := secondIdentity.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(h.channelAddr, creds)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	second := &roleHarness{servedHarness: h.servedHarness, client: transport.NewAgentClient(conn), agent: secondName, identity: secondIdentity, channelAddr: h.channelAddr, serverName: h.serverName}
	if _, err := second.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: secondName, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	secondID := agentRowID(h.tenant, secondName)
	if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPut, root+"/"+secondID, token, "owned-large-second-host", map[string]any{"enabled": true}); code != http.StatusOK {
		t.Fatalf("second native host not selected: %d", code)
	}
	if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/"+secondID+"/runs", token, "owned-large-second-inventory", nil); code != http.StatusAccepted {
		t.Fatalf("second native inventory not queued: %d", code)
	}
	claimed, err := second.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{servicedependents.InventoryDestination}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatal("second enrolled host could not claim its own native read", err)
	}
	job := claimed.Jobs[0]
	nativeIntent, err := servicedependents.DecodeInventoryIntent(job.Payload)
	if err != nil {
		t.Fatal(err)
	}
	secondReport := inventory
	secondReport.RunID = nativeIntent.RunID
	secondReport.BindingDigest = nativeIntent.BindingDigest
	secondReport.ObservedAt = time.Now().UTC()
	secondRaw, err := json.Marshal(secondReport)
	if err != nil || len(secondRaw) > servicedependents.MaxInventoryReportBytes {
		t.Fatal("second native report exceeded the original frame", err)
	}
	receipt, err := second.client.ReportJobResult(ctx, second.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(secondRaw), crypto.SHA256Hex(secondRaw)))
	if err != nil || !receipt.Accepted {
		t.Fatal("second signed native report was not accepted", err)
	}
	secondScan, err := h.store.GetServiceDependentScan(ctx, h.tenant, secondReport.RunID)
	if err != nil {
		t.Fatal(err)
	}
	host = servicedependents.RotationManifestHost{Binding: nativeIntent.Binding, InventoryRunID: secondReport.RunID, InventoryDigest: secondScan.ReportDigest, ObservedAt: secondReport.ObservedAt}
	originalBinding := binding
	binding = nativeIntent.Binding
	for _, target := range secondReport.Services {
		add("services", target.Name)
	}
	for _, target := range secondReport.Tasks {
		add("tasks", target.Path)
	}
	for _, target := range secondReport.Pools {
		add("iis", target.Name)
	}
	binding = originalBinding
	legacy := map[string]any{"secret_name": "app/dependent", "order": order, "probes": probes}
	code, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/rotations/preview", token, "owned-inline-review-boundary", legacy)
	if code != http.StatusUnprocessableEntity && code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large fixture did not reach the existing inline limit: %d", code)
	}
	code, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/reviews", token, "owned-open-large-native-review", map[string]any{"secret_name": "app/dependent"})
	var review store.ServiceDependentManifest
	if code != http.StatusCreated || json.Unmarshal(raw, &review) != nil {
		t.Fatalf("large native review did not open: %d", code)
	}
	path := "/api/v1/access/discovery/dependent-reviews/" + review.Header.ID
	previous := review.HeaderDigest
	totalBytes, pages := 0, 0
	for offset := 0; offset < len(entries); offset += 32 {
		end := offset + 32
		if end > len(entries) {
			end = len(entries)
		}
		input := map[string]any{"header_digest": review.HeaderDigest, "previous_digest": previous, "hosts": []servicedependents.RotationManifestHost{entries[offset].Host}, "entries": entries[offset:end]}
		code, raw = secretsReqKey(t, h.servedHarness, http.MethodPut, fmt.Sprintf("%s/pages/%d", path, pages), token, fmt.Sprintf("owned-large-native-page-%d", pages), input)
		var page servicedependents.RotationManifestPage
		if code != http.StatusCreated || json.Unmarshal(raw, &page) != nil || page.Validate(review.Header) != nil || len(raw) > servicedependents.MaxRotationManifestPageBytes {
			t.Fatalf("large native page violated exact source/frame: page=%d status=%d bytes=%d", pages, code, len(raw))
		}
		totalBytes += len(raw)
		previous = page.Digest
		pages++
		if end < len(entries) && end+32 >= len(entries) {
			if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, path+"/seal", token, "refuse-last-native-page-omission", map[string]any{"header_digest": review.HeaderDigest, "tail_digest": previous}); code != http.StatusConflict {
				t.Fatalf("large incomplete account was sealed: %d", code)
			}
		}
	}
	if totalBytes <= servicedependents.MaxRotationPlanBytes {
		t.Fatalf("paged fixture did not exceed the inline account size: %d", totalBytes)
	}
	code, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, path+"/seal", token, "owned-seal-large-native-review", map[string]any{"header_digest": review.HeaderDigest, "tail_digest": previous})
	var sealed store.ServiceDependentManifest
	if code != http.StatusCreated || json.Unmarshal(raw, &sealed) != nil || sealed.Seal == nil || sealed.Seal.EntryCount != int64(len(entries)) || sealed.Seal.PageCount != int64(pages) || sealed.Seal.HostCount != 2 {
		t.Fatalf("large complete account did not retain one seal: %d", code)
	}
	if directory.applied != 0 || directory.restored != 0 {
		t.Fatal("large review queued a premature directory mutation")
	}
	if err := projector.ProjectCatchUp(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, h.log); err != nil {
		t.Fatal("large manifest could not rebuild", err)
	}
	code, raw = secretsReq(t, h.servedHarness, http.MethodGet, path, token, nil)
	var rebuilt store.ServiceDependentManifest
	if code != http.StatusOK || json.Unmarshal(raw, &rebuilt) != nil || rebuilt.Seal == nil || rebuilt.Seal.Digest != sealed.Seal.Digest {
		t.Fatal("large manifest rebuild changed complete native scope")
	}
	t.Logf("A267_LARGE_REVIEW_OK native_refs=%d pages=%d total_public_page_bytes=%d; each page<=%d; review authoring caused no directory effect; signed host metadata fixtures", len(entries), pages, totalBytes, servicedependents.MaxRotationManifestPageBytes)
	if execute {
		servedLargeDependentExecution(t, h, second, token, root, path, sealed, entries, directory)
	}
}
