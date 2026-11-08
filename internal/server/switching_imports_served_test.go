// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/switchkit"
)

// a265Export is several thousand rows across nested folders, owners and
// application groups, with the defects a real export carries: a duplicate, an
// unparseable fingerprint, an expired certificate and a row with no endpoint.
// Its column names are the export's own, renamed by a column map.
func a265Export(n int, salt string, now time.Time) (string, map[string]string) {
	fp := func(i int) string { return crypto.SHA256Hex([]byte(fmt.Sprintf("a265-%s-%d", salt, i))) }
	var b strings.Builder
	b.WriteString("Thumbprint,Subject CN,Valid To,Policy Folder,App Group,Owner,Renewal Days,Installed At\n")
	for i := 1; i <= n; i++ {
		thumb, notAfter, endpoint := fp(i), now.AddDate(0, 0, 30+i%300).Format("2006-01-02"), fmt.Sprintf("svc-%d.a265.test:443", i)
		switch {
		case i%997 == 0:
			thumb = fp(i - 1)
		case i%499 == 0:
			thumb = "not-a-fingerprint"
		case i%251 == 0:
			notAfter = now.AddDate(0, 0, -3).Format("2006-01-02")
		case i%7 == 0:
			endpoint = ""
		}
		fmt.Fprintf(&b, "%s,svc-%d.a265.test,%s,Root\\Region %d\\Team %d,app-%d,owner-%d@%s.a265.test,30,%s\n",
			thumb, i, notAfter, i%4, i%9, i%12, i%25, salt, endpoint)
	}
	return b.String(), map[string]string{"Thumbprint": "fingerprint_sha256", "Subject CN": "common_name", "Valid To": "not_after",
		"Policy Folder": "folder", "App Group": "application", "Owner": "owner_email", "Renewal Days": "renewal_window_days",
		"Installed At": "endpoints"}
}

// A265 Done when (part 1): a seeded export with several thousand certificates,
// nested folders, owners and application groups imports with a mapping report
// and no silent drops. Every row has exactly one stored outcome, every mapped
// row became a certificate (or was linked to the one already in the
// inventory, which is left as it was), and owners land per application group.
func TestServedSwitchingImportA265(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a265-admin", "*")
	call := func(method, path, key string, body any, want int) []byte {
		t.Helper()
		code, out := doBearer(t, h.ts, method, path, admin, key, body)
		if code != want {
			t.Fatalf("%s %s = %d, want %d: %.600s", method, path, code, want, out)
		}
		return out
	}
	salt := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	now := time.Now().UTC()
	const n = 3000
	export, columnMap := a265Export(n, salt, now)

	// Already in this tenant: one owner (owner-3 in app-3) and one certificate
	// the export also lists (its first row, line 2), recorded by trstctl's own
	// discovery.
	existingOwner, err := h.srv.orch.CreateOwnerRecord(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerTeam,
		Name: "app-3 team", Email: "owner-3@" + salt + ".a265.test", ApplicationID: "app-3"})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := switchkit.Parse([]byte(export), columnMap)
	if err != nil {
		t.Fatal(err)
	}
	row1 := rows[0].Fields["fingerprint_sha256"]
	knownNotAfter := now.Add(40 * 24 * time.Hour)
	known, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{Subject: "CN=svc-1.a265.test",
		SANs: []string{"svc-1.a265.test"}, Serial: "a265-known", Issuer: "CN=A265 Discovery CA", Fingerprint: row1,
		NotAfter: &knownNotAfter, Source: "discovered"})
	if err != nil {
		t.Fatal(err)
	}

	// Preview: every row has one outcome, the seeded defects are named, the
	// known certificate is marked, and nothing changed.
	var preview struct {
		Rows         int                      `json:"rows"`
		Counts       map[string]int           `json:"counts"`
		GapCounts    map[string]int           `json:"gap_counts"`
		Known        int                      `json:"known"`
		Items        []switchkit.Mapped       `json:"items"`
		Folders      []switchkit.FolderPolicy `json:"folders"`
		Owners       []switchkit.OwnerMatch   `json:"owners"`
		Applications []string                 `json:"applications"`
		Digest       string                   `json:"digest"`
	}
	request := map[string]any{"name": "A265 seeded export", "export": export, "column_map": columnMap}
	if err := json.Unmarshal(call(http.MethodPost, "/api/v1/switching/imports/preview", "", request, http.StatusOK), &preview); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, c := range preview.Counts {
		total += c
	}
	if preview.Rows != n || total != n || preview.Known != 1 || preview.Counts[switchkit.OutcomeDuplicate] == 0 ||
		preview.Counts[switchkit.OutcomeUnparseable] == 0 || preview.Counts[switchkit.OutcomeExpired] == 0 ||
		preview.GapCounts["no endpoint"] == 0 || len(preview.Folders) != 36 || len(preview.Owners) != 300 || len(preview.Applications) != 12 {
		t.Fatalf("preview = rows %d total %d known %d counts %v gaps %v folders %d owners %d apps %d", preview.Rows, total,
			preview.Known, preview.Counts, preview.GapCounts, len(preview.Folders), len(preview.Owners), len(preview.Applications))
	}
	reused := 0
	for _, o := range preview.Owners {
		if !o.Create {
			reused++
			if o.OwnerID != existingOwner.ID {
				t.Fatalf("owner %s/%s matched %s, want %s", o.Email, o.Application, o.OwnerID, existingOwner.ID)
			}
		}
	}
	if reused != 1 {
		t.Fatalf("%d owners matched an existing one, want 1", reused)
	}
	for _, m := range preview.Items {
		if m.Outcome != switchkit.OutcomeMapped && m.Outcome != switchkit.OutcomeMappedWithGaps && m.Reason == "" {
			t.Fatalf("preview row %d is %s with no reason", m.Row, m.Outcome)
		}
	}
	if imports, err := h.store.ListSwitchingImports(ctx, h.tenant, 100); err != nil {
		t.Fatal(err)
	} else {
		for _, imp := range imports {
			if imp.PreviewDigest == preview.Digest {
				t.Fatal("a preview recorded an import")
			}
		}
	}

	// Apply: no digest and a stale digest are refused; the reviewed digest
	// records the import and every row, and a retry of the same command is
	// the same import.
	request["preview_digest"] = ""
	call(http.MethodPost, "/api/v1/switching/imports", "a265-apply-nodigest-"+salt, request, http.StatusBadRequest)
	request["preview_digest"] = "sha256:" + strings.Repeat("0", 64)
	call(http.MethodPost, "/api/v1/switching/imports", "a265-apply-stale-"+salt, request, http.StatusConflict)
	request["preview_digest"] = preview.Digest
	var imp struct {
		ID           string `json:"id"`
		Status       string `json:"status"`
		RowsTotal    int    `json:"rows_total"`
		RowsRecorded int    `json:"rows_recorded"`
		RowsApplied  int    `json:"rows_applied"`
	}
	applyKey := "a265-apply-" + salt
	if err := json.Unmarshal(call(http.MethodPost, "/api/v1/switching/imports", applyKey, request, http.StatusCreated), &imp); err != nil {
		t.Fatal(err)
	}
	if imp.Status != "recording" || imp.RowsTotal != n || imp.RowsRecorded != n {
		t.Fatalf("applied import = %+v", imp)
	}
	var again struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(call(http.MethodPost, "/api/v1/switching/imports", applyKey, request, http.StatusCreated), &again); err != nil || again.ID != imp.ID {
		t.Fatalf("retried apply = %s (%v), want %s", again.ID, err, imp.ID)
	}

	// The leader applies it in bounded batches until it completes.
	applyStart := time.Now()
	deadline := applyStart.Add(5 * time.Minute)
	for {
		if _, err := h.srv.ApplySwitchingImportsOnce(ctx); err != nil {
			t.Fatal(err)
		}
		got, err := h.store.GetSwitchingImport(ctx, h.tenant, imp.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("import still %s after 5 minutes: %d of %d applied", got.Status, got.RowsApplied, got.RowsTotal)
		}
	}
	t.Logf("applied the import's mapped rows in %s", time.Since(applyStart).Round(time.Millisecond))
	mapped := preview.Counts[switchkit.OutcomeMapped] + preview.Counts[switchkit.OutcomeMappedWithGaps]
	if err := json.Unmarshal(call(http.MethodGet, "/api/v1/switching/imports/"+imp.ID, "", nil, http.StatusOK), &imp); err != nil {
		t.Fatal(err)
	}
	if imp.Status != "completed" || imp.RowsApplied != mapped {
		t.Fatalf("completed import = %+v, want %d applied", imp, mapped)
	}

	// No silent drops: every row is stored exactly once with one outcome (a
	// CSV row is numbered by its line, so the export's rows are 2..n+1);
	// every mapped row names its certificate; the known row (line 2) is linked.
	seen := make([]bool, n+2)
	outcomes := map[string]int{}
	after := 0
	for {
		var page struct {
			Items []struct {
				Row           int      `json:"row_number"`
				Outcome       string   `json:"outcome"`
				Reason        string   `json:"reason"`
				Gaps          []string `json:"gaps"`
				CertificateID string   `json:"certificate_id"`
				OwnerID       string   `json:"owner_id"`
				OwnerEmail    string   `json:"owner_email"`
				Linked        bool     `json:"linked"`
			} `json:"items"`
			NextAfter string `json:"next_after"`
		}
		if err := json.Unmarshal(call(http.MethodGet, fmt.Sprintf("/api/v1/switching/imports/%s/rows?after=%d&limit=1000", imp.ID, after),
			"", nil, http.StatusOK), &page); err != nil {
			t.Fatal(err)
		}
		for _, r := range page.Items {
			if r.Row < 2 || r.Row > n+1 || seen[r.Row] {
				t.Fatalf("row %d out of range or listed twice", r.Row)
			}
			seen[r.Row] = true
			outcomes[r.Outcome]++
			usable := r.Outcome == switchkit.OutcomeMapped || r.Outcome == switchkit.OutcomeMappedWithGaps
			switch {
			case !usable && (r.Reason == "" || r.CertificateID != ""):
				t.Fatalf("row %d is %s with reason %q and certificate %q", r.Row, r.Outcome, r.Reason, r.CertificateID)
			case usable && r.CertificateID == "":
				t.Fatalf("mapped row %d became no certificate", r.Row)
			case r.Row == 2 && (!r.Linked || r.CertificateID != known.ID):
				t.Fatalf("row 2 = linked %v certificate %s, want linked to %s", r.Linked, r.CertificateID, known.ID)
			case r.Row != 2 && r.Linked:
				t.Fatalf("row %d linked, only row 2 is known", r.Row)
			case usable && r.Row != 2 && r.OwnerEmail != "" && r.OwnerID == "":
				t.Fatalf("row %d names %s but has no owner", r.Row, r.OwnerEmail)
			}
		}
		if page.NextAfter == "" {
			break
		}
		if after, err = strconv.Atoi(page.NextAfter); err != nil {
			t.Fatalf("next_after %q: %v", page.NextAfter, err)
		}
	}
	for line := 2; line <= n+1; line++ {
		if !seen[line] {
			t.Fatalf("row %d was dropped", line)
		}
	}
	for outcome, c := range preview.Counts {
		if outcomes[outcome] != c {
			t.Fatalf("stored %d %s rows, preview counted %d", outcomes[outcome], outcome, c)
		}
	}

	// The inventory: the import's certificates are watch-only under their
	// owners; the known certificate kept its own names, source and owner.
	var imported, keyed int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE issuance_idempotency_key <> '')
			FROM certificates WHERE tenant_id = $1 AND source = $2`, h.tenant, orchestrator.SwitchingImportSource(imp.ID)).
			Scan(&imported, &keyed)
	}); err != nil {
		t.Fatal(err)
	}
	// An issuance key would make an imported certificate a renewal candidate.
	if imported != mapped-1 || keyed != 0 {
		t.Fatalf("%d certificates carry the import's source (want %d), %d with an issuance key", imported, mapped-1, keyed)
	}
	kept, err := h.store.GetCertificate(ctx, h.tenant, known.ID)
	if err != nil {
		t.Fatal(err)
	}
	if kept.Source != "discovered" || len(kept.SANs) != 1 || kept.OwnerID != nil || kept.Serial != "a265-known" {
		t.Fatalf("known certificate rewritten by the import: %+v", kept)
	}
	owners, err := h.store.ListOwners(ctx, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	perPair := map[string]int{}
	for _, o := range owners {
		if strings.HasSuffix(o.Email, "@"+salt+".a265.test") {
			perPair[switchkit.OwnerKey(o.Email, o.ApplicationID)]++
		}
	}
	if len(perPair) != 300 {
		t.Fatalf("%d owners for the export's 300 email and application pairs", len(perPair))
	}
	for pair, c := range perPair {
		if c != 1 {
			t.Fatalf("owner %q recorded %d times", pair, c)
		}
	}

	// A JSON export with a certificate's own PEM records its bytes and names;
	// a row with only metadata records its SANs.
	served, err := tlsprobe.NewServingTestServer("api."+salt+".a265.test", "www."+salt+".a265.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(served.Close)
	der, err := certinfo.LeafDER(served.LeafPEM)
	if err != nil {
		t.Fatal(err)
	}
	// The watch's endpoints: one listener serving a different certificate
	// than the export lists for it, and one that is closed.
	swapped, err := tlsprobe.NewServingTestServer("pay." + salt + ".a265.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(swapped.Close)
	swappedDER, err := certinfo.LeafDER(swapped.LeafPEM)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := tlsprobe.NewServingTestServer("gone." + salt + ".a265.test")
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	metaFP := crypto.SHA256Hex([]byte("a265-json-" + salt))
	listedFP := crypto.SHA256Hex([]byte("a265-json-listed-" + salt))
	goneFP := crypto.SHA256Hex([]byte("a265-json-gone-" + salt))
	jsonExport, _ := json.Marshal(map[string]any{"certificates": []map[string]any{
		{"certificate_pem": string(served.LeafPEM), "folder": "Web/Public", "application": "storefront",
			"owner_email": "web@" + salt + ".a265.test", "endpoints": []string{served.Addr}},
		{"fingerprint_sha256": metaFP, "common_name": "meta." + salt + ".a265.test",
			"sans": "meta." + salt + ".a265.test,alt." + salt + ".a265.test", "not_after": now.AddDate(0, 2, 0).Format(time.RFC3339),
			"folder": "Web/Public", "application": "storefront", "owner_email": "web@" + salt + ".a265.test"},
		{"fingerprint_sha256": listedFP, "common_name": "pay." + salt + ".a265.test", "not_after": now.AddDate(0, 2, 0).Format(time.RFC3339),
			"folder": "Web/Public", "application": "payments", "owner_email": "pay@" + salt + ".a265.test", "endpoints": []string{swapped.Addr}},
		{"fingerprint_sha256": goneFP, "common_name": "gone." + salt + ".a265.test", "not_after": now.AddDate(0, 2, 0).Format(time.RFC3339),
			"folder": "Web/Public", "application": "payments", "owner_email": "pay@" + salt + ".a265.test", "endpoints": []string{closed.Addr}},
	}})
	jsonRequest := map[string]any{"name": "A265 JSON export", "export": string(jsonExport)}
	var jsonPreview struct {
		Counts map[string]int `json:"counts"`
		Digest string         `json:"digest"`
	}
	if err := json.Unmarshal(call(http.MethodPost, "/api/v1/switching/imports/preview", "", jsonRequest, http.StatusOK), &jsonPreview); err != nil {
		t.Fatal(err)
	}
	jsonRequest["preview_digest"] = jsonPreview.Digest
	var jsonImport struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(call(http.MethodPost, "/api/v1/switching/imports", "a265-json-"+salt, jsonRequest, http.StatusCreated), &jsonImport); err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		if _, err := h.srv.ApplySwitchingImportsOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if got, err := h.store.GetSwitchingImport(ctx, h.tenant, jsonImport.ID); err != nil {
			t.Fatal(err)
		} else if got.Status == "completed" {
			break
		}
		if i == 20 {
			t.Fatal("the JSON import did not complete")
		}
	}
	withPEM, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, crypto.SHA256Hex(der))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(withPEM.CertificateDER, der) || len(withPEM.SANs) != 2 || withPEM.Source != orchestrator.SwitchingImportSource(jsonImport.ID) {
		t.Fatalf("PEM row recorded as %+v", withPEM)
	}
	withMeta, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, metaFP)
	if err != nil {
		t.Fatal(err)
	}
	if len(withMeta.SANs) != 2 || withMeta.Subject != "CN=meta."+salt+".a265.test" || withMeta.NotAfter == nil {
		t.Fatalf("metadata row recorded as %+v", withMeta)
	}

	// The endpoint watch. A round is refused before an import completes or
	// with a private grant that names no range; by default the control plane
	// reaches public addresses only, so every loopback endpoint is unreachable.
	watchPath := "/api/v1/switching/imports/" + jsonImport.ID + "/watch"
	call(http.MethodPost, watchPath, "a265-watch-bad-"+salt, map[string]any{"allow_private_endpoint": true}, http.StatusBadRequest)
	call(http.MethodPost, watchPath, "a265-watch-bad2-"+salt, map[string]any{"private_egress_cidrs": []string{"127.0.0.1/32"}}, http.StatusBadRequest)
	type watchView struct {
		Watch struct {
			Round       int            `json:"round"`
			Pending     int            `json:"pending"`
			RequestedBy string         `json:"requested_by"`
			Counts      map[string]int `json:"counts"`
		} `json:"watch"`
	}
	runWatch := func(at time.Time) watchView {
		t.Helper()
		for i := 0; i < 10; i++ {
			if _, err := h.srv.applySwitchingImportsAt(ctx, at); err != nil {
				t.Fatal(err)
			}
			var v watchView
			if err := json.Unmarshal(call(http.MethodGet, "/api/v1/switching/imports/"+jsonImport.ID, "", nil, http.StatusOK), &v); err != nil {
				t.Fatal(err)
			}
			if v.Watch.Pending == 0 && v.Watch.Round > 0 {
				return v
			}
		}
		t.Fatal("the watch round did not finish")
		return watchView{}
	}
	call(http.MethodPost, watchPath, "a265-watch-1-"+salt, nil, http.StatusOK)
	first := runWatch(time.Now().UTC())
	if first.Watch.Round != 1 || first.Watch.Counts["unreachable"] != 3 || first.Watch.Counts["no_endpoint"] != 1 {
		t.Fatalf("public-only round = %+v", first.Watch)
	}
	// With loopback granted: each row is matched or flagged with its reason.
	call(http.MethodPost, watchPath, "a265-watch-2-"+salt, map[string]any{"allow_private_endpoint": true,
		"private_egress_cidrs": []string{"127.0.0.1/32"}}, http.StatusOK)
	second := runWatch(time.Now().UTC())
	if second.Watch.Round != 2 || second.Watch.Counts["matched"] != 1 || second.Watch.Counts["serves_other"] != 1 ||
		second.Watch.Counts["unreachable"] != 1 || second.Watch.Counts["no_endpoint"] != 1 {
		t.Fatalf("granted round = %+v", second.Watch)
	}
	var flagged struct {
		Items []struct {
			Row          int        `json:"row_number"`
			Status       string     `json:"watch_status"`
			Endpoint     string     `json:"watch_endpoint"`
			ServedFP     string     `json:"served_fingerprint_sha256"`
			Fingerprint  string     `json:"fingerprint_sha256"`
			WatchedAtSet *time.Time `json:"watched_at"`
		} `json:"items"`
	}
	if err := json.Unmarshal(call(http.MethodGet, "/api/v1/switching/imports/"+jsonImport.ID+"/rows?watch_status=serves_other", "", nil,
		http.StatusOK), &flagged); err != nil {
		t.Fatal(err)
	}
	if len(flagged.Items) != 1 || flagged.Items[0].Fingerprint != listedFP || flagged.Items[0].ServedFP != crypto.SHA256Hex(swappedDER) ||
		flagged.Items[0].Endpoint != swapped.Addr || flagged.Items[0].WatchedAtSet == nil {
		t.Fatalf("serves_other rows = %+v", flagged.Items)
	}
	// A day later the leader starts the next round itself, with the same grant.
	third := runWatch(time.Now().UTC().Add(25 * time.Hour))
	if third.Watch.Round != 3 || third.Watch.RequestedBy != "scheduler" || third.Watch.Counts["matched"] != 1 {
		t.Fatalf("scheduled round = %+v", third.Watch)
	}
}

// A266 finding: an export over the shared 1 MiB REST request limit, well
// inside the switching kit's own 50,000 rows and 20 MiB, previews, applies and
// is recorded in full. Before, preview took it and apply refused it with 413,
// so no export of more than about 2,500 rows could be applied at all.
func TestServedSwitchingImportAppliesAnExportOverOneMiB(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a266-admin", "*")
	call := func(method, path, key string, body any, want int) []byte {
		t.Helper()
		code, out := doBearer(t, h.ts, method, path, admin, key, body)
		if code != want {
			t.Fatalf("%s %s = %d, want %d: %.600s", method, path, code, want, out)
		}
		return out
	}
	salt := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	now := time.Now().UTC()
	// Each certificate is deployed on a dozen hosts, as a shared wildcard is.
	const n = 2000
	rows := make([]map[string]string, 0, n)
	for i := 0; i < n; i++ {
		endpoints := make([]string, 12)
		for e := range endpoints {
			endpoints[e] = fmt.Sprintf("web-%04d-%02d.a266-%s.test:443", i, e, salt)
		}
		rows = append(rows, map[string]string{
			"fingerprint_sha256": crypto.SHA256Hex([]byte(fmt.Sprintf("a266-%s-%d", salt, i))),
			"common_name":        fmt.Sprintf("svc-%04d.a266-%s.test", i, salt),
			"not_after":          now.AddDate(0, 0, 30+i%300).Format(time.RFC3339),
			"folder":             fmt.Sprintf("Estate/Region %d", i%4),
			"application":        fmt.Sprintf("app-%d", i%6),
			"owner_email":        fmt.Sprintf("owner-%d@a266-%s.test", i%6, salt),
			"endpoints":          strings.Join(endpoints, ","),
		})
	}
	export, err := json.Marshal(map[string]any{"certificates": rows})
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"name": "A266 export over one MiB", "export": string(export)}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) <= 1<<20 || len(export) > switchkit.MaxBytes {
		t.Fatalf("request is %d bytes and export %d; the proof needs a request over 1 MiB and an export within the kit's limit", len(body), len(export))
	}

	var preview struct {
		Rows   int    `json:"rows"`
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(call(http.MethodPost, "/api/v1/switching/imports/preview", "", request, http.StatusOK), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Rows != n || preview.Digest == "" {
		t.Fatalf("preview = %+v, want %d rows and a digest", preview, n)
	}
	request["preview_digest"] = preview.Digest
	var imp struct {
		ID        string `json:"id"`
		RowsTotal int    `json:"rows_total"`
	}
	applyKey := "a266-apply-" + salt
	if err := json.Unmarshal(call(http.MethodPost, "/api/v1/switching/imports", applyKey, request, http.StatusCreated), &imp); err != nil {
		t.Fatal(err)
	}
	if imp.ID == "" || imp.RowsTotal != n {
		t.Fatalf("applied import = %+v, want %d rows", imp, n)
	}
	// The key binds the whole request: the same bytes replay, an export that
	// differs only in its last row is a different command.
	var again struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(call(http.MethodPost, "/api/v1/switching/imports", applyKey, request, http.StatusCreated), &again); err != nil || again.ID != imp.ID {
		t.Fatalf("retried apply = %s (%v), want %s", again.ID, err, imp.ID)
	}
	rows[n-1]["common_name"] = "changed.a266.test"
	changed, err := json.Marshal(map[string]any{"certificates": rows})
	if err != nil {
		t.Fatal(err)
	}
	call(http.MethodPost, "/api/v1/switching/imports", applyKey, map[string]any{"name": request["name"], "export": string(changed),
		"preview_digest": preview.Digest}, http.StatusConflict)

	deadline := time.Now().Add(5 * time.Minute)
	for {
		if _, err := h.srv.ApplySwitchingImportsOnce(ctx); err != nil {
			t.Fatal(err)
		}
		got, err := h.store.GetSwitchingImport(ctx, h.tenant, imp.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status == "completed" {
			if got.RowsApplied != n {
				t.Fatalf("completed import applied %d of %d rows", got.RowsApplied, n)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("import still %s after 5 minutes: %d of %d applied", got.Status, got.RowsApplied, got.RowsTotal)
		}
	}
}
