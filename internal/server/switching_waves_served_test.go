// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
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
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A row in a live wave is matched while its endpoint serves the imported
// certificate, serves_trstctl once it serves one trstctl issued, and
// renewed_by_other_product when it serves neither; a row in no wave serving
// another certificate is serves_other.
func TestObserveSwitchingRowClassifiesWaveRows(t *testing.T) {
	served, err := tlsprobe.NewServingTestServer("observe.a265.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(served.Close)
	info, err := certinfo.Inspect(served.LeafPEM)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := privateEgressSafeClientOptions([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	control := netsec.SafeDialControlWithOptions(opts)
	row := store.SwitchingImportRow{Row: 2, Fingerprint: crypto.SHA256Hex([]byte("imported")), Endpoints: []string{served.Addr}}
	for _, tc := range []struct {
		name    string
		trstctl map[string]bool
		want    string
	}{
		{"no wave", nil, store.SwitchingWatchServesOther},
		{"wave, trstctl's certificate", map[string]bool{info.SHA256Fingerprint: true}, store.SwitchingWatchServesTrstctl},
		{"wave, a third certificate", map[string]bool{"other": true}, store.SwitchingWatchRenewedByOtherProduct},
	} {
		if got := observeSwitchingRow(t.Context(), row, tc.trstctl, control); got.Status != tc.want || got.ServedFingerprint != info.SHA256Fingerprint {
			t.Errorf("%s: %+v, want %s", tc.name, got, tc.want)
		}
	}
	row.Fingerprint = info.SHA256Fingerprint
	if got := observeSwitchingRow(t.Context(), row, map[string]bool{}, control); got.Status != store.SwitchingWatchMatched {
		t.Errorf("imported certificate still served: %+v", got)
	}
}

// A265 Done when (part 3): a renewal wave cuts over and rolls back cleanly, and
// nothing renews twice while both products run. A wave moves two imported
// rows to trstctl (a third, with names the replacement would drop, is left out
// with its reason); each gets the one identity trstctl keeps for the row,
// bound to the wave's target and issued by trstctl, and the scheduler renews
// exactly those identities — never an imported, watch-only certificate. A row
// in a live wave cannot join another; the watch flags a wave row whose
// endpoint the other product renewed. Rolling back pauses the renewals,
// withdraws the queued renewal work and returns the rows to watch-only; a
// later wave finds the same identity and resumes it.
func TestServedSwitchingWaveA265(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.LifecycleRenewBefore = time.Hour })
	ctx := t.Context()
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a265-wave-admin", "*")
	call := func(method, path, key string, body any, want int) []byte {
		t.Helper()
		code, out := doBearer(t, h.ts, method, path, admin, key, body)
		if code != want {
			t.Fatalf("%s %s = %d, want %d: %.800s", method, path, code, want, out)
		}
		return out
	}
	salt := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	host := func(name string) string { return name + "." + salt + ".a265.test" }
	fp := func(s string) string { return crypto.SHA256Hex([]byte("a265-wave-" + salt + "-" + s)) }
	now := time.Now().UTC()

	// After the cutover the other product still renews wave1 and installs its
	// new certificate on wave1's endpoint; keep is watch-only and its endpoint
	// serves the imported certificate.
	otherRenewal, err := tlsprobe.NewServingTestServer(host("wave1"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(otherRenewal.Close)
	keep, err := tlsprobe.NewServingTestServer(host("keep"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keep.Close)
	notAfter := now.AddDate(0, 2, 0).Format(time.RFC3339)
	owner := "edge@" + salt + ".a265.test"
	export, _ := json.Marshal(map[string]any{"certificates": []map[string]any{
		{"fingerprint_sha256": fp("1"), "common_name": host("wave1"), "not_after": notAfter, "folder": "Edge", "application": "edge",
			"owner_email": owner, "endpoints": []string{otherRenewal.Addr}},
		{"fingerprint_sha256": fp("2"), "common_name": host("wave2"), "not_after": notAfter, "folder": "Edge", "application": "edge",
			"owner_email": owner},
		{"fingerprint_sha256": fp("3"), "common_name": host("wave3"), "sans": host("wave3") + "," + host("alt3"), "not_after": notAfter,
			"folder": "Edge", "application": "edge", "owner_email": owner},
		{"certificate_pem": string(keep.LeafPEM), "folder": "Edge", "application": "edge", "owner_email": owner,
			"endpoints": []string{keep.Addr}},
	}})
	request := map[string]any{"name": "A265 wave export", "export": string(export)}
	var preview struct {
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(call(http.MethodPost, "/api/v1/switching/imports/preview", "", request, http.StatusOK), &preview); err != nil {
		t.Fatal(err)
	}
	request["preview_digest"] = preview.Digest
	var imp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(call(http.MethodPost, "/api/v1/switching/imports", "a265-wave-import-"+salt, request, http.StatusCreated), &imp); err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		if _, err := h.srv.ApplySwitchingImportsOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if got, err := h.store.GetSwitchingImport(ctx, h.tenant, imp.ID); err != nil {
			t.Fatal(err)
		} else if got.Status == "completed" {
			break
		}
		if i == 20 {
			t.Fatal("the import did not complete")
		}
	}
	// Each endpoint is its own deployment target; a target carries one
	// active identity.
	targets := map[int]store.DeploymentTarget{}
	for _, n := range []int{1, 2} {
		target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: "edge" + strconv.Itoa(n) + "-" + salt,
			Type: "nginx", Config: json.RawMessage(`{}`), Enabled: true, EnabledSet: true})
		if err != nil {
			t.Fatal(err)
		}
		targets[n] = target
	}
	assign := func(pairs ...int) []map[string]any {
		var out []map[string]any
		for i := 0; i < len(pairs); i += 2 {
			out = append(out, map[string]any{"row_number": pairs[i], "target_id": targets[pairs[i+1]].ID})
		}
		return out
	}

	// Preview: rows 1 and 2 move, row 3 is left out with its reason, and the
	// other product's stop list names exactly the moved certificates.
	type planView struct {
		Rows []struct {
			Row            int    `json:"row_number"`
			IdentityID     string `json:"identity_id"`
			IdentityExists bool   `json:"identity_exists"`
		} `json:"rows"`
		Excluded []struct {
			Row    int    `json:"row_number"`
			Reason string `json:"reason"`
		} `json:"excluded"`
		StopRenewing []string `json:"stop_renewing"`
		Digest       string   `json:"digest"`
	}
	wavesPath := "/api/v1/switching/imports/" + imp.ID + "/waves"
	waveReq := map[string]any{"name": "edge wave", "assignments": assign(1, 1, 2, 2, 3, 1)}
	var plan planView
	if err := json.Unmarshal(call(http.MethodPost, wavesPath+"/preview", "", waveReq, http.StatusOK), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Rows) != 2 || plan.Rows[0].Row != 1 || plan.Rows[1].Row != 2 || len(plan.Excluded) != 1 || plan.Excluded[0].Row != 3 ||
		!strings.Contains(plan.Excluded[0].Reason, "1 more names") || len(plan.StopRenewing) != 2 ||
		plan.StopRenewing[0] != fp("1") || plan.StopRenewing[1] != fp("2") {
		t.Fatalf("wave plan = %+v", plan)
	}
	identities := []string{plan.Rows[0].IdentityID, plan.Rows[1].IdentityID}
	if identities[0] != orchestrator.SwitchingRowIdentityID(h.tenant, imp.ID, 1) {
		t.Fatalf("row 1's identity = %s", identities[0])
	}

	// Cut over: the reviewed digest only.
	waveReq["preview_digest"] = "sha256:" + strings.Repeat("0", 64)
	call(http.MethodPost, wavesPath, "a265-wave-stale-"+salt, waveReq, http.StatusConflict)
	waveReq["preview_digest"] = plan.Digest
	type waveView struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Rows   []struct {
			Row            int      `json:"row_number"`
			IdentityID     string   `json:"identity_id"`
			TargetID       string   `json:"target_id"`
			IdentityStatus string   `json:"identity_status"`
			RenewalPaused  bool     `json:"renewal_paused"`
			Trstctl        []string `json:"trstctl_fingerprints_sha256"`
			WatchStatus    string   `json:"watch_status"`
			Live           bool     `json:"live"`
		} `json:"rows"`
	}
	var wave waveView
	if err := json.Unmarshal(call(http.MethodPost, wavesPath, "a265-wave-cut-"+salt, waveReq, http.StatusCreated), &wave); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(call(http.MethodGet, "/api/v1/switching/waves/"+wave.ID, "", nil, http.StatusOK), &wave); err != nil {
		t.Fatal(err)
	}
	if wave.Status != "cut_over" || len(wave.Rows) != 2 {
		t.Fatalf("wave = %+v", wave)
	}
	issued := map[string]store.Certificate{}
	targetOf := map[string]store.DeploymentTarget{}
	for _, r := range wave.Rows {
		targetOf[r.IdentityID] = targets[r.Row]
		if r.TargetID != targets[r.Row].ID {
			t.Fatalf("row %d bound to %s, want %s", r.Row, r.TargetID, targets[r.Row].ID)
		}
		if r.IdentityStatus != "deployed" || len(r.Trstctl) != 1 || !r.Live || r.RenewalPaused {
			t.Fatalf("cut-over row = %+v", r)
		}
		cert, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, r.Trstctl[0])
		if err != nil {
			t.Fatal(err)
		}
		issued[r.IdentityID] = cert
	}
	// A row in a live wave cannot join another.
	var again planView
	if err := json.Unmarshal(call(http.MethodPost, wavesPath+"/preview", "", map[string]any{"name": "second",
		"assignments": assign(1, 1, 2, 2)}, http.StatusOK), &again); err != nil {
		t.Fatal(err)
	}
	if len(again.Rows) != 0 || len(again.Excluded) != 2 || !strings.Contains(again.Excluded[0].Reason, "already in live wave "+wave.ID) {
		t.Fatalf("second wave over live rows = %+v", again)
	}

	// Nothing renews twice: at each trstctl certificate's renewal window the
	// scheduler queues exactly one renewal per wave identity, and no imported
	// certificate (row 4 has no identity at all) is ever a candidate.
	renewals := func(identityID string) (pending, total int) {
		t.Helper()
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status IN ('pending','processing')), count(*) FROM outbox
				WHERE tenant_id = $1 AND destination = 'ca.renew' AND convert_from(payload,'UTF8')::jsonb->>'identity_id' = $2`,
				h.tenant, identityID).Scan(&pending, &total)
		}); err != nil {
			t.Fatal(err)
		}
		return pending, total
	}
	// The deploys wait for the target's executor (an agent on the host); it
	// reports each one delivered and verified, as recorded here, exactly as
	// the A179 assurance proof stands in for it.
	for id, cert := range issued {
		identityID := id
		for _, status := range []string{"delivered", "verified"} {
			if _, err := h.srv.orch.RecordConnectorDelivery(ctx, h.tenant, store.ConnectorDeliveryReceipt{IdentityID: &identityID,
				Destination: "connector.deploy", Connector: targetOf[id].Type, Target: targetOf[id].Name, Fingerprint: cert.Fingerprint,
				Status: status, IdempotencyKey: "a265-wave-" + identityID + ":" + status}); err != nil {
				t.Fatal(err)
			}
		}
	}
	window := issued[identities[0]].NotAfter.Add(-time.Minute)
	if later := issued[identities[1]].NotAfter.Add(-time.Minute); later.After(window) {
		window = later
	}
	if _, err := h.srv.runLifecycleOnceAt(ctx, window); err != nil {
		t.Fatal(err)
	}
	for _, id := range identities {
		if pending, total := renewals(id); pending != 1 || total != 1 {
			t.Fatalf("identity %s: %d pending of %d queued renewals, want exactly one", id, pending, total)
		}
	}
	if _, err := h.store.GetIdentity(ctx, h.tenant, orchestrator.SwitchingRowIdentityID(h.tenant, imp.ID, 4)); !store.IsNotFound(err) {
		t.Fatalf("watch-only row 4 has an identity: %v", err)
	}

	// The watch: wave1's endpoint now serves the other product's renewal.
	call(http.MethodPost, "/api/v1/switching/imports/"+imp.ID+"/watch", "a265-wave-watch-"+salt,
		map[string]any{"allow_private_endpoint": true, "private_egress_cidrs": []string{"127.0.0.1/32"}}, http.StatusOK)
	for i := 0; i < 10; i++ {
		if _, err := h.srv.ApplySwitchingImportsOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var watched struct {
		Items []struct {
			Row    int    `json:"row_number"`
			Status string `json:"watch_status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(call(http.MethodGet, "/api/v1/switching/imports/"+imp.ID+"/rows", "", nil, http.StatusOK), &watched); err != nil {
		t.Fatal(err)
	}
	want := map[int]string{1: store.SwitchingWatchRenewedByOtherProduct, 2: store.SwitchingWatchNoEndpoint,
		3: store.SwitchingWatchNoEndpoint, 4: store.SwitchingWatchMatched}
	for _, r := range watched.Items {
		if r.Status != want[r.Row] {
			t.Fatalf("row %d watch = %q, want %q (%+v)", r.Row, r.Status, want[r.Row], watched.Items)
		}
	}

	// Roll back: refused while the renewals are in flight (nothing changes);
	// once they settle, the queued deploys are withdrawn, the renewals paused
	// and the rows watch-only, and the scheduler queues nothing more for them.
	call(http.MethodPost, "/api/v1/switching/waves/"+wave.ID+"/rollback", "a265-wave-rollback-bad-"+salt, map[string]any{}, http.StatusBadRequest)
	call(http.MethodPost, "/api/v1/switching/waves/"+wave.ID+"/rollback", "a265-wave-rollback-early-"+salt,
		map[string]any{"reason": "too early"}, http.StatusConflict)
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	var rolled struct {
		waveView
		Withdrawn int `json:"withdrawn"`
	}
	if err := json.Unmarshal(call(http.MethodPost, "/api/v1/switching/waves/"+wave.ID+"/rollback", "a265-wave-rollback-"+salt,
		map[string]any{"reason": "cutover window missed"}, http.StatusOK), &rolled); err != nil {
		t.Fatal(err)
	}
	if rolled.Status != "rolled_back" || rolled.Withdrawn == 0 {
		t.Fatalf("rolled back wave = %+v (withdrew %d)", rolled, rolled.Withdrawn)
	}
	for _, r := range rolled.Rows {
		if r.Live || !r.RenewalPaused {
			t.Fatalf("rolled back row = %+v", r)
		}
	}
	call(http.MethodPost, "/api/v1/switching/waves/"+wave.ID+"/rollback", "a265-wave-rollback-2-"+salt,
		map[string]any{"reason": "again"}, http.StatusConflict)
	for _, id := range identities {
		if pending, total := renewals(id); pending != 0 || total != 1 {
			t.Fatalf("identity %s after rollback: %d pending of %d", id, pending, total)
		}
	}
	if _, err := h.srv.runLifecycleOnceAt(ctx, window.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, id := range identities {
		if pending, total := renewals(id); pending != 0 || total != 1 {
			t.Fatalf("identity %s renewed after the rollback: %d pending of %d", id, pending, total)
		}
	}

	// A later wave moves row 1 again with the same identity and resumes it.
	var replan planView
	if err := json.Unmarshal(call(http.MethodPost, wavesPath+"/preview", "", map[string]any{"name": "edge wave again",
		"assignments": assign(1, 1, 4, 1)}, http.StatusOK), &replan); err != nil {
		t.Fatal(err)
	}
	// Row 4 cannot share row 1's target: the target carries one identity.
	if len(replan.Rows) != 1 || replan.Rows[0].IdentityID != identities[0] || !replan.Rows[0].IdentityExists ||
		len(replan.Excluded) != 1 || replan.Excluded[0].Row != 4 || !strings.Contains(replan.Excluded[0].Reason, "assigned to row 1") {
		t.Fatalf("second wave plan = %+v", replan)
	}
	var recut waveView
	if err := json.Unmarshal(call(http.MethodPost, wavesPath, "a265-wave-recut-"+salt, map[string]any{"name": "edge wave again",
		"assignments": assign(1, 1, 4, 1), "preview_digest": replan.Digest}, http.StatusCreated), &recut); err != nil {
		t.Fatal(err)
	}
	if len(recut.Rows) != 1 || recut.Rows[0].IdentityID != identities[0] || recut.Rows[0].RenewalPaused || !recut.Rows[0].Live ||
		recut.Rows[0].IdentityStatus != "deployed" {
		t.Fatalf("re-cut row = %+v", recut.Rows)
	}
}
