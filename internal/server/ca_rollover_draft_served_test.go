// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

type servedRolloverAuthority struct {
	servedCAAuthority
	RolloverDraft *struct {
		BandMonths       int    `json:"band_months"`
		CeremonyID       string `json:"ceremony_id"`
		CeremonyStatus   string `json:"ceremony_status"`
		Approvals        int    `json:"approvals"`
		Threshold        int    `json:"threshold"`
		Reason           string `json:"reason"`
		TTLSeconds       int64  `json:"ttl_seconds"`
		NotDraftedReason string `json:"not_drafted_reason"`
	} `json:"rollover_draft"`
}

func listRolloverAuthorities(t *testing.T, h *servedHarness, token string) map[string]servedRolloverAuthority {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodGet, "/api/v1/ca/authorities", token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("list CA authorities = %d %s", code, raw)
	}
	var list struct {
		Items []servedRolloverAuthority `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	out := map[string]servedRolloverAuthority{}
	for _, item := range list.Items {
		out[item.ID] = item
	}
	return out
}

func createRolloverRoot(t *testing.T, h *servedHarness, operator, approver, name string, ttl time.Duration) servedCAAuthority {
	t.Helper()
	spec := map[string]any{
		"common_name": name, "max_path_len": 1, "ttl_seconds": int64(ttl.Seconds()),
		"permitted_dns_domains": []string{"rollover.example.test"}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, operator, "create_root", "", spec, 1, name+"-ceremony")
	approveCACeremony(t, h, approver, ceremony.ID, 1, name+"-approval")
	return createRootCA(t, h, operator, ceremony.ID, spec, name+"-create")
}

// A216: with ca.rollover_draft_band_months set, an authority entering that
// band gets a re-key ceremony opened by the CA calendar with the reviewed plan;
// a second sweep drafts nothing new, approval alone rotates nothing, and a
// person executing the re-key with the drafted plan rolls the authority over.
// An authority outside the band gets no draft.
func TestServedCARolloverIsDraftedAtTheBandAndWaitsForAPerson(t *testing.T) {
	ctx := t.Context()
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.CARolloverDraftBandMonths = 12 })
	scopes := []string{"issuers:write", "issuers:read", "certs:issue"}
	operator := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "rollover-operator", scopes)
	approver := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "rollover-approver", scopes)
	near := createRolloverRoot(t, h, operator, approver, "rollover near root", 200*24*time.Hour)
	far := createRolloverRoot(t, h, operator, approver, "rollover far root", 3*365*24*time.Hour)

	drafted, err := h.srv.RunCARolloverDraftsOnce(ctx)
	if err != nil || drafted != 1 {
		t.Fatalf("rollover drafts = %d, %v; want one for the authority inside the band", drafted, err)
	}
	authorities := listRolloverAuthorities(t, h, operator)
	draft := authorities[near.ID].RolloverDraft
	if draft == nil || draft.CeremonyID == "" || draft.CeremonyStatus != "pending" || draft.Approvals != 0 || draft.Threshold != 1 ||
		draft.BandMonths > 12 || draft.TTLSeconds != int64((200*24*time.Hour).Seconds()) ||
		!strings.Contains(draft.Reason, "Scheduled rollover: rollover near root") {
		t.Fatalf("near root draft = %+v; want a pending re-key ceremony with the reviewed plan", draft)
	}
	if authorities[far.ID].RolloverDraft != nil {
		t.Fatalf("far root got a draft %+v outside the band", authorities[far.ID].RolloverDraft)
	}
	if got := authorities[near.ID]; got.Status != "active" || got.SignerHandle != near.SignerHandle || len(authorities) != 2 {
		t.Fatalf("drafting changed the authorities: %+v (%d authorities)", got, len(authorities))
	}
	ceremony, err := h.store.GetKeyCeremony(ctx, h.tenant, draft.CeremonyID)
	if err != nil || ceremony.Opener != caCalendarActor || !strings.HasPrefix(ceremony.Purpose, "ca-rekey-v2:") {
		t.Fatalf("drafted ceremony = %+v (%v); want a re-key ceremony the CA calendar opened", ceremony, err)
	}

	if again, err := h.srv.RunCARolloverDraftsOnce(ctx); err != nil || again != 0 {
		t.Fatalf("second sweep drafted %d (%v); want nothing new", again, err)
	}
	approveCACeremony(t, h, approver, draft.CeremonyID, 1, "rollover-draft-approval")
	if again, err := h.srv.RunCARolloverDraftsOnce(ctx); err != nil || again != 0 {
		t.Fatalf("sweep after approval drafted %d (%v)", again, err)
	}
	if got := listRolloverAuthorities(t, h, operator)[near.ID]; got.Status != "active" || got.SignerHandle != near.SignerHandle {
		t.Fatalf("approval alone rotated the authority: %+v", got)
	}

	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+near.ID+"/rekey", operator, "rollover-execute", map[string]any{
		"ceremony_id": draft.CeremonyID, "ttl_seconds": draft.TTLSeconds, "reason": draft.Reason,
	})
	if code != http.StatusCreated {
		t.Fatalf("execute the drafted re-key = %d %s", code, raw)
	}
	if got := listRolloverAuthorities(t, h, operator)[near.ID]; got.Status != "superseded" {
		t.Fatalf("after the person executed the re-key the authority is %q; want superseded", got.Status)
	}
}

// A216: without the setting (the default) nothing is drafted.
func TestServedCARolloverDraftsAreOffByDefault(t *testing.T) {
	ctx := t.Context()
	h := newOperatingServedHarness(t, config.Protocols{})
	scopes := []string{"issuers:write", "issuers:read", "certs:issue"}
	operator := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "rollover-off-operator", scopes)
	approver := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "rollover-off-approver", scopes)
	near := createRolloverRoot(t, h, operator, approver, "rollover off root", 100*24*time.Hour)
	if drafted, err := h.srv.RunCARolloverDraftsOnce(ctx); err != nil || drafted != 0 {
		t.Fatalf("drafts with the setting off = %d, %v", drafted, err)
	}
	if got := listRolloverAuthorities(t, h, operator)[near.ID]; got.RolloverDraft != nil {
		t.Fatalf("an authority got a draft with the setting off: %+v", got.RolloverDraft)
	}
}
