// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/transit"
)

type servedTransitVersion struct {
	Version    int    `json:"version"`
	Current    bool   `json:"current"`
	FactID     string `json:"fact_id"`
	Recorded   bool   `json:"recorded"`
	RecordedAt string `json:"recorded_at"`
}

func servedTransitVersions(t *testing.T, h *servedHarness, token, name string) []servedTransitVersion {
	t.Helper()
	code, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/transit/keys/"+name+"/versions", token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("versions = %d; body=%s", code, body)
	}
	var history struct {
		Versions []servedTransitVersion `json:"versions"`
	}
	if err := json.Unmarshal(body, &history); err != nil {
		t.Fatalf("decode versions: %v; body=%s", err, body)
	}
	return history.Versions
}

// A126 through the served binary: a create and a rotation are lifecycle facts
// in the event log under each version's fact ID, the versions listing names
// them as recorded, and the read model is a projection of the log: when it is
// lost, a reconcile pass projects the existing events again without appending
// new ones, and so does a replay of the whole log.
func TestServedTransitLifecycleFactsAreEventSourced(t *testing.T) {
	ctx := context.Background()
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedServedAPIToken(t, ctx, h.store, h.tenant, "kms-operator", []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/transit/keys", token, "a126-create", map[string]string{
		"name": "audit-macs", "kind": "hmac",
	}); code != http.StatusCreated {
		t.Fatalf("create = %d; body=%s", code, body)
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/transit/keys/rotate", token, "a126-rotate", map[string]string{
		"name": "audit-macs",
	}); code != http.StatusOK {
		t.Fatalf("rotate = %d; body=%s", code, body)
	}
	versions := servedTransitVersions(t, h, token, "audit-macs")
	if len(versions) != 2 {
		t.Fatalf("versions = %+v", versions)
	}
	for _, v := range versions {
		if !transit.ValidFactID(v.FactID) || !v.Recorded || v.RecordedAt == "" {
			t.Fatalf("version %d = %+v, want a recorded fact", v.Version, v)
		}
	}

	countFacts := func() map[string]int {
		t.Helper()
		seen := map[string]int{}
		if err := h.log.Replay(ctx, 0, func(e events.Event) error {
			if e.TenantID != h.tenant || (e.Type != transit.EventKeyCreated && e.Type != transit.EventKeyRotated) {
				return nil
			}
			if e.SchemaVersion != transit.FactSchemaVersion {
				return nil
			}
			var pl projections.TransitKeyFact
			if err := json.Unmarshal(e.Data, &pl); err != nil {
				t.Fatalf("fact %s payload: %v", e.ID, err)
			}
			for _, v := range versions {
				if v.FactID == e.ID && (pl.Key != "audit-macs" || pl.Kind != "hmac" || pl.Version != v.Version) {
					t.Fatalf("fact %s = %+v, want version %d of audit-macs", e.ID, pl, v.Version)
				}
			}
			seen[e.ID]++
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return seen
	}
	facts := countFacts()
	for _, v := range versions {
		if facts[v.FactID] != 1 {
			t.Fatalf("the log holds fact %s %d times, want once", v.FactID, facts[v.FactID])
		}
	}

	dropProjection := func() {
		t.Helper()
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM transit_key_facts WHERE tenant_id = $1`, h.tenant)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		for _, v := range servedTransitVersions(t, h, token, "audit-macs") {
			if v.Recorded {
				t.Fatalf("version %d still reads as recorded with the projection gone", v.Version)
			}
		}
	}
	dropProjection()
	h.srv.transitFactReconcileOnce(ctx)
	for _, v := range servedTransitVersions(t, h, token, "audit-macs") {
		if !v.Recorded {
			t.Fatalf("version %d is not recorded after a reconcile pass", v.Version)
		}
	}
	dropProjection()
	if err := projections.New(h.store).Project(ctx, h.log); err != nil {
		t.Fatalf("replay the log: %v", err)
	}
	for _, v := range servedTransitVersions(t, h, token, "audit-macs") {
		if !v.Recorded {
			t.Fatalf("version %d is not recorded after a replay", v.Version)
		}
	}
	for id, n := range countFacts() {
		if n != 1 {
			t.Fatalf("fact %s was appended %d times", id, n)
		}
	}
}
