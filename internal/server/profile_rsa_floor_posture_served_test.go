// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
)

// Owner decision (batch 14): an unset min_rsa_bits means 2048, and a profile
// that sets a lower floor explicitly raises a posture finding. The finding
// names the profile, its version and the floor; a later version at or above
// the default resolves it, and lowering the floor again reopens it.
func TestServedProfileRSAFloorBelowDefaultRaisesAFinding(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	token := seedScopedToken(t, h.store, h.tenant, "profiles:read", "profiles:write")
	version := 0
	create := func(spec map[string]any) {
		t.Helper()
		version++
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/profiles", token, "legacy-rsa-"+strconv.Itoa(version),
			map[string]any{"name": "legacy-rsa", "spec": spec})
		if status != http.StatusCreated {
			t.Fatalf("create profile version %d = %d: %s", version, status, body)
		}
	}
	type finding struct {
		Status, Provenance, EvidenceRef string
		Meta                            struct {
			Profile string `json:"profile"`
			Version int    `json:"version"`
			Floor   int    `json:"min_rsa_bits"`
			Default int    `json:"default_min_rsa_bits"`
		}
		Count int
	}
	read := func() finding {
		t.Helper()
		var f finding
		var meta []byte
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM discovery_findings WHERE tenant_id = $1 AND kind = $2`,
				h.tenant, orchestrator.ProfileRSAFloorFindingKind).Scan(&f.Count); err != nil || f.Count == 0 {
				return err
			}
			return tx.QueryRow(ctx, `SELECT triage_status, provenance, triage_evidence_ref, metadata FROM discovery_findings
				WHERE tenant_id = $1 AND kind = $2`, h.tenant, orchestrator.ProfileRSAFloorFindingKind).
				Scan(&f.Status, &f.Provenance, &f.EvidenceRef, &meta)
		}); err != nil {
			t.Fatal(err)
		}
		if f.Count == 1 {
			if err := json.Unmarshal(meta, &f.Meta); err != nil {
				t.Fatal(err)
			}
		}
		return f
	}

	// An unset floor is the 2048-bit default: nothing to report.
	create(map[string]any{"allowed_key_algorithms": []string{"RSA"}, "max_validity": "2160h"})
	if f := read(); f.Count != 0 {
		t.Fatalf("an unset floor raised a finding: %+v", f)
	}
	// An explicit floor below the default raises one, naming version and value.
	create(map[string]any{"allowed_key_algorithms": []string{"RSA"}, "min_rsa_bits": 1024, "max_validity": "2160h"})
	f := read()
	if f.Count != 1 || f.Status != "unmanaged" || f.Provenance != "profile:legacy-rsa@v2" ||
		f.Meta.Profile != "legacy-rsa" || f.Meta.Version != 2 || f.Meta.Floor != 1024 || f.Meta.Default != 2048 {
		t.Fatalf("the floor below the default is not reported by name, version and value: %+v", f)
	}
	// A version at or above the default resolves it as remediated, with evidence.
	create(map[string]any{"allowed_key_algorithms": []string{"RSA"}, "min_rsa_bits": 3072, "max_validity": "2160h"})
	if f := read(); f.Count != 1 || f.Status != "remediated" || f.EvidenceRef != "profile:legacy-rsa@v3" {
		t.Fatalf("raising the floor did not resolve the finding: %+v", f)
	}
	// Lowering it again reopens the same finding for the new version.
	create(map[string]any{"allowed_key_algorithms": []string{"RSA"}, "min_rsa_bits": 1536, "max_validity": "2160h"})
	if f := read(); f.Count != 1 || f.Status != "unmanaged" || f.Provenance != "profile:legacy-rsa@v4" || f.Meta.Floor != 1536 {
		t.Fatalf("lowering the floor again did not reopen the finding: %+v", f)
	}
	// The sweep converges on the same state without new events.
	before, err := h.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := h.srv.orch.ReconcileProfileRSAFloorPosture(ctx, h.tenant); err != nil || n != 0 {
		t.Fatalf("a converged tenant's sweep changed %d findings: %v", n, err)
	}
	if after, err := h.log.LastSequence(ctx); err != nil || after != before {
		t.Fatalf("a converged sweep appended events: %d -> %d (%v)", before, after, err)
	}
	// Restoring the compliant version is a new active version: resolved again.
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/profiles/legacy-rsa/versions/3/restore", token, "legacy-rsa-restore",
		map[string]any{"expected_active_version": 4, "reason": "back to the 3072-bit floor"})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("restore the compliant version = %d: %s", status, body)
	}
	if f := read(); f.Status != "remediated" || f.EvidenceRef != "profile:legacy-rsa@v5" {
		t.Fatalf("restoring the compliant version did not resolve the finding: %+v", f)
	}
}
