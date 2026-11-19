// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// CR-008 (design D2, review item 9): the API checks a cloud change's writer
// binding against the IAM endpoint of the finding's source. A finding whose source
// configuration cannot be read names no endpoint to check, so the proposal is
// refused there rather than accepted on the reference alone, and nothing is
// proposed.
func TestServedCloudChangeRefusesAFindingWhoseSourceCannotBeReadCR008(t *testing.T) {
	t.Setenv("TRSTCTL_CR008_WRITER_PATH", "/var/run/trstctl/cr008-writer-session")
	h := newOperatingServedHarness(t, config.Protocols{},
		bindOutboundEnvCredentialRefs("cloud_machine_change", []string{"https://iam.amazonaws.com"}, "env:TRSTCTL_CR008_WRITER_PATH"))
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "cr008-cloud-operator", "access:write", "access:read", "discovery:read", "discovery:write", "graph:read")
	// A cloud_machine_entitlement source whose stored configuration does not
	// decode (it names no session reference), with a finding of its own.
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		now := time.Now().UTC()
		if err := h.store.ApplyDiscoverySourceUpsertedTx(t.Context(), tx, store.DiscoverySource{ID: "22222222-2222-2222-2222-22222222b001",
			TenantID: h.tenant, Kind: assessment.SourceKind, Name: "cr008-unreadable-source", Config: []byte(`{"endpoint":"https://iam.amazonaws.com"}`),
			CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		if err := h.store.ApplyDiscoveryRunQueuedTx(t.Context(), tx, store.DiscoveryRun{ID: "22222222-2222-2222-2222-22222222b002",
			TenantID: h.tenant, SourceID: "22222222-2222-2222-2222-22222222b001", Status: "queued", CreatedAt: now}); err != nil {
			return err
		}
		return h.store.ApplyDiscoveryFindingRecordedTx(t.Context(), tx, store.DiscoveryFinding{ID: "22222222-2222-2222-2222-22222222b003",
			TenantID: h.tenant, RunID: "22222222-2222-2222-2222-22222222b002", SourceID: "22222222-2222-2222-2222-22222222b001",
			Kind: assessment.SourceKind, Ref: "arn:aws:iam::111122223333:user/cr008", Provenance: "aws-iam", Fingerprint: "cr008-unreadable",
			Metadata: []byte(`{}`), DiscoveredAt: now})
	}); err != nil {
		t.Fatalf("seed the unreadable source: %v", err)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/cloud-entitlements/changes", operator, "cr008-unreadable-source", map[string]any{ // #nosec G101 -- fabricated fixture values; no value is real (CWE-798)
		"finding_id":              "22222222-2222-2222-2222-22222222b003",
		"action":                  "revoke_key",
		"access_key_id":           "AKIACR008EXAMPLEKEY0",
		"writer_session_file_ref": "env:TRSTCTL_CR008_WRITER_PATH",
		"reason":                  "CR-008: the finding's source configuration cannot be read",
		"required_approvals":      1,
	})
	if status != http.StatusBadRequest || !strings.Contains(string(body), "readable cloud_machine_entitlement source") {
		t.Fatalf("proposal against an unreadable source: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/cloud-entitlements/changes", operator, nil)
	var listed struct {
		Items []json.RawMessage `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &listed) != nil || len(listed.Items) != 0 {
		t.Fatalf("a refused proposal left a change behind: status %d body %s", status, body)
	}
}
