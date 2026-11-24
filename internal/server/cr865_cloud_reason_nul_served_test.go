// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/config"
)

// VL-170 (VH72-N1): can an ordinary tenant principal put a NUL byte into a cloud
// machine change's propose reason so that the appended approval-request event cannot
// be projected (append-then-apply split, the CR-359 class)?
func TestCR865CloudChangeProposeReasonNULCannotPoisonProjectionReplay(t *testing.T) {
	ctx := t.Context()
	h := newOperatingServedHarness(t, config.Protocols{},
		bindOutboundEnvCredentialRefs(assessment.SourceKind, []string{"https://iam.amazonaws.com"}, "env:VL170_READER"),
		bindOutboundEnvCredentialRefs("cloud_machine_change", []string{"https://iam.amazonaws.com"}, "env:VL170_WRITER"))
	second := uuid.NewString()
	registerServedTenantID(t, h, second, "VL170 victim tenant")
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "cloud-operator", "access:write", "access:read", "discovery:read", "discovery:write", "graph:read", "approvals:review", "access:approve", string(authz.PrivateEgress))

	arn := "arn:aws:iam::000000000000:user/vl170"
	cfg := assessment.SourceConfig{SessionFileRef: "env:VL170_READER", Principals: []awsiam.Selection{{Kind: awspolicy.IAMUser, Name: "vl170"}}, Input: assessment.Input{Checks: []assessment.Check{{PrincipalARN: arn, Action: "s3:GetObject", Resource: "arn:aws:s3:::vl170/object", ResourceAccountID: "000000000000"}}}}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", operator, "vl170-source", map[string]any{"kind": assessment.SourceKind, "name": "vl170 source", "config": cfg})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil {
		t.Fatalf("source create: %d %s", status, body)
	}
	stored, err := h.store.GetDiscoverySource(ctx, h.tenant, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := assessment.DecodeSource(stored.Config)
	if err != nil {
		t.Fatal(err)
	}
	sourceFP, err := assessment.SourceFingerprint(decoded)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	value := assessment.Assessment{SourceOrigin: "https://iam.amazonaws.com", SourceFingerprint: sourceFP, CapturedInput: decoded.Input, InputSHA256: "vl170", Version: 1, Provider: "aws-iam", CollectedAt: now,
		Identity: awsiam.Identity{NativeID: "AIDAVL170", Name: "vl170", Principal: awspolicy.Principal{Kind: awspolicy.IAMUser, ARN: arn, AccountID: "000000000000"}, Keys: []awsiam.Key{{ID: "AKIAVL170000000001", Status: "Active", Created: now}}}}
	fp, err := assessment.Fingerprint(value)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	runID, findingID := uuid.NewString(), uuid.NewString()
	if _, err := h.store.SystemPool().Exec(ctx, `INSERT INTO discovery_runs (id,tenant_id,source_id,status,created_at) VALUES ($1,$2,$3,'succeeded',$4)`, runID, h.tenant, source.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.SystemPool().Exec(ctx, `INSERT INTO discovery_findings (id,tenant_id,run_id,source_id,kind,ref,provenance,fingerprint,metadata,discovered_at) VALUES ($1,$2,$3,$4,$5,$6,'vl170',$7,$8,$9)`, findingID, h.tenant, runID, source.ID, assessment.FindingKind, arn, fp, meta, now); err != nil {
		t.Fatal(err)
	}
	propose := func(key, reason string) (int, []byte) {
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/cloud-entitlements/changes", operator, key, map[string]any{"finding_id": findingID, "action": "revoke_key", "access_key_id": "AKIAVL170000000001", "writer_session_file_ref": "env:VL170_WRITER", "reason": reason, "required_approvals": 1})
	}
	// Control: the same request with a clean reason is accepted, so the fixture is valid.
	if status, body := propose("vl170-clean", "Retire the exact unused fixture key"); status != http.StatusCreated {
		t.Fatalf("control proposal refused: %d %s", status, body)
	}
	// Attack: the same request whose reason carries a JSON-escaped NUL byte.
	status, body = propose("vl170-nul", "retire key\u0000 now")
	t.Logf("VL170 proposal with NUL reason: status=%d body=%s", status, strings.TrimSpace(string(body)))
	if status < http.StatusBadRequest || status >= http.StatusInternalServerError {
		t.Errorf("NUL-bearing proposal status = %d, want a client refusal", status)
	}
	// Does the platform notice? Poll /readyz (projection tail) for a while.
	var readyStatus int
	var readyBody string
	for i := 0; i < 25; i++ {
		resp, err := http.Get(h.ts.URL + "/readyz")
		if err == nil {
			raw, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			readyStatus, readyBody = resp.StatusCode, string(raw)
			if readyStatus != http.StatusOK {
				break
			}
		}
		time.Sleep(time.Second)
	}
	t.Logf("VL170 /readyz after the NUL proposal: %d %.200s", readyStatus, readyBody)
	if readyStatus != http.StatusOK {
		t.Errorf("one tenant's rejected NUL proposal disabled readiness for all tenants: %d", readyStatus)
	}
	h.ts.Close()
	restarted, err := Build(ctx, Deps{Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz, CACertFile: h.caFile, Protocols: config.Protocols{}})
	if err != nil {
		t.Errorf("VL170: restart Build failed for every tenant after one tenant's NUL-bearing proposal (status %d): %v", status, err)
		return
	}
	cleanupServedServer(t, restarted)
}
