// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	decommission "trstctl.com/trstctl/internal/decommission"
	"trstctl.com/trstctl/internal/decommission/depstate"
	decstore "trstctl.com/trstctl/internal/decommission/store"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func TestServedCARevokedUnservedHostLeafReleaseBindsExactRevocation(t *testing.T) {
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{agentJobKindEndpointRenew}, func(d *Deps) {
		d.Store.WithExtraMigrations(decstore.MigrationsFS())
		if err := d.Store.Migrate(t.Context()); err != nil {
			t.Fatalf("VDEC migrations: %v", err)
		}
		runtime, err := decommission.NewRuntime(decommission.RuntimeConfig{Store: d.Store, Log: d.Log})
		if err != nil {
			t.Fatal(err)
		}
		d.LicensedAPIOptionsFactory = runtime.APIOptionsFactory
		d.LicensedProjectionOptions = append(d.LicensedProjectionOptions, runtime.ProjectionOptions...)
	})
	operator := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "revoked-release-operator",
		[]string{"issuers:write", "issuers:read", "certs:issue", "certs:read", "certs:revoke", "identities:write", "keys:write", "keys:read"})
	first := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "revoked-release-custodian-one",
		[]string{"issuers:write", "issuers:read"})
	second := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "revoked-release-custodian-two",
		[]string{"issuers:write", "issuers:read"})
	rootSpec := map[string]any{
		"common_name": "revoked release fixture root", "max_path_len": 1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"release.example.test"}, "signature_algorithm": "ecdsa-p256",
	}
	rootCeremony := createCACeremony(t, h.servedHarness, operator, "create_root", "", rootSpec, 1, "revoked-release-root-ceremony")
	approveCACeremony(t, h.servedHarness, first, rootCeremony.ID, 1, "revoked-release-root-approval")
	root := createRootCA(t, h.servedHarness, operator, rootCeremony.ID, rootSpec, "revoked-release-root-create")
	owner, err := h.srv.orch.CreateOwner(t.Context(), h.tenant, string(store.OwnerTeam), "Revoked release team", "release@example.test")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.srv.orch.CreateIdentity(t.Context(), h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "unserved.release.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	intent := RelayDeployIntent{Connector: "nginx", Target: "unserved-host", IdentityID: identity.ID,
		SubjectCommonName: identity.Name, SubjectDNSNames: []string{identity.Name},
		IssuingAuthoritySource: "private", IssuingAuthorityID: root.ID}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `INSERT INTO outbox
			(tenant_id,destination,payload,idempotency_key,required_agent_id) VALUES ($1,$2,$3,$4,$5)`,
			h.tenant, agentJobKindEndpointRenew, payload, "revoked-release-unserved-job", agentRowID(h.tenant, h.agent))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := h.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{Kinds: []string{agentJobKindEndpointRenew}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim unserved host job: %v %+v", err, claimed)
	}
	key, err := crypto.GenerateHostSubjectKey(identity.Name, []string{identity.Name})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := h.client.SignJobCSR(t.Context(), &transport.SignJobCSRRequest{
		JobID: claimed.Jobs[0].JobID, Attempt: claimed.Jobs[0].Attempt, CSRDER: key.CSRDER})
	key.Destroy()
	if err != nil {
		t.Fatalf("sign host-held leaf: %v", err)
	}
	cert, err := h.store.GetCertificateByFingerprint(t.Context(), h.tenant, signed.Fingerprint)
	if err != nil || cert.KeyOrigin != "host_agent" || cert.DeploymentLocation != "" || cert.LastSeenAt != nil {
		t.Fatalf("unserved host leaf custody: %+v %v", cert, err)
	}
	if err := h.srv.proj.ProjectCatchUp(t.Context(), h.log); err != nil {
		t.Fatal(err)
	}
	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/certificates/bulk-revoke", operator,
		"revoked-release-exact-revocation", map[string]any{"certificate_ids": []string{cert.ID}, "reason": "cessationOfOperation"})
	if status != http.StatusOK || !strings.Contains(string(body), `"total_revoked":1`) {
		t.Fatalf("revoke exact host leaf = %d: %s", status, body)
	}
	revoked, err := h.store.GetCertificate(t.Context(), h.tenant, cert.ID)
	if err != nil || revoked.Status != "revoked" {
		t.Fatalf("revocation readback: %+v %v", revoked, err)
	}
	request := map[string]any{"operation": "release_managed_ca_leaf", "authority_id": root.ID,
		"dependent_id": cert.ID, "expected_certificate_sha256": cert.Fingerprint,
		"reason": depstate.ReleaseReasonRevokedUnservedHostCustody, "risk_accepted": true, "threshold": 2}
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/preview", operator, "", request)
	if status != http.StatusOK || !strings.Contains(string(body), `"revocation_event_id"`) {
		t.Fatalf("review exact revoked host leaf = %d: %s", status, body)
	}
	previewCopy := strings.ToLower(string(body))
	for _, required := range []string{"revoked host-held", "exact local revocation"} {
		if !strings.Contains(previewCopy, required) {
			t.Fatalf("revoked host release preview omits %q: %s", required, body)
		}
	}
	for _, misleading := range []string{"expired managed ca leaf", "the requester held this leaf"} {
		if strings.Contains(previewCopy, misleading) {
			t.Fatalf("revoked host release preview claims %q: %s", misleading, body)
		}
	}
	request["expected_certificate_sha256"] = strings.Repeat("a", 64)
	status, _ = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/preview", operator, "", request)
	if status != http.StatusConflict {
		t.Fatalf("wrong revoked leaf digest preview = %d, want 409", status)
	}
	request["expected_certificate_sha256"] = cert.Fingerprint
	request["reason"] = depstate.ReleaseReasonExpiredRequesterCustody
	status, _ = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/preview", operator, "", request)
	if status != http.StatusConflict {
		t.Fatalf("revoked leaf accepted as expired requester = %d", status)
	}
	request["reason"] = depstate.ReleaseReasonRevokedUnservedHostCustody
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", operator,
		"revoked-release-ceremony", request)
	if status != http.StatusCreated {
		t.Fatalf("start revoked host release ceremony = %d: %s", status, body)
	}
	var ceremony servedCACeremony
	if err := json.Unmarshal(body, &ceremony); err != nil || ceremony.ID == "" {
		t.Fatalf("decode ceremony: %v %s", err, body)
	}
	approveCACeremony(t, h.servedHarness, first, ceremony.ID, 1, "revoked-release-approval-one")
	approveCACeremony(t, h.servedHarness, second, ceremony.ID, 2, "revoked-release-approval-two")
	releaseBody := map[string]any{"certificate_id": cert.ID,
		"expected_certificate_sha256": cert.Fingerprint, "ceremony_id": ceremony.ID,
		"reason": depstate.ReleaseReasonRevokedUnservedHostCustody, "risk_accepted": true}
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/keys/"+root.ID+"/dependencies/release", operator,
		"revoked-release-execute", releaseBody)
	if status != http.StatusOK || !strings.Contains(string(body), `"status":"released"`) {
		t.Fatalf("release exact revoked host leaf = %d: %s", status, body)
	}
	var receipt struct {
		ReleaseEventID string `json:"release_event_id"`
	}
	if err := json.Unmarshal(body, &receipt); err != nil || receipt.ReleaseEventID == "" {
		t.Fatalf("decode revoked release receipt: %v %s", err, body)
	}
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/keys/"+root.ID+"/dependencies/release", operator,
		"revoked-release-lost-response", releaseBody)
	if status != http.StatusOK || !strings.Contains(string(body), receipt.ReleaseEventID) {
		t.Fatalf("lost response recovery changed release = %d: %s", status, body)
	}
	state, found, err := decstore.New(h.store).FetchKeyState(t.Context(), h.tenant, root.ID)
	if err != nil || !found || len(state.Unaccounted()) != 0 {
		t.Fatalf("revoked leaf remains outstanding: %+v found=%v error=%v", state, found, err)
	}
	// The durable V3 event must be independently accepted by the signer's fold.
	var history []events.Event
	if err := h.log.Replay(t.Context(), 0, func(event events.Event) error {
		if event.TenantID == h.tenant {
			history = append(history, event)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := depstate.Fold(history); err != nil {
		t.Fatalf("signer event replay rejected approved release: %v", err)
	}
}
