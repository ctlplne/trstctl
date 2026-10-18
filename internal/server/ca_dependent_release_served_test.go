// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	decommission "trstctl.com/trstctl/internal/decommission"
	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/decommission/release"
	decstore "trstctl.com/trstctl/internal/decommission/store"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// This served test keeps the issuer, two custodians, immutable mint, VDEC
// projection, and release route in one real PostgreSQL/NATS/signer stack.
func TestServedCAExpiredRequesterLeafReleaseRequiresExactTwoCustodians(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
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
	operator := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "release-operator",
		[]string{"issuers:write", "issuers:read", "certs:issue", "keys:write", "keys:read"})
	first := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "release-custodian-one",
		[]string{"issuers:write", "issuers:read"})
	second := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "release-custodian-two",
		[]string{"issuers:write", "issuers:read"})
	rootSpec := map[string]any{
		"common_name": "release fixture root", "max_path_len": 1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"release.example.test"},
		"signature_algorithm":   "ecdsa-p256",
	}
	rootCeremony := createCACeremony(t, h, operator, "create_root", "", rootSpec, 1, "release-root-ceremony")
	approveCACeremony(t, h, first, rootCeremony.ID, 1, "release-root-approval")
	root := createRootCA(t, h, operator, rootCeremony.ID, rootSpec, "release-root-create")
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: hierarchyLeafCSR(t, "leaf.release.example.test")}))
	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/issue", operator,
		"release-leaf", map[string]any{"csr_pem": csr, "ttl_seconds": 1})
	if status != http.StatusCreated {
		t.Fatalf("issue one-second requester-held leaf = %d: %s", status, body)
	}
	var issued servedCAIssuedLeaf
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect([]byte(issued.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	var mint projections.CAEndEntityInventoried
	var mintEvent events.Event
	if err := h.log.Replay(t.Context(), 0, func(e events.Event) error {
		if e.Type == projections.EventCAEndEntityIssued && e.TenantID == h.tenant {
			mintEvent = e
			return json.Unmarshal(e.Data, &mint)
		}
		return nil
	}); err != nil || mint.ID == "" || mintEvent.ID == "" {
		t.Fatalf("read exact managed mint: event=%s certificate=%s error=%v", mintEvent.ID, mint.ID, err)
	}
	if err := h.srv.proj.ProjectCatchUp(t.Context(), h.log); err != nil {
		t.Fatalf("project VDEC dependent: %v", err)
	}
	if wait := time.Until(info.NotAfter.Add(time.Second)); wait > 0 {
		time.Sleep(wait)
	}
	request := map[string]any{
		"operation": "release_managed_ca_leaf", "authority_id": root.ID,
		"dependent_id": mint.ID, "expected_certificate_sha256": info.SHA256Fingerprint,
		"reason": depstate.ReleaseReasonExpiredRequesterCustody, "risk_accepted": true,
		"threshold": 2,
	}
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/preview", operator, "", request)
	if status != http.StatusOK || !strings.Contains(string(body), mintEvent.ID) ||
		!strings.Contains(string(body), info.SHA256Fingerprint) {
		t.Fatalf("review exact expired leaf = %d: %s", status, body)
	}
	request["expected_certificate_sha256"] = strings.Repeat("a", 64)
	status, _ = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/preview", operator, "", request)
	if status != http.StatusConflict {
		t.Fatalf("wrong leaf digest preview = %d, want 409", status)
	}
	request["expected_certificate_sha256"] = info.SHA256Fingerprint
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", operator, "release-ceremony", request)
	if status != http.StatusCreated {
		t.Fatalf("start release ceremony = %d: %s", status, body)
	}
	var ceremony servedCACeremony
	if err := json.Unmarshal(body, &ceremony); err != nil || ceremony.ID == "" {
		t.Fatalf("decode release ceremony: %v body=%s", err, body)
	}
	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/ca/ceremonies/"+ceremony.ID, first, "", nil)
	if status != http.StatusOK || !strings.Contains(string(body), mintEvent.ID) ||
		!strings.Contains(string(body), info.SHA256Fingerprint) {
		t.Fatalf("custodian readback omits exact mint or digest = %d: %s", status, body)
	}
	releaseBody := map[string]any{
		"certificate_id": mint.ID, "expected_certificate_sha256": info.SHA256Fingerprint,
		"ceremony_id": ceremony.ID, "reason": depstate.ReleaseReasonExpiredRequesterCustody,
		"risk_accepted": true,
	}
	url := "/api/v1/ca/keys/" + root.ID + "/dependencies/release"
	status, _ = doBearer(t, h.ts, http.MethodPost, url, operator, "release-before-approval", releaseBody)
	if status != http.StatusConflict {
		t.Fatalf("release before quorum = %d, want 409", status)
	}
	status, _ = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+ceremony.ID+"/approvals", operator,
		"release-self-approval", nil)
	if status != http.StatusConflict {
		t.Fatalf("operator self-approval = %d, want 409", status)
	}
	approveCACeremony(t, h, first, ceremony.ID, 1, "release-first-approval")
	approveCACeremony(t, h, second, ceremony.ID, 2, "release-second-approval")
	status, body = doBearer(t, h.ts, http.MethodPost, url, operator, "release-execute", releaseBody)
	if status != http.StatusOK || !strings.Contains(string(body), `"status":"released"`) {
		t.Fatalf("execute approved release = %d: %s", status, body)
	}
	var receipt struct {
		ReleaseEventID string `json:"release_event_id"`
	}
	if err := json.Unmarshal(body, &receipt); err != nil || receipt.ReleaseEventID == "" {
		t.Fatalf("decode release receipt: %v %s", err, body)
	}
	status, body = doBearer(t, h.ts, http.MethodPost, url, operator, "release-lost-response", releaseBody)
	if status != http.StatusOK || !strings.Contains(string(body), receipt.ReleaseEventID) {
		t.Fatalf("same exact release after lost response = %d: %s", status, body)
	}
	releaseBody["certificate_id"] = "00000000-0000-4000-8000-000000000000"
	status, _ = doBearer(t, h.ts, http.MethodPost, url, operator, "release-conflict", releaseBody)
	if status != http.StatusConflict {
		t.Fatalf("changed leaf after first-writer release = %d, want 409", status)
	}
	state, found, err := decstore.New(h.store).FetchKeyState(context.Background(), h.tenant, root.ID)
	if err != nil || !found || len(state.Unaccounted()) != 0 {
		t.Fatalf("VDEC readback still lists released leaf: state=%+v found=%t err=%v", state, found, err)
	}

	// Simulate process loss immediately after the first-writer SQL claim, before
	// broker append. The recovery pass must publish only that saved event. A
	// cancellation cannot race through while the claim is pending.
	secondCSR := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: hierarchyLeafCSR(t, "recover.release.example.test")}))
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/issue", operator,
		"release-recovery-leaf", map[string]any{"csr_pem": secondCSR, "ttl_seconds": 1})
	if status != http.StatusCreated {
		t.Fatalf("issue crash-recovery leaf = %d: %s", status, body)
	}
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatal(err)
	}
	secondInfo, err := certinfo.Inspect([]byte(issued.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.ProjectCatchUp(t.Context(), h.log); err != nil {
		t.Fatal(err)
	}
	var secondMint projections.CAEndEntityInventoried
	var secondEvent events.Event
	if err := h.log.Replay(t.Context(), mintEvent.Sequence, func(e events.Event) error {
		if e.Type == projections.EventCAEndEntityIssued && e.TenantID == h.tenant {
			secondEvent = e
			return json.Unmarshal(e.Data, &secondMint)
		}
		return nil
	}); err != nil || secondMint.ID == "" {
		t.Fatalf("read second immutable mint: event=%s certificate=%s err=%v", secondEvent.ID, secondMint.ID, err)
	}
	if wait := time.Until(secondInfo.NotAfter.Add(time.Second)); wait > 0 {
		time.Sleep(wait)
	}
	secondRequest := release.Request{CertificateID: secondMint.ID,
		ExpectedCertificateSHA256: secondInfo.SHA256Fingerprint,
		Reason:                    depstate.ReleaseReasonExpiredRequesterCustody, RiskAccepted: true}
	review, err := release.NewReviewer(h.store, h.log).Preview(t.Context(), h.tenant, root.ID, secondRequest, time.Now().UTC())
	if err != nil {
		t.Fatalf("review crash-recovery leaf: %v", err)
	}
	request["dependent_id"] = secondMint.ID
	request["expected_certificate_sha256"] = secondInfo.SHA256Fingerprint
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", operator, "release-recovery-ceremony", request)
	if status != http.StatusCreated || json.Unmarshal(body, &ceremony) != nil {
		t.Fatalf("start recovery ceremony = %d: %s", status, body)
	}
	approveCACeremony(t, h, first, ceremony.ID, 1, "release-recovery-first")
	approveCACeremony(t, h, second, ceremony.ID, 2, "release-recovery-second")
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", operator,
		"release-competing-ceremony", request)
	var competitor servedCACeremony
	if status != http.StatusCreated || json.Unmarshal(body, &competitor) != nil || competitor.ID == "" {
		t.Fatalf("start competing ceremony before first claim = %d: %s", status, body)
	}
	approveCACeremony(t, h, first, competitor.ID, 1, "release-competing-first")
	approveCACeremony(t, h, second, competitor.ID, 2, "release-competing-second")
	actor := events.Actor{Subject: "release-operator"}
	var saved events.Event
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		_, approvals, err := h.store.ValidateKeyCeremonyWithApprovalEvidenceTx(
			t.Context(), tx, h.tenant, ceremony.ID, review.Purpose())
		if err != nil {
			return err
		}
		payload := depstate.DependencyReleasedV2{
			TenantID: h.tenant, KeyID: root.ID,
			Dependent:     depstate.Dependent{Class: depstate.DependentCredential, ID: secondMint.ID},
			SourceEventID: secondEvent.ID, SourceSequence: secondEvent.Sequence,
			Serial: secondInfo.SerialNumber, CertificateSHA256: secondInfo.SHA256Fingerprint,
			CeremonyID: ceremony.ID, Actor: actor.Subject,
			Reason: depstate.ReleaseReasonExpiredRequesterCustody, RiskAccepted: true,
		}
		for _, approval := range approvals {
			payload.ApprovalEventIDs = append(payload.ApprovalEventIDs, approval.EventID)
		}
		slices.Sort(payload.ApprovalEventIDs)
		saved, err = depstate.Encode(payload)
		if err != nil {
			return err
		}
		saved.ID, saved.Time, saved.Actor = events.NewID(), time.Now().UTC().Truncate(time.Microsecond), &actor
		return h.store.ReserveCACeremonyEffectCommandTx(t.Context(), tx,
			store.CACeremonyEffectCommand{TenantID: h.tenant, CeremonyID: ceremony.ID,
				KeyID: root.ID, CertificateID: secondMint.ID, Event: saved})
	}); err != nil {
		t.Fatalf("reserve exact event before simulated crash: %v", err)
	}
	releaseBody["certificate_id"] = secondMint.ID
	releaseBody["expected_certificate_sha256"] = secondInfo.SHA256Fingerprint
	releaseBody["ceremony_id"] = competitor.ID
	status, _ = doBearer(t, h.ts, http.MethodPost, url, operator,
		"release-competing-execute", releaseBody)
	if status != http.StatusConflict {
		t.Fatalf("second ceremony executing same dependent = %d, want 409", status)
	}
	status, _ = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/preview", operator, "", request)
	if status != http.StatusConflict {
		t.Fatalf("preview after pending dependent claim = %d, want 409", status)
	}
	status, _ = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+ceremony.ID+"/cancel", operator,
		"release-recovery-cancel", map[string]any{"reason": "operator changed mind after execution began"})
	if status != http.StatusConflict {
		t.Fatalf("cancel after durable effect claim = %d, want 409", status)
	}
	healed, err := release.NewCoordinator(h.store, h.log).ReconcilePending(t.Context())
	if err != nil || healed != 1 {
		t.Fatalf("reconcile saved first-writer event: healed=%d err=%v", healed, err)
	}
	releaseBody["certificate_id"] = secondMint.ID
	releaseBody["expected_certificate_sha256"] = secondInfo.SHA256Fingerprint
	releaseBody["ceremony_id"] = ceremony.ID
	status, body = doBearer(t, h.ts, http.MethodPost, url, operator, "release-recovery-readback", releaseBody)
	if status != http.StatusOK || !strings.Contains(string(body), saved.ID) {
		t.Fatalf("recovered release returned different event = %d: %s", status, body)
	}
	state, found, err = decstore.New(h.store).FetchKeyState(t.Context(), h.tenant, root.ID)
	if err != nil || !found || len(state.Unaccounted()) != 0 {
		t.Fatalf("recovered dependent not accounted: state=%+v found=%t err=%v", state, found, err)
	}
}
