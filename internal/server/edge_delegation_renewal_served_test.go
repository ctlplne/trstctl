// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

// A220: a host renews its delegated edge CA over the agent channel with a
// fresh TPM attestation over a new CSR for the same key, inside the renewal
// window, where the segment's operator allowed it. The renewed delegation
// keeps the key, names the one it renewed and gets the same lifetime. Renewal
// off, a stale or unrooted attestation, a second renewal of the old
// delegation, a delegation outside the window and another host's delegation
// are each refused, and the delegation is left to expire.
func TestServedEdgeDelegationRenewsWithFreshAttestation(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost})
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "edge-test", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "edge-operator", []string{"issuers:write", "issuers:read", "certs:issue"})
	approverOne := seedServedAPIToken(t, ctx, h.store, h.tenant, "custodian-one", []string{"issuers:write", "issuers:read"})
	approverTwo := seedServedAPIToken(t, ctx, h.store, h.tenant, "custodian-two", []string{"issuers:write", "issuers:read"})
	rootSpec := map[string]any{
		"common_name": "edge renewal parent", "max_path_len": 1,
		"ttl_seconds":           int64((90 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"example.test"}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h.servedHarness, operator, "create_root", "", rootSpec, 2, "renew-root-ceremony")
	approveCACeremony(t, h.servedHarness, approverOne, ceremony.ID, 1, "renew-root-approve-1")
	approveCACeremony(t, h.servedHarness, approverTwo, ceremony.ID, 2, "renew-root-approve-2")
	root := createRootCA(t, h.servedHarness, operator, ceremony.ID, rootSpec, "renew-root-create")
	segment, err := h.store.UpsertDiscoverySegment(ctx, h.tenant, store.DiscoverySegment{Name: "edge-renewal", Ranges: []string{"10.9.2.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceattesttest.NewTPMIdentity(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	setPolicy := func(renewal bool, idem string) {
		t.Helper()
		code, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/edge/segments/"+segment.ID, operator, idem, map[string]any{
			"enabled": true, "attestation_roots_pem": []string{string(identity.RootPEM())},
			"permitted_dns_domains": []string{"edge.example.test"}, "renewal_enabled": renewal,
		})
		if code != http.StatusOK {
			t.Fatalf("set policy = %d %s", code, body)
		}
		var policy struct {
			RenewalEnabled    bool `json:"renewal_enabled"`
			RenewalWindowDays int  `json:"renewal_window_days"`
		}
		if err := json.Unmarshal(body, &policy); err != nil || policy.RenewalEnabled != renewal || policy.RenewalWindowDays != 7 {
			t.Fatalf("policy = %s (%v); want renewal %v with the 7-day window", body, err, renewal)
		}
	}
	setPolicy(false, "renew-policy-off")

	provider := identity.EdgeCAKeyProvider()
	handle, csrDER, err := crypto.GenerateEdgeCAKeyHandleAndCSR(ctx, "renew-generation-1", "renew edge CA", crypto.ECDSAP256, provider)
	if err != nil {
		t.Fatal(err)
	}
	mint := func(host string, ttl time.Duration, idem string) (id, serial string, notAfter time.Time) {
		t.Helper()
		credential, err := identity.CredentialJSON(crypto.EdgeAttestationChallenge(h.tenant, segment.ID, csrDER))
		if err != nil {
			t.Fatal(err)
		}
		code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations", operator, idem, map[string]any{
			"segment_id": segment.ID, "ca_id": root.ID, "host": host, "common_name": "renew edge CA",
			"ttl_seconds": int(ttl.Seconds()), "csr_der": csrDER, "attestation_credential_json": credential,
		})
		if code != http.StatusCreated {
			t.Fatalf("mint = %d %s", code, body)
		}
		var minted struct {
			ID       string    `json:"id"`
			Serial   string    `json:"serial"`
			NotAfter time.Time `json:"not_after"`
		}
		if err := json.Unmarshal(body, &minted); err != nil {
			t.Fatal(err)
		}
		return minted.ID, minted.Serial, minted.NotAfter
	}
	oldID, oldSerial, oldNotAfter := mint(h.agent, 3*24*time.Hour, "renew-mint")

	renewalCSR, err := crypto.EdgeCSRForKeyHandle(ctx, handle, provider, "renew edge CA")
	if err != nil {
		t.Fatal(err)
	}
	freshCredential, err := identity.CredentialJSON(crypto.EdgeAttestationChallenge(h.tenant, segment.ID, renewalCSR))
	if err != nil {
		t.Fatal(err)
	}
	renew := func(serial string, csr, credential []byte) (*transport.EdgeRenewalResponse, error) {
		return h.client.RenewEdgeDelegation(ctx, &transport.EdgeRenewalRequest{Serial: serial, CSRDER: csr, AttestationCredentialJSON: credential})
	}
	if _, err := renew(oldSerial, renewalCSR, freshCredential); status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "does not let hosts renew") {
		t.Fatalf("renewal with the policy off = %v; want PermissionDenied", err)
	}
	setPolicy(true, "renew-policy-on")

	// A credential over the MINT's CSR does not vouch for the renewal CSR, and
	// one from a TPM the segment did not pin is refused: the delegation is
	// left to expire.
	staleCredential, err := identity.CredentialJSON(crypto.EdgeAttestationChallenge(h.tenant, segment.ID, csrDER))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := renew(oldSerial, renewalCSR, staleCredential); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a stale attestation = %v; want PermissionDenied", err)
	}
	stranger, err := deviceattesttest.NewTPMIdentity(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	strangerCredential, err := stranger.CredentialJSON(crypto.EdgeAttestationChallenge(h.tenant, segment.ID, renewalCSR))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := renew(oldSerial, renewalCSR, strangerCredential); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an unrooted attestation = %v; want PermissionDenied", err)
	}

	renewed, err := renew(oldSerial, renewalCSR, freshCredential)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if renewed.DelegationID == "" || renewed.DelegationID == oldID || normalizeEdgeSerial(renewed.Serial) == normalizeEdgeSerial(oldSerial) ||
		renewed.NotAfter.Before(oldNotAfter) || !strings.Contains(renewed.CertificatePEM, "BEGIN CERTIFICATE") {
		t.Fatalf("renewed = %+v; want a new delegation expiring no earlier, with its chain", renewed)
	}
	if lifetime := time.Until(renewed.NotAfter); lifetime > 3*24*time.Hour+time.Hour || lifetime < 3*24*time.Hour-2*time.Hour {
		t.Fatalf("renewed lifetime %s; want the old delegation's three days", lifetime)
	}
	type delegationView struct {
		Delegation struct {
			ID           string `json:"id"`
			CSRKeySHA256 string `json:"csr_key_sha256"`
			AttestedKey  string `json:"attested_key_sha256"`
			RenewedFrom  string `json:"renewed_from"`
			RenewedBy    string `json:"renewed_by"`
			Status       string `json:"status"`
		} `json:"delegation"`
	}
	read := func(id string) delegationView {
		t.Helper()
		code, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/edge/delegations/"+id, operator, "", nil)
		if code != http.StatusOK {
			t.Fatalf("read %s = %d %s", id, code, body)
		}
		var view delegationView
		if err := json.Unmarshal(body, &view); err != nil {
			t.Fatal(err)
		}
		return view
	}
	oldView, newView := read(oldID), read(renewed.DelegationID)
	if newView.Delegation.RenewedFrom != oldID || oldView.Delegation.RenewedBy != renewed.DelegationID || oldView.Delegation.Status != "active" {
		t.Fatalf("old %+v / new %+v; want the renewal linked both ways and the old one still active", oldView.Delegation, newView.Delegation)
	}
	if newView.Delegation.CSRKeySHA256 != oldView.Delegation.CSRKeySHA256 || newView.Delegation.AttestedKey != oldView.Delegation.AttestedKey {
		t.Fatalf("the renewal changed the delegated CA key: old %+v new %+v", oldView.Delegation, newView.Delegation)
	}
	if _, err := renew(oldSerial, renewalCSR, freshCredential); status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "already renewed") {
		t.Fatalf("renewing the old delegation again = %v; want PermissionDenied", err)
	}

	// Outside the window, and another host's delegation.
	_, farSerial, _ := mint(h.agent, 20*24*time.Hour, "renew-mint-far")
	if _, err := renew(farSerial, renewalCSR, freshCredential); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "may renew from") {
		t.Fatalf("a renewal before the window opens = %v; want FailedPrecondition", err)
	}
	_, otherSerial, _ := mint("some-other-host", 3*24*time.Hour, "renew-mint-other")
	if _, err := renew(otherSerial, renewalCSR, freshCredential); status.Code(err) != codes.NotFound {
		t.Fatalf("renewing another host's delegation = %v; want NotFound", err)
	}
}
