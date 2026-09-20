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
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
	"trstctl.com/trstctl/internal/crypto/edgetest"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

// B6's three acceptance bullets against the served binary: an attested no-path
// host receives a name-constrained, short-lived delegated CA minted by the
// isolated signer; issues locally within those constraints and FAILS CLOSED
// outside them; the delegation is revocable from the brain (riding the parent
// CA's issued ledger, so OCSP/CRL answer for it); and local issuances
// reconcile back with violations recorded rather than hidden. Default-off is
// exercised as refusals: an un-opted segment and an un-attested host get
// nothing.
func TestServedEdgeDelegationEndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	ctx := context.Background()
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "edge-operator", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approverOne := seedServedAPIToken(t, ctx, h.store, h.tenant, "custodian-one", []string{"issuers:write", "issuers:read"})
	approverTwo := seedServedAPIToken(t, ctx, h.store, h.tenant, "custodian-two", []string{"issuers:write", "issuers:read"})

	// A signer-backed parent CA through the real ceremony flow.
	rootSpec := map[string]any{
		"common_name":           "trstctl edge parent",
		"max_path_len":          1,
		"ttl_seconds":           int64((90 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"example.test"},
		"extended_key_usages":   []string{"serverAuth"},
		"signature_algorithm":   "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, operator, "create_root", "", rootSpec, 2, "edge-root-ceremony")
	approveCACeremony(t, h, approverOne, ceremony.ID, 1, "edge-root-approve-1")
	approveCACeremony(t, h, approverTwo, ceremony.ID, 2, "edge-root-approve-2")
	root := createRootCA(t, h, operator, ceremony.ID, rootSpec, "edge-root-create")

	// Two declared segments: one will opt in, one stays default-off.
	segment, err := h.store.UpsertDiscoverySegment(ctx, h.tenant, store.DiscoverySegment{
		Name: "edge-lab", Ranges: []string{"10.9.0.0/24"},
	})
	if err != nil {
		t.Fatalf("declare segment: %v", err)
	}
	coldSegment, err := h.store.UpsertDiscoverySegment(ctx, h.tenant, store.DiscoverySegment{
		Name: "edge-cold", Ranges: []string{"10.9.1.0/24"},
	})
	if err != nil {
		t.Fatalf("declare cold segment: %v", err)
	}

	// The edge host: a TPM fixture whose CSR is over the attested key.
	now := time.Now().UTC()
	identity, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatalf("TPM fixture: %v", err)
	}
	// Drive the same opaque-handle CSR primitive the shipping agent calls. The
	// fixture provider uses the exact credential key its WebAuthn TPM evidence
	// attests, closing the former test gap where served mint bypassed edge-csr.
	edgeProvider := identity.EdgeCAKeyProvider()
	edgeHandle, csrDER, err := crypto.GenerateEdgeCAKeyHandleAndCSR(
		ctx, "served-edge-generation-1", "bunker-01 edge CA", crypto.ECDSAP256, edgeProvider,
	)
	if err != nil {
		t.Fatalf("shipping handle CSR path: %v", err)
	}
	challenge := crypto.EdgeAttestationChallenge(h.tenant, segment.ID, csrDER)
	credentialJSON, err := identity.CredentialJSON(challenge)
	if err != nil {
		t.Fatalf("TPM credential: %v", err)
	}

	// Enabling without attestation roots is refused: the opt-in IS the
	// declaration, and without a root any key that asks would be vouched for.
	code, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/edge/segments/"+segment.ID, operator, "edge-policy-noroots", map[string]any{
		"enabled":               true,
		"permitted_dns_domains": []string{"edge.example.test"},
	})
	if code != http.StatusBadRequest || !strings.Contains(string(body), "attestation root") {
		t.Fatalf("enable without roots = %d body=%s; want 400 naming the missing roots", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodPut, "/api/v1/edge/segments/"+segment.ID, operator, "edge-policy-set", map[string]any{
		"enabled":               true,
		"attestation_roots_pem": []string{string(identity.RootPEM())},
		"permitted_dns_domains": []string{"edge.example.test"},
		"excluded_dns_domains":  []string{"blocked.edge.example.test"},
	})
	if code != http.StatusOK {
		t.Fatalf("enable segment = %d body=%s", code, body)
	}

	mintBody := func(segmentID string, attestation []byte) map[string]any {
		out := map[string]any{
			"segment_id":  segmentID,
			"ca_id":       root.ID,
			"host":        "bunker-01",
			"common_name": "bunker-01 edge CA",
			"ttl_seconds": 3600,
			"csr_der":     csrDER,
		}
		if attestation != nil {
			out["attestation_credential_json"] = attestation
		}
		return out
	}

	// Default-off and the attestation gate, as refusals.
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations", operator, "edge-mint-cold", mintBody(coldSegment.ID, credentialJSON))
	if code != http.StatusForbidden || !strings.Contains(string(body), "not opted in") {
		t.Fatalf("mint for un-opted segment = %d body=%s; want 403 naming the missing opt-in", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations", operator, "edge-mint-unattested", mintBody(segment.ID, nil))
	if code != http.StatusForbidden || !strings.Contains(string(body), "un-attested") {
		t.Fatalf("un-attested mint = %d body=%s; want 403.\n\nAn un-attested host receiving a "+
			"delegated CA is the acceptance's exact counterexample.", code, body)
	}
	// A valid TPM attestation over a DIFFERENT key than the CSR's is refused:
	// the TPM must vouch for the key being delegated, not merely exist.
	_, otherCSR, err := crypto.GenerateEdgeCAKeyAndCSR("other edge CA")
	if err != nil {
		t.Fatalf("other CSR: %v", err)
	}
	otherChallenge := crypto.EdgeAttestationChallenge(h.tenant, segment.ID, otherCSR)
	mismatchedCredential, err := identity.CredentialJSON(otherChallenge)
	if err != nil {
		t.Fatalf("mismatched credential: %v", err)
	}
	mismatch := mintBody(segment.ID, mismatchedCredential)
	mismatch["csr_der"] = otherCSR
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations", operator, "edge-mint-mismatch", mismatch)
	if code != http.StatusForbidden || !strings.Contains(string(body), "not the CSR's key") {
		t.Fatalf("key-mismatch mint = %d body=%s; want 403.\n\nA TPM vouching for one key must not "+
			"license delegating a different one — that gap would let a software key ride any "+
			"hardware attestation on the host.", code, body)
	}
	// A valid host TPM is not permission to hide an EXPORTABLE software CA key.
	// The provider is policy-bound first; the default policy allows only TPM2.
	softwareMint := mintBody(segment.ID, mismatchedCredential)
	softwareMint["csr_der"] = otherCSR
	softwareMint["key_provider"] = "software"
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations", operator, "edge-mint-software-default-refused", softwareMint)
	if code != http.StatusForbidden || !strings.Contains(string(body), "software") || !strings.Contains(string(body), "policy") {
		t.Fatalf("default software custody = %d body=%s; want an explicit policy refusal", code, body)
	}

	// The operator may declare a software disaster-recovery exception, but the
	// evidence must say FILE + EXPORTABLE + SOFTWARE_EXCEPTION. The host TPM
	// still proves which enrolled machine submitted the CSR; it does not get
	// mislabeled as attesting the unrelated software key.
	code, body = doBearer(t, h.ts, http.MethodPut, "/api/v1/edge/segments/"+segment.ID, operator, "edge-policy-software-exception", map[string]any{
		"enabled":               true,
		"attestation_roots_pem": []string{string(identity.RootPEM())},
		"permitted_dns_domains": []string{"edge.example.test"},
		"excluded_dns_domains":  []string{"blocked.edge.example.test"},
		"allowed_key_providers": []string{"tpm2", "software", "pkcs11"},
	})
	if code != http.StatusOK {
		t.Fatalf("declare custody exceptions = %d body=%s", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations", operator, "edge-mint-software-exception", softwareMint)
	if code != http.StatusCreated {
		t.Fatalf("explicit software exception mint = %d body=%s", code, body)
	}
	var softwareEvidence struct {
		KeyProvider       string `json:"key_provider"`
		KeyStorage        string `json:"key_storage"`
		KeyExportable     bool   `json:"key_exportable"`
		CustodyAssurance  string `json:"custody_assurance"`
		CSRKeySHA256      string `json:"csr_key_sha256"`
		AttestedKeySHA256 string `json:"attested_key_sha256"`
	}
	if err := json.Unmarshal(body, &softwareEvidence); err != nil {
		t.Fatal(err)
	}
	if softwareEvidence.KeyProvider != "software" || softwareEvidence.KeyStorage != "file" ||
		!softwareEvidence.KeyExportable || softwareEvidence.CustodyAssurance != "host_attested_software_exception" ||
		softwareEvidence.CSRKeySHA256 == "" || softwareEvidence.CSRKeySHA256 == softwareEvidence.AttestedKeySHA256 {
		t.Fatalf("dishonest software custody evidence: %+v", softwareEvidence)
	}

	pkcs11Mint := mintBody(segment.ID, mismatchedCredential)
	pkcs11Mint["csr_der"] = otherCSR
	pkcs11Mint["key_provider"] = "pkcs11"
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations", operator, "edge-mint-pkcs11", pkcs11Mint)
	if code != http.StatusCreated {
		t.Fatalf("policy-approved PKCS#11 mint = %d body=%s", code, body)
	}
	var tokenEvidence struct {
		KeyProvider      string `json:"key_provider"`
		KeyStorage       string `json:"key_storage"`
		KeyExportable    bool   `json:"key_exportable"`
		CustodyAssurance string `json:"custody_assurance"`
	}
	if err := json.Unmarshal(body, &tokenEvidence); err != nil {
		t.Fatal(err)
	}
	if tokenEvidence.KeyProvider != "pkcs11" || tokenEvidence.KeyStorage != "pkcs11" ||
		tokenEvidence.KeyExportable || tokenEvidence.CustodyAssurance != "host_attested_operator_claim" {
		t.Fatalf("dishonest PKCS#11 custody evidence: %+v", tokenEvidence)
	}
	// A TTL past the 30-day ceiling is refused, not clamped.
	long := mintBody(segment.ID, credentialJSON)
	long["ttl_seconds"] = int((45 * 24 * time.Hour).Seconds())
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations", operator, "edge-mint-long", long)
	if code != http.StatusBadRequest || !strings.Contains(string(body), "ceiling") {
		t.Fatalf("45-day mint = %d body=%s; want 400 naming the ceiling", code, body)
	}

	// The real mint.
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations", operator, "edge-mint", mintBody(segment.ID, credentialJSON))
	if code != http.StatusCreated {
		t.Fatalf("mint = %d body=%s", code, body)
	}
	var minted struct {
		ID                  string    `json:"id"`
		Serial              string    `json:"serial"`
		Status              string    `json:"status"`
		CertificatePEM      string    `json:"certificate_pem"`
		PermittedDNSDomains []string  `json:"permitted_dns_domains"`
		ExcludedDNSDomains  []string  `json:"excluded_dns_domains"`
		NotAfter            time.Time `json:"not_after"`
		KeyProvider         string    `json:"key_provider"`
		KeyStorage          string    `json:"key_storage"`
		KeyExportable       bool      `json:"key_exportable"`
		CustodyAssurance    string    `json:"custody_assurance"`
	}
	if err := json.Unmarshal(body, &minted); err != nil || minted.ID == "" {
		t.Fatalf("decode mint: %v body=%s", err, body)
	}
	if len(minted.PermittedDNSDomains) != 1 || minted.PermittedDNSDomains[0] != "edge.example.test" {
		t.Fatalf("minted constraints = %v, want the SEGMENT POLICY's, not the request's", minted.PermittedDNSDomains)
	}
	if minted.KeyProvider != "tpm2" || minted.KeyStorage != "device_bound" || minted.KeyExportable || minted.CustodyAssurance != "hardware_key_attested" {
		t.Fatalf("TPM custody evidence = %+v, want a non-exportable same-key attestation", minted)
	}
	if until := time.Until(minted.NotAfter); until > 2*time.Hour {
		t.Fatalf("delegation lives %s, want the requested hour: auto-expiry is the bound", until)
	}
	// The delegated CA's serial is in the PARENT's issued ledger: OCSP answers
	// for it and revocation will ride the existing CRL machinery.
	if _, found, err := h.store.LookupIssuedCert(ctx, h.tenant, root.ID, minted.Serial); err != nil || !found {
		t.Fatalf("delegation serial in parent ledger: found=%v err=%v", found, err)
	}

	// Local issuance on the "host": in-constraint works, out-of-constraint and
	// excluded names FAIL CLOSED, enforced from the certificate itself.
	delegationPEM := []byte(minted.CertificatePEM)
	goodLeaf, err := crypto.IssueEdgeLeafWithKeyHandle(ctx, delegationPEM, edgeHandle, edgeProvider, crypto.EdgeLeafRequest{
		CommonName: "db.edge.example.test", TTL: 30 * time.Minute,
	}, now)
	if err != nil {
		t.Fatalf("in-constraint local issue: %v", err)
	}
	if _, err := crypto.IssueEdgeLeafWithKeyHandle(ctx, delegationPEM, edgeHandle, edgeProvider, crypto.EdgeLeafRequest{
		CommonName: "evil.other.example.test",
	}, now); err == nil {
		t.Fatal("out-of-constraint local issue succeeded; the acceptance requires it to fail closed")
	}
	if _, err := crypto.IssueEdgeLeafWithKeyHandle(ctx, delegationPEM, edgeHandle, edgeProvider, crypto.EdgeLeafRequest{
		CommonName: "x.blocked.edge.example.test",
	}, now); err == nil {
		t.Fatal("excluded-subtree local issue succeeded; exclusion must beat permission")
	}

	// Reconcile the journal. A leaf from a FOREIGN CA is rejected (it is not
	// this delegation's issuance); re-reporting is idempotent by serial.
	foreignLeaf, err := edgetest.ForeignLeaf("db.edge.example.test")
	if err != nil {
		t.Fatalf("foreign leaf fixture: %v", err)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations/"+minted.ID+"/reconcile", operator, "edge-reconcile-1", map[string]any{
		"host":             "bunker-01",
		"certificates_pem": []string{string(goodLeaf.CertificatePEM), foreignLeaf},
	})
	if code != http.StatusOK {
		t.Fatalf("reconcile = %d body=%s", code, body)
	}
	var recon struct {
		Reconciled int `json:"reconciled"`
		Violations int `json:"violations"`
		Already    int `json:"already"`
		Rejected   int `json:"rejected"`
	}
	if err := json.Unmarshal(body, &recon); err != nil {
		t.Fatalf("decode reconcile: %v", err)
	}
	if recon.Reconciled != 1 || recon.Rejected != 1 || recon.Violations != 0 {
		t.Fatalf("reconcile counts = %+v, want 1 reconciled and the foreign leaf rejected", recon)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations/"+minted.ID+"/reconcile", operator, "edge-reconcile-2", map[string]any{
		"certificates_pem": []string{string(goodLeaf.CertificatePEM)},
	})
	if code != http.StatusOK {
		t.Fatalf("re-reconcile = %d body=%s", code, body)
	}
	if err := json.Unmarshal(body, &recon); err != nil || recon.Already != 1 || recon.Reconciled != 0 {
		t.Fatalf("re-reconcile counts = %+v err=%v, want the duplicate counted, not re-recorded", recon, err)
	}
	// The reconciled leaf is now in the certificate inventory — no shadow
	// issuance invisible to the estate.
	invRows, err := h.store.ListCertificatesPage(ctx, h.tenant, store.ZeroUUID, nil, 500, nil)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	foundLeaf := false
	for _, row := range invRows {
		if row.Serial == goodLeaf.SerialHex && row.Source == "edge-delegation" {
			foundLeaf = true
		}
	}
	if !foundLeaf {
		t.Fatal("reconciled edge leaf missing from the certificate inventory")
	}

	// A leaf signed by the DELEGATED KEY outside the constraints — the host's
	// tooling bypassed, the certificate real. The report is recorded AS A
	// VIOLATION, visibly, never silently dropped and never silently accepted.
	hostKeyPEM, err := identity.CredentialKeyPEM()
	if err != nil {
		t.Fatalf("fixture-only rogue key export: %v", err)
	}
	defer secret.Wipe(hostKeyPEM)
	rogue, err := edgetest.RogueLeaf(delegationPEM, hostKeyPEM, "evil.other.example.test")
	if err != nil {
		t.Fatalf("rogue leaf fixture: %v", err)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations/"+minted.ID+"/reconcile", operator, "edge-reconcile-3", map[string]any{
		"certificates_pem": []string{rogue},
	})
	if code != http.StatusOK {
		t.Fatalf("violation reconcile = %d body=%s", code, body)
	}
	if err := json.Unmarshal(body, &recon); err != nil || recon.Violations != 1 {
		t.Fatalf("violation counts = %+v err=%v, want the rogue leaf recorded as a violation", recon, err)
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/edge/delegations/"+minted.ID, operator, "", nil)
	if code != http.StatusOK {
		t.Fatalf("get delegation = %d", code)
	}
	var detail struct {
		Issuances []struct {
			Serial            string `json:"serial"`
			WithinConstraints bool   `json:"within_constraints"`
			Violation         string `json:"violation"`
		} `json:"issuances"`
	}
	if err := json.Unmarshal(body, &detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	violations := 0
	for _, issuance := range detail.Issuances {
		if !issuance.WithinConstraints {
			violations++
			if issuance.Violation == "" {
				t.Fatal("violation row carries no reason")
			}
		}
	}
	if len(detail.Issuances) != 2 || violations != 1 {
		t.Fatalf("detail issuances = %+v, want the good leaf and one flagged violation", detail.Issuances)
	}

	// Revocation from the brain: the delegation flips AND the parent ledger
	// row revokes, so OCSP and the CRL answer for it. Idempotent on repeat.
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations/"+minted.ID+"/revoke", operator, "edge-revoke", map[string]any{
		"reason": "host decommissioned",
	})
	if code != http.StatusOK {
		t.Fatalf("revoke = %d body=%s", code, body)
	}
	var revoked struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &revoked); err != nil || revoked.Status != "revoked" {
		t.Fatalf("revoke status = %+v err=%v", revoked, err)
	}
	issued, found, err := h.store.LookupIssuedCert(ctx, h.tenant, root.ID, minted.Serial)
	if err != nil || !found || !issued.Revoked() {
		t.Fatalf("parent ledger after revoke: found=%v revoked=%v err=%v; revocation must ride "+
			"the existing OCSP/CRL machinery", found, issued.Revoked(), err)
	}
	code, _ = doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations/"+minted.ID+"/revoke", operator, "edge-revoke-again", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("second revoke = %d, want idempotent 200", code)
	}
}
