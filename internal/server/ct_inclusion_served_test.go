// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/ctlog"
	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/store"
)

// issueCTFixtureCertificate issues a leaf from the platform CA and records it
// in the inventory, as an issued certificate an operator then logs.
func issueCTFixtureCertificate(t *testing.T, h *servedHarness, name string) (store.Certificate, string) {
	t.Helper()
	key, err := crypto.GenerateHostSubjectKey(name, []string{name})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	issued, err := h.srv.issueLeafWithValidity(t.Context(), key.CSRDER, 24*time.Hour, crypto.LeafProfile{ClampTTLToIssuer: true})
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(issued.DER)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := h.srv.orch.RecordCertificate(t.Context(), h.tenant, store.Certificate{
		Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer, Serial: info.SerialNumber,
		Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm, Source: "issued",
		CertificateDER: issued.DER, NotBefore: &info.NotBefore, NotAfter: &info.NotAfter,
		ValidityAnchor: &issued.ValidityAnchor,
	})
	if err != nil {
		t.Fatalf("record the issued certificate: %v", err)
	}
	return cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issued.DER}))
}

// ctSCTsByLog reads what each log answered for a certificate.
func ctSCTsByLog(t *testing.T, h *servedHarness, fingerprint string) map[string]store.CertificateSCT {
	t.Helper()
	rows, err := h.store.CertificateSCTs(t.Context(), h.tenant, fingerprint)
	if err != nil {
		t.Fatalf("read SCTs: %v", err)
	}
	out := map[string]store.CertificateSCT{}
	for _, row := range rows {
		out[row.LogURL] = row
	}
	return out
}

type ctTransparencyDetail struct {
	Transparency []struct {
		LogURL          string `json:"log_url"`
		LogID           string `json:"log_id"`
		SCTStatus       string `json:"sct_status"`
		SCTReason       string `json:"sct_reason"`
		InclusionStatus string `json:"inclusion_status"`
		InclusionReason string `json:"inclusion_reason"`
		LeafIndex       *int64 `json:"leaf_index"`
		TreeSize        *int64 `json:"tree_size"`
		RootHash        string `json:"root_hash"`
	} `json:"transparency"`
}

func TestServedCTSCTVerifiesAndItsInclusionIsProvenAfterTheMerge(t *testing.T) {
	logSrv := ctlogtest.NewSigningServer(ctlogtest.WithDelayedMerge())
	t.Cleanup(logSrv.Close)
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:write", "certs:read", string(authz.PrivateEgress))
	cert, certPEM := issueCTFixtureCertificate(t, h, "ct-inclusion.example.com")

	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/revocation/ct-submissions", tok, "ct-inclusion-good", map[string]any{
		"certificate_pem":        certPEM,
		"logs":                   []string{logSrv.URL()},
		"log_public_keys":        map[string]string{logSrv.URL(): base64.StdEncoding.EncodeToString(logSrv.PublicKeyDER())},
		"allow_private_endpoint": true,
		"private_egress_cidrs":   []string{serviceNowSinkCIDR(t, logSrv.URL())},
	})
	if status != http.StatusAccepted {
		t.Fatalf("queue CT submission: status %d body %s", status, raw)
	}
	var queued struct {
		Residuals []struct {
			Code string `json:"code"`
		} `json:"residuals"`
	}
	if err := json.Unmarshal(raw, &queued); err != nil || len(queued.Residuals) != 0 {
		t.Fatalf("a submission naming every log's key has residuals %+v (%v): %s", queued.Residuals, err, raw)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain CT submission: %v", err)
	}
	sct := ctSCTsByLog(t, h, cert.Fingerprint)[logSrv.URL()]
	if sct.SCTStatus != store.SCTVerified || sct.InclusionStatus != store.InclusionPending || len(sct.LeafHash) != 64 ||
		sct.LogID != hex.EncodeToString(ctlog.LogID(logSrv.PublicKeyDER())) {
		t.Fatalf("delivered SCT = %+v; want verified against the log key and pending inclusion", sct)
	}

	if err := h.srv.RunCTInclusionOnce(t.Context()); err != nil {
		t.Fatalf("inclusion check before the merge: %v", err)
	}
	if got := ctSCTsByLog(t, h, cert.Fingerprint)[logSrv.URL()]; got.InclusionStatus != store.InclusionPending {
		t.Fatalf("an entry the log has not merged is %q (%s); want pending", got.InclusionStatus, got.InclusionReason)
	}

	logSrv.Merge()
	if err := h.srv.RunCTInclusionOnce(t.Context()); err != nil {
		t.Fatalf("inclusion check after the merge: %v", err)
	}
	got := ctSCTsByLog(t, h, cert.Fingerprint)[logSrv.URL()]
	if got.InclusionStatus != store.InclusionVerified || got.LeafIndex == nil || *got.LeafIndex != 0 ||
		got.TreeSize == nil || *got.TreeSize != 1 || len(got.RootHash) != 64 || got.InclusionCheckedAt == nil {
		t.Fatalf("merged entry = %+v; want inclusion verified at index 0 of a tree of 1", got)
	}
	if !h.hasEvent(t, "ct.sct.recorded") || !h.hasEvent(t, "ct.inclusion.recorded") {
		t.Fatal("the SCT and its inclusion were not recorded as events")
	}

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+cert.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("certificate detail: status %d body %s", status, body)
	}
	var detail ctTransparencyDetail
	if err := json.Unmarshal(body, &detail); err != nil || len(detail.Transparency) != 1 {
		t.Fatalf("certificate detail transparency = %+v (%v); body %s", detail.Transparency, err, body)
	}
	if entry := detail.Transparency[0]; entry.SCTStatus != "verified" || entry.InclusionStatus != "verified" ||
		entry.TreeSize == nil || *entry.TreeSize != 1 || entry.RootHash != got.RootHash || entry.LogID != sct.LogID {
		t.Fatalf("certificate detail shows %+v; want the verified SCT and its proven inclusion", entry)
	}
}

func TestServedCTFlagsBadSCTsAndUnprovenInclusion(t *testing.T) {
	corrupt := ctlogtest.NewSigningServer(ctlogtest.WithCorruptSCTs())
	unkeyed := ctlogtest.NewSigningServer()
	forked := ctlogtest.NewSigningServer(ctlogtest.WithForkedTreeHeads())
	late := ctlogtest.NewSigningServer(ctlogtest.WithDelayedMerge())
	for _, srv := range []*ctlogtest.Server{corrupt, unkeyed, forked, late} {
		t.Cleanup(srv.Close)
	}
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:write", "certs:read", string(authz.PrivateEgress))
	cert, certPEM := issueCTFixtureCertificate(t, h, "ct-flagged.example.com")
	keyOf := func(srv *ctlogtest.Server) string { return base64.StdEncoding.EncodeToString(srv.PublicKeyDER()) }

	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/revocation/ct-submissions", tok, "ct-inclusion-flagged", map[string]any{
		"certificate_pem": certPEM,
		"logs":            []string{corrupt.URL(), unkeyed.URL(), forked.URL(), late.URL()},
		"log_public_keys": map[string]string{
			corrupt.URL(): keyOf(corrupt), forked.URL(): keyOf(forked), late.URL(): keyOf(late),
		},
		"allow_private_endpoint": true,
		"private_egress_cidrs":   []string{serviceNowSinkCIDR(t, corrupt.URL())},
	})
	if status != http.StatusAccepted {
		t.Fatalf("queue CT submission: status %d body %s", status, raw)
	}
	var queued struct {
		Residuals []struct {
			Code   string `json:"code"`
			Detail string `json:"detail"`
		} `json:"residuals"`
	}
	if err := json.Unmarshal(raw, &queued); err != nil || len(queued.Residuals) != 1 ||
		queued.Residuals[0].Code != "ct-log-key-not-named" || !strings.Contains(queued.Residuals[0].Detail, unkeyed.URL()) {
		t.Fatalf("residuals = %+v (%v); want the log without a key named", queued.Residuals, err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain CT submissions: %v", err)
	}
	scts := ctSCTsByLog(t, h, cert.Fingerprint)
	if got := scts[corrupt.URL()]; got.SCTStatus != store.SCTInvalid || !strings.Contains(got.SCTReason, "signature") ||
		got.InclusionStatus != store.InclusionNotChecked {
		t.Fatalf("corrupt SCT = %+v; want invalid with the signature named and inclusion not checked", got)
	}
	if got := scts[unkeyed.URL()]; got.SCTStatus != store.SCTUnverified || got.SCTReason == "" ||
		got.InclusionStatus != store.InclusionNotChecked {
		t.Fatalf("SCT from a log without a key = %+v; want unverified, inclusion not checked", got)
	}
	for _, srv := range []*ctlogtest.Server{forked, late} {
		if got := scts[srv.URL()]; got.SCTStatus != store.SCTVerified || got.InclusionStatus != store.InclusionPending {
			t.Fatalf("SCT from %s = %+v; want verified and pending", srv.URL(), got)
		}
	}

	if err := h.srv.RunCTInclusionOnce(t.Context()); err != nil {
		t.Fatalf("inclusion check: %v", err)
	}
	scts = ctSCTsByLog(t, h, cert.Fingerprint)
	if got := scts[forked.URL()]; got.InclusionStatus != store.InclusionProofBad || !strings.Contains(got.InclusionReason, "root") {
		t.Fatalf("entry under a forked tree head = %+v; want proof_invalid", got)
	}
	if got := scts[late.URL()]; got.InclusionStatus != store.InclusionPending {
		t.Fatalf("entry inside the merge delay = %+v; want pending", got)
	}

	late.AgeTreeHeads(25 * time.Hour)
	if err := h.srv.RunCTInclusionOnce(t.Context()); err != nil {
		t.Fatalf("inclusion check past the merge delay: %v", err)
	}
	if got := ctSCTsByLog(t, h, cert.Fingerprint)[late.URL()]; got.InclusionStatus != store.InclusionNotIncluded || got.InclusionReason == "" {
		t.Fatalf("entry missing from a tree head signed past the merge delay = %+v; want not_included", got)
	}

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+cert.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("certificate detail: status %d body %s", status, body)
	}
	var detail ctTransparencyDetail
	if err := json.Unmarshal(body, &detail); err != nil {
		t.Fatalf("decode certificate detail: %v", err)
	}
	shown := map[string]string{}
	for _, entry := range detail.Transparency {
		shown[entry.LogURL] = entry.SCTStatus + "/" + entry.InclusionStatus
	}
	want := map[string]string{
		corrupt.URL(): "invalid/not_checked", unkeyed.URL(): "unverified/not_checked",
		forked.URL(): "verified/proof_invalid", late.URL(): "verified/not_included",
	}
	for logURL, w := range want {
		if shown[logURL] != w {
			t.Fatalf("certificate detail shows %s for %s; want %s (all: %v)", shown[logURL], logURL, w, shown)
		}
	}
}
