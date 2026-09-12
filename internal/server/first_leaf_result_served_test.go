// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Real PostgreSQL/NATS and the existing UDS signer harness; not an independent
// signer-process or browser/stock-client TLS qualification.
func TestServedFirstLeafResultIsExactPendingIdempotentAndReplayable(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "owners:read", "owners:write", "identities:read", "identities:write", "certs:read", "certs:issue", "certs:write")
	owner := servedCreateID(t, h, token, "first-leaf-owner", "/api/v1/owners", map[string]any{
		"kind": "workload", "name": "first-leaf", "email": "owner@example.test",
		"application_id": "first-leaf", "environment": "test",
	})
	identityBody := map[string]any{"kind": "x509_certificate", "name": "first-leaf.example.test", "owner_id": owner}
	identity := servedCreateID(t, h, token, "first-leaf-create", "/api/v1/identities", identityBody)
	key, err := crypto.GenerateHostSubjectKey("first-leaf.example.test", []string{"first-leaf.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy() // Caller key remains alive; no private bytes go to the API.
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: key.CSRDER})
	transitionKey := "first-leaf-transition"
	transition := map[string]any{"to": "issued", "reason": "caller-held CSR", "subject_csr_pem": string(csr)}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+identity+"/transitions", token, transitionKey, transition)
	if status != http.StatusOK {
		t.Fatalf("transition = %d: %s", status, body)
	}
	path := "/api/v1/identities/" + identity + "/issuance-result?request_key=" + url.QueryEscape(transitionKey)
	status, body = secretsReq(t, h, http.MethodGet, path, token, nil)
	var pending struct {
		State       string          `json:"state"`
		Certificate json.RawMessage `json:"certificate"`
		PEM         string          `json:"certificate_pem"`
	}
	if err := json.Unmarshal(body, &pending); err != nil || status != http.StatusOK || pending.State != "pending" || pending.PEM != "" || len(pending.Certificate) != 0 {
		t.Fatalf("accepted transition is not yet a leaf: status=%d body=%s err=%v", status, body, err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodGet, path, token, nil)
	var result struct {
		State       string `json:"state"`
		IdentityID  string `json:"identity_id"`
		RequestKey  string `json:"request_key"`
		PEM         string `json:"certificate_pem"`
		Certificate struct {
			ID          string `json:"id"`
			Fingerprint string `json:"fingerprint"`
			KeyOrigin   string `json:"key_origin"`
		} `json:"certificate"`
	}
	if err := json.Unmarshal(body, &result); err != nil || status != http.StatusOK || result.State != "issued" || result.IdentityID != identity || result.RequestKey != transitionKey {
		t.Fatalf("result = %d %s, %v", status, body, err)
	}
	first, rest := pem.Decode([]byte(result.PEM))
	issuer, tail := pem.Decode(rest)
	if first == nil || issuer == nil || len(bytes.TrimSpace(tail)) != 0 || !bytes.Equal(issuer.Bytes, caCertDER(t, h.caPEM)) {
		t.Fatal("result omitted or substituted the actual issuing CA")
	}
	info, err := certinfo.Inspect(first.Bytes)
	if err != nil || info.SPKISHA256 != crypto.SHA256Hex(key.PublicKeyDER) || info.SHA256Fingerprint != result.Certificate.Fingerprint || result.Certificate.KeyOrigin != "requester" {
		t.Fatalf("result does not bind caller key and exact recorded leaf: %+v %v", info, err)
	}
	stored, err := h.store.GetCertificate(t.Context(), h.tenant, result.Certificate.ID)
	if err != nil || !bytes.Equal(stored.CertificateDER, first.Bytes) {
		t.Fatalf("wrong stored leaf: %v", err)
	}
	assertInventoryBinding := func() {
		t.Helper()
		for _, inventoryPath := range []string{"/api/v1/certificates/" + result.Certificate.ID, "/api/v1/certificates?limit=100"} {
			code, raw := secretsReq(t, h, http.MethodGet, inventoryPath, token, nil)
			var record struct {
				IdentityIDs []string `json:"identity_ids"`
				Items       []struct {
					ID          string   `json:"id"`
					IdentityIDs []string `json:"identity_ids"`
				} `json:"items"`
			}
			if err := json.Unmarshal(raw, &record); err != nil || code != http.StatusOK {
				t.Fatalf("inventory binding: %d %s %v", code, raw, err)
			}
			ids := record.IdentityIDs
			for _, item := range record.Items {
				if item.ID == result.Certificate.ID {
					ids = item.IdentityIDs
				}
			}
			if !reflect.DeepEqual(ids, []string{identity}) {
				t.Fatalf("inventory bound the wrong identity: %s", raw)
			}
		}
	}
	assertInventoryBinding()
	counts := tenantEventTypes(t, h.log, h.tenant)
	if counts["issuance.server_side_keygen"] != 0 {
		t.Fatal("caller CSR fell back to server key generation")
	}
	// Lost create/transition acknowledgements must not select another identity/key.
	if got := servedCreateID(t, h, token, "first-leaf-create", "/api/v1/identities", identityBody); got != identity {
		t.Fatal("creation retry changed identity")
	}
	status, retry := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+identity+"/transitions", token, transitionKey, transition)
	if status != http.StatusOK {
		t.Fatalf("transition retry = %d %s", status, retry)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, again := secretsReq(t, h, http.MethodGet, path, token, nil)
	if status != http.StatusOK || !bytes.Equal(body, again) || !reflect.DeepEqual(counts, tenantEventTypes(t, h.log, h.tenant)) {
		t.Fatal("retry/read changed result or minted/appended again")
	}
	// The relation and public chain must be reconstructed from immutable events.
	if err := projections.New(h.store).Rebuild(t.Context(), h.log); err != nil {
		t.Fatal(err)
	}
	status, again = secretsReq(t, h, http.MethodGet, path, token, nil)
	if status != http.StatusOK || !bytes.Equal(body, again) {
		t.Fatalf("replay changed exact public result: %d %s", status, again)
	}
	// Ordinary served inventory import changes current provenance, not the
	// immutable issuance result. No private key or issuance key is imported.
	status, imported := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates", token,
		"first-leaf-public-reimport", map[string]any{"pem": string(pem.EncodeToMemory(first)), "owner_id": owner})
	if status != http.StatusCreated {
		t.Fatalf("same-leaf import = %d %s", status, imported)
	}
	status, importedResult := secretsReq(t, h, http.MethodGet, path, token, nil)
	var afterImport struct {
		State       string `json:"state"`
		IdentityID  string `json:"identity_id"`
		RequestKey  string `json:"request_key"`
		PEM         string `json:"certificate_pem"`
		Certificate struct {
			ID          string `json:"id"`
			Fingerprint string `json:"fingerprint"`
			Source      string `json:"source"`
		} `json:"certificate"`
	}
	if err := json.Unmarshal(importedResult, &afterImport); err != nil || status != http.StatusOK ||
		afterImport.State != "issued" || afterImport.IdentityID != identity || afterImport.RequestKey != transitionKey ||
		afterImport.PEM != result.PEM || afterImport.Certificate.ID != result.Certificate.ID ||
		afterImport.Certificate.Fingerprint != result.Certificate.Fingerprint || afterImport.Certificate.Source != "import" {
		t.Fatalf("re-import lost exact issuance or misstated provenance: %d %s err=%v", status, importedResult, err)
	}
	if err := projections.New(h.store).Rebuild(t.Context(), h.log); err != nil {
		t.Fatal(err)
	}
	status, afterImportReplay := secretsReq(t, h, http.MethodGet, path, token, nil)
	if status != http.StatusOK || !bytes.Equal(importedResult, afterImportReplay) {
		t.Fatalf("rebuild lost imported issuance result: %d %s", status, afterImportReplay)
	}
	assertInventoryBinding() // Re-import and full replay preserve exact identity evidence.
	beforeConflict := tenantEventTypes(t, h.log, h.tenant)
	stored.CertificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: stored.CertificateDER})
	if _, err := h.srv.orch.RecordCertificate(t.Context(), h.tenant, stored); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed retained chain = %v", err)
	}
	if !reflect.DeepEqual(beforeConflict, tenantEventTypes(t, h.log, h.tenant)) {
		t.Fatal("conflicting public result appended an event")
	}

}

func TestServedFirstLeafResultRequiresExactTenantIdentityAndReadAuthority(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "owners:write", "identities:write", "identities:read", "certs:read", "certs:issue")
	owner := servedCreateID(t, h, token, "first-result-owner", "/api/v1/owners", map[string]any{"kind": "workload", "name": "shared-owner"})
	id := servedCreateID(t, h, token, "first-result-id", "/api/v1/identities", map[string]any{"kind": "x509_certificate", "name": "same.example.test", "owner_id": owner})
	other := servedCreateID(t, h, token, "first-result-other", "/api/v1/identities", map[string]any{"kind": "x509_certificate", "name": "same.example.test", "owner_id": owner})
	csr := subjectCSR(t, "same.example.test")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions", token, "exact-result-key", map[string]any{"to": "issued", "subject_csr_pem": string(csr)})
	if status != http.StatusOK {
		t.Fatalf("transition = %d %s", status, body)
	}
	for _, query := range []string{"", "?request_key=", "?request_key=a&request_key=b", "?request_key=" + strings.Repeat("x", 257)} {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+id+"/issuance-result"+query, token, nil)
		if status != http.StatusBadRequest {
			t.Fatalf("invalid result query = %d %s", status, body)
		}
	}
	readerless := seedScopedToken(t, h.store, h.tenant, "identities:read")
	neighbor := seedScopedToken(t, h.store, "22222222-2222-2222-2222-222222222222", "identities:read", "certs:read")
	for _, tc := range []struct {
		name, id, key, token string
		status               int
	}{
		{"anonymous", id, "exact-result-key", "", http.StatusUnauthorized},
		{"missing permission", id, "exact-result-key", readerless, http.StatusForbidden},
		{"wrong tenant", id, "exact-result-key", neighbor, http.StatusNotFound},
		{"same owner and name", other, "exact-result-key", token, http.StatusNotFound},
		{"wrong key", id, "another-result-key", token, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+tc.id+"/issuance-result?request_key="+url.QueryEscape(tc.key), tc.token, nil)
			if status != tc.status {
				t.Fatalf("result = %d %s, want %d", status, body, tc.status)
			}
		})
	}
}

// Deliberately malformed records are negative fixture inputs, never proof that
// any caller actually received a valid certificate.
func TestServedFirstLeafResultRejectsMissingMaterialAndAmbiguousRecords(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "owners:write", "identities:write", "identities:read", "certs:read", "certs:issue")
	owner := servedCreateID(t, h, token, "negative-result-owner", "/api/v1/owners", map[string]any{"kind": "workload", "name": "negative-result"})
	id := servedCreateID(t, h, token, "negative-result-id", "/api/v1/identities", map[string]any{"kind": "x509_certificate", "name": "negative.example.test", "owner_id": owner})
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions", token, "negative-result-key", map[string]any{"to": "issued", "subject_csr_pem": string(subjectCSR(t, "negative.example.test"))})
	if status != http.StatusOK {
		t.Fatalf("transition = %d %s", status, body)
	}
	path := "/api/v1/identities/" + id + "/issuance-result?request_key=negative-result-key"
	for _, digit := range []string{"a", "b"} {
		_, err := h.srv.orch.RecordCertificate(t.Context(), h.tenant, store.Certificate{
			OwnerID: &owner, Subject: "CN=negative.example.test", SANs: []string{"negative.example.test"},
			Source: "issued", Fingerprint: strings.Repeat(digit, 64), IssuanceIdempotencyKey: "issue:transition:negative-result-key",
		})
		if err != nil {
			t.Fatal(err)
		}
		status, body = secretsReq(t, h, http.MethodGet, path, token, nil)
		if status != http.StatusConflict {
			t.Fatalf("missing material/duplicate result = %d %s, want 409", status, body)
		}
	}
}

// Actual API + PostgreSQL/NATS regression. The malformed PKCS#10 reaches the
// server; no client envelope double substitutes for its signature/parser gate.
func TestServedFirstLeafRejectedCSRHasExactReplayableCorrectionDisposition(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "owners:write", "identities:write", "identities:read", "certs:issue", "certs:read")
	owner := servedCreateID(t, h, token, "correction-owner", "/api/v1/owners", map[string]any{"kind": "workload", "name": "correction"})
	id := servedCreateID(t, h, token, "correction-identity", "/api/v1/identities", map[string]any{"kind": "x509_certificate", "name": "correct.example.test", "owner_id": owner})
	bad := "-----BEGIN CERTIFICATE REQUEST-----\nAQID\n-----END CERTIFICATE REQUEST-----"
	reason := "first issuance via UI from an operator-supplied CSR"
	body := map[string]any{"to": "issued", "reason": reason, "subject_csr_pem": bad}
	path := "/api/v1/identities/" + id + "/transitions"
	prior := tenantEventTypes(t, h.log, h.tenant)
	status, raw := secretsReqKey(t, h, http.MethodPost, path, token, "rejected-csr-key", body)
	if status != http.StatusBadRequest {
		t.Fatalf("malformed CSR = %d %s", status, raw)
	}
	var refusal struct {
		Code        string            `json:"code"`
		Disposition map[string]string `json:"disposition"`
	}
	if err := json.Unmarshal(raw, &refusal); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"tenant_id": h.tenant, "subject": "secrets-test", "identity_id": id, "request_key": "rejected-csr-key", "subject_csr_sha256": crypto.SHA256Hex([]byte(bad)), "to": "issued", "reason": reason}
	if bytes.Contains(raw, []byte(bad)) {
		t.Fatal("rejected arbitrary input was reflected in durable response")
	}
	if refusal.Code != "identity_csr_rejected_before_transition" || !reflect.DeepEqual(refusal.Disposition, want) {
		t.Fatalf("ambiguous disposition: %s", raw)
	}
	status, replay := secretsReqKey(t, h, http.MethodPost, path, token, "rejected-csr-key", body)
	if status != http.StatusBadRequest || !bytes.Equal(raw, replay) {
		t.Fatalf("lost refusal cannot be recovered exactly: %d %s", status, replay)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(prior, tenantEventTypes(t, h.log, h.tenant)) {
		t.Fatal("CSR refusal transitioned or dispatched issuance")
	}
	privateLooking := "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----"
	privateRequest := map[string]any{"to": "issued", "reason": reason, "subject_csr_pem": privateLooking}
	privateStatus, privateBody := secretsReqKey(t, h, http.MethodPost, path, token, "rejected-nonpublic-key", privateRequest)
	if privateStatus != http.StatusBadRequest || bytes.Contains(privateBody, []byte("AQID")) {
		t.Fatalf("nonpublic input was accepted or reflected: %d", privateStatus)
	}
	key, err := crypto.GenerateHostSubjectKey("correct.example.test", []string{"correct.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	validPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: key.CSRDER}))
	for index, prefix := range []string{
		"-----BEGIN CERTIFICATE REQUEST-----\n!!!!\n-----END CERTIFICATE REQUEST-----\n",
		"-----BEGIN CERTIFICATE REQUEST-----\n",
		"-----BEGIN NEW CERTIFICATE REQUEST-----\n!!!!\n-----END NEW CERTIFICATE REQUEST-----\n",
		"-----BEGIN CERTIFICATE REQUEST-----\n-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n",
	} {
		attemptKey := fmt.Sprintf("rejected-skipped-csr-%d", index)
		malformed := map[string]any{"to": "issued", "reason": reason, "subject_csr_pem": prefix + validPEM}
		status, refused := secretsReqKey(t, h, http.MethodPost, path, token, attemptKey, malformed)
		if status != http.StatusBadRequest || !bytes.Contains(refused, []byte("identity_csr_rejected_before_transition")) {
			t.Fatalf("skipped CSR prefix %d accepted or ambiguous: %d %s", index, status, refused)
		}
		status, replay := secretsReqKey(t, h, http.MethodPost, path, token, attemptKey, malformed)
		if status != http.StatusBadRequest || !bytes.Equal(refused, replay) {
			t.Fatal("skipped-prefix refusal was not replayed exactly")
		}
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(prior, tenantEventTypes(t, h.log, h.tenant)) {
		t.Fatal("skipped-prefix refusal transitioned or dispatched issuance")
	}
	corrected := map[string]any{"to": "issued", "reason": reason, "subject_csr_pem": validPEM}
	status, conflict := secretsReqKey(t, h, http.MethodPost, path, token, "rejected-csr-key", corrected)
	if status != http.StatusConflict {
		t.Fatalf("same key accepted changed body: %d %s", status, conflict)
	}
	status, accepted := secretsReqKey(t, h, http.MethodPost, path, token, "intentional-corrected-key", corrected)
	if status != http.StatusOK {
		t.Fatalf("deliberate same-identity correction refused: %d %s", status, accepted)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, result := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+id+"/issuance-result?request_key=intentional-corrected-key", token, nil)
	var leaf struct {
		IdentityID string `json:"identity_id"`
		State      string `json:"state"`
		PEM        string `json:"certificate_pem"`
	}
	if err := json.Unmarshal(result, &leaf); err != nil || status != http.StatusOK || leaf.IdentityID != id || leaf.State != "issued" {
		t.Fatalf("corrected exact result absent: %d %s %v", status, result, err)
	}
	info, err := certinfo.Inspect([]byte(leaf.PEM))
	if err != nil || info.SPKISHA256 != crypto.SHA256Hex(key.PublicKeyDER) {
		t.Fatalf("corrected CSR key not retained: %v", err)
	}
	counts := tenantEventTypes(t, h.log, h.tenant)
	if counts["identity.created"] != prior["identity.created"] || counts["owner.created"] != prior["owner.created"] || counts["issuance.server_side_keygen"] != 0 {
		t.Fatal("correction replaced owner/identity or generated a server key")
	}
	status, replay = secretsReqKey(t, h, http.MethodPost, path, token, "rejected-csr-key", body)
	if status != http.StatusBadRequest || !bytes.Equal(raw, replay) {
		t.Fatal("later success rewrote the original refusal receipt")
	}
}
