// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// eMudhra, Part 4: an offline root's key never enters the signer, so its
// import either carries a challenge signed offline during the ceremony or
// records that possession was not proven. Signer-held authorities record the
// challenge their key answered.
func TestServedCAImportsRecordHowKeyPossessionWasEstablished(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := context.Background()
	scopes := []string{"issuers:write", "issuers:read", "certs:issue"}
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "possession-operator", scopes)
	approverOne := seedServedAPIToken(t, ctx, h.store, h.tenant, "possession-custodian-one", scopes)
	approverTwo := seedServedAPIToken(t, ctx, h.store, h.tenant, "possession-custodian-two", scopes)

	offlineRoot := func(name string) (*crypto.LockedSigner, string, map[string]any) {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP384)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		profile := crypto.HierarchyCAProfile{CommonName: name, MaxPathLen: 1, TTL: 365 * 24 * time.Hour}
		root, err := crypto.SelfSignedHierarchyCA(key, profile)
		if err != nil {
			t.Fatal(err)
		}
		return key, string(root.CertificatePEM), map[string]any{
			"common_name": profile.CommonName, "max_path_len": profile.MaxPathLen,
			"ttl_seconds": int64(profile.TTL.Seconds()), "signature_algorithm": "ecdsa-p384",
		}
	}
	approvedCeremony := func(pem string, spec map[string]any, idem string) string {
		t.Helper()
		ceremony := createCACeremonyWithCertificate(t, h, operator, "import_offline_root", pem, spec, 2, idem)
		approveCACeremony(t, h, approverOne, ceremony.ID, 1, idem+"-approval-one")
		approveCACeremony(t, h, approverTwo, ceremony.ID, 2, idem+"-approval-two")
		return ceremony.ID
	}
	// The offline signer's half, as `openssl dgst -sha256 -sign` makes it.
	sign := func(key *crypto.LockedSigner, ceremonyID string) string {
		t.Helper()
		digest, err := crypto.Digest(crypto.SHA256, crypto.OfflinePossessionMessage(ceremonyID))
		if err != nil {
			t.Fatal(err)
		}
		sig, err := key.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256})
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(sig)
	}
	importRoot := func(ceremonyID, pem string, spec map[string]any, signature, idem string) (int, []byte) {
		t.Helper()
		body := map[string]any{"ceremony_id": ceremonyID, "certificate_pem": pem, "spec": spec}
		if signature != "" {
			body["possession_signature"] = signature
		}
		return doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/offline-roots", operator, idem, body)
	}

	key, pem, spec := offlineRoot("possession proven root")
	ceremonyID := approvedCeremony(pem, spec, "possession-proven")
	// A signature over another ceremony's challenge, or no signature at all
	// in a malformed field, is refused before the ceremony is consumed.
	if code, body := importRoot(ceremonyID, pem, spec, sign(key, "a-different-ceremony"), "possession-wrong-ceremony"); code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "possession signature does not verify") {
		t.Fatalf("signature over another ceremony = %d %s", code, body)
	}
	if code, body := importRoot(ceremonyID, pem, spec, "not base64!", "possession-not-base64"); code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "possession_signature is not standard base64") {
		t.Fatalf("malformed signature = %d %s", code, body)
	}
	code, body := importRoot(ceremonyID, pem, spec, sign(key, ceremonyID), "possession-right")
	var proven struct {
		ID              string `json:"id"`
		PossessionProof string `json:"possession_proof"`
	}
	if code != http.StatusCreated || json.Unmarshal(body, &proven) != nil || proven.PossessionProof != "offline_signature" {
		t.Fatalf("signed import = %d %s", code, body)
	}

	_, unsignedPEM, unsignedSpec := offlineRoot("possession unproven root")
	unsignedCeremony := approvedCeremony(unsignedPEM, unsignedSpec, "possession-unproven")
	code, body = importRoot(unsignedCeremony, unsignedPEM, unsignedSpec, "", "possession-unsigned")
	var unproven struct {
		ID              string `json:"id"`
		PossessionProof string `json:"possession_proof"`
	}
	if code != http.StatusCreated || json.Unmarshal(body, &unproven) != nil || unproven.PossessionProof != "not_proven" {
		t.Fatalf("unsigned import = %d %s", code, body)
	}

	// The creation events are the durable record.
	recorded := map[string]string{}
	if err := h.log.Replay(ctx, 0, func(e events.Event) error {
		if e.Type != projections.EventCARootCreated || e.TenantID != h.tenant {
			return nil
		}
		var payload projections.CAAuthorityCreated
		if err := json.Unmarshal(e.Data, &payload); err != nil {
			return err
		}
		recorded[payload.CAID] = payload.PossessionProof
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if recorded[proven.ID] != "offline_signature" || recorded[unproven.ID] != "not_proven" {
		t.Fatalf("recorded possession = %v", recorded)
	}
}
