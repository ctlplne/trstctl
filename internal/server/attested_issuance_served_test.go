// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/attest/awsiid"
	"trstctl.com/trstctl/internal/attest/azureimds"
	"trstctl.com/trstctl/internal/attest/gcpmeta"
	"trstctl.com/trstctl/internal/attest/githuboidc"
	"trstctl.com/trstctl/internal/attest/k8ssat"
	"trstctl.com/trstctl/internal/attest/tpmquote"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/custody"
)

// A preview must not consume proof, emit an event, reserve an idempotency key,
// queue an external call, or ask the signer to do work.
func TestServedAttestedPreviewIsExactEffectFreeAndFailClosed(t *testing.T) {
	attestor := &countingAttestedPreviewAttestor{}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{
			Enabled: true, TrustDomain: "served.test", DefaultTTL: 10 * time.Minute,
			MaxTTL: time.Hour, Attestors: []attest.Attestor{attestor},
		}
	})
	token := seedScopedTokenSubject(t, h.store, h.tenant, "attested-preview-owner", "certs:issue", "certs:read")
	body := map[string]any{
		"method": "k8s_sat", "payload_base64": base64.StdEncoding.EncodeToString([]byte("one-time-proof")),
		"public_key_pem": servedAttestedPublicKeyPEM(t), "ttl_seconds": int64(math.MaxInt64),
	}
	headBefore, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	stateBefore := ephemeralPreviewMutationState(t, h)
	signer := &countingEphemeralDigestSigner{DigestSigner: h.srv.attestedIssuance.caSigner}
	h.srv.attestedIssuance.caSigner = signer
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attested-issuance/preview", token, "", body)
	if status != http.StatusOK {
		t.Fatalf("attested preview status = %d, want 200; body=%s", status, raw)
	}
	var preview struct {
		Ready                   bool     `json:"ready"`
		EffectFree              bool     `json:"effect_free"`
		Method                  string   `json:"method"`
		Requester               string   `json:"requester"`
		TrustDomain             string   `json:"trust_domain"`
		EffectiveTTLSeconds     int64    `json:"effective_ttl_seconds"`
		TTLClamped              bool     `json:"ttl_clamped"`
		RequiredPermission      string   `json:"required_permission"`
		AttestationVerification string   `json:"attestation_verification"`
		PayloadSHA256           string   `json:"payload_sha256"`
		PublicKeySHA256         string   `json:"public_key_sha256"`
		PreviewWrites           []string `json:"preview_writes"`
		PreviewExternalEffects  []string `json:"preview_external_effects"`
		PreviewSignerCalls      []string `json:"preview_signer_calls"`
		ExecutionWrites         []string `json:"execution_writes"`
		ExecutionSignerCalls    []string `json:"execution_signer_calls"`
		Steps                   []string `json:"steps"`
		Blockers                []string `json:"blockers"`
		RecoverySteps           []string `json:"recovery_steps"`
		DataHandling            []string `json:"data_handling"`
	}
	if err := json.Unmarshal(raw, &preview); err != nil {
		t.Fatal(err)
	}
	if !preview.Ready || !preview.EffectFree || preview.Method != "k8s_sat" ||
		preview.Requester != "attested-preview-owner" || preview.TrustDomain != "served.test" ||
		preview.EffectiveTTLSeconds != 3600 || !preview.TTLClamped ||
		preview.RequiredPermission != "certs:issue" || preview.AttestationVerification != "execution_only" {
		t.Fatalf("exact attested preview = %+v", preview)
	}
	if len(preview.PayloadSHA256) != 64 || len(preview.PublicKeySHA256) != 64 ||
		len(preview.PreviewWrites) != 0 || len(preview.PreviewExternalEffects) != 0 || len(preview.PreviewSignerCalls) != 0 ||
		len(preview.ExecutionWrites) == 0 || len(preview.ExecutionSignerCalls) == 0 || len(preview.Steps) < 2 ||
		len(preview.RecoverySteps) == 0 || len(preview.DataHandling) == 0 || len(preview.Blockers) != 0 {
		t.Fatalf("incomplete attested preview contract: %+v", preview)
	}
	if bytes.Contains(raw, []byte("one-time-proof")) || bytes.Contains(raw, []byte(body["payload_base64"].(string))) || bytes.Contains(raw, []byte("BEGIN PUBLIC KEY")) {
		t.Fatalf("preview leaked proof or public-key body: %s", raw)
	}
	for _, method := range []string{"aws_iid", "unknown"} {
		body["method"] = method
		status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attested-issuance/preview", token, "", body)
		if status != http.StatusOK {
			t.Fatalf("unconfigured %s preview status = %d; body=%s", method, status, raw)
		}
		if err := json.Unmarshal(raw, &preview); err != nil {
			t.Fatal(err)
		}
		if preview.Ready || len(preview.Blockers) == 0 || !strings.Contains(strings.Join(preview.Blockers, " "), "not configured") {
			t.Fatalf("unconfigured method did not fail closed: %+v", preview)
		}
	}
	if signer.calls.Load() != 0 || attestor.calls.Load() != 0 {
		t.Fatalf("preview called signer=%d or proof verifier=%d", signer.calls.Load(), attestor.calls.Load())
	}
	if headAfter, err := h.log.LastSequence(t.Context()); err != nil || headAfter != headBefore {
		t.Fatalf("preview changed event head: before=%d after=%d err=%v", headBefore, headAfter, err)
	}
	if stateAfter := ephemeralPreviewMutationState(t, h); stateAfter != stateBefore {
		t.Fatalf("preview changed durable state: before=%+v after=%+v", stateBefore, stateAfter)
	}
	// Ready is configuration truth, not a bypass of proof verification.
	body["method"] = "k8s_sat"
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attested-issuance", token, "f30-invalid-proof", body)
	if status != http.StatusForbidden || signer.calls.Load() != 0 || attestor.calls.Load() != 1 {
		t.Fatalf("ready preview bypassed proof verification: status=%d signer=%d verifier=%d body=%s", status, signer.calls.Load(), attestor.calls.Load(), raw)
	}
}

func TestServedAttestedPreviewRejectsMissingPermissionAndMalformedInput(t *testing.T) {
	fixtures := servedAttestedIssuanceFixtures(t)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.AttestedIssuance = fixtures.Config })
	owner := seedScopedToken(t, h.store, h.tenant, "certs:issue")
	reader := seedScopedToken(t, h.store, h.tenant, "certs:read")
	key := servedAttestedPublicKeyPEM(t)
	for _, tc := range []struct {
		name, token, payload, key string
		status                    int
	}{
		{"reader cannot issue", reader, "c2F0", key, http.StatusForbidden},
		{"anonymous", "", "c2F0", key, http.StatusUnauthorized},
		{"malformed base64", owner, "!not-base64!", key, http.StatusBadRequest},
		{"empty proof", owner, "", key, http.StatusBadRequest},
		{"malformed public key", owner, "c2F0", "not-a-key", http.StatusBadRequest},
		{"multiple public keys", owner, "c2F0", key + key, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attested-issuance/preview", tc.token, "", map[string]any{
				"method": "k8s_sat", "payload_base64": tc.payload, "public_key_pem": tc.key,
			})
			if status != tc.status {
				t.Fatalf("preview status=%d want=%d body=%s", status, tc.status, raw)
			}
		})
	}
}

type countingAttestedPreviewAttestor struct{ calls atomic.Int32 }

func (*countingAttestedPreviewAttestor) Method() string { return "k8s_sat" }

func (a *countingAttestedPreviewAttestor) Attest(context.Context, []byte) (attest.Attestation, error) {
	a.calls.Add(1)
	return attest.Attestation{}, errors.New("preview must not consume one-time proof")
}

func TestAttestedSVIDTTLClampsBeforeDurationConversion(t *testing.T) {
	s := attestedIssuerService{defaultTTL: 10 * time.Minute, maxTTL: time.Hour}
	for _, seconds := range []int64{3601, math.MaxInt64} {
		if got := s.ttl(seconds); got != time.Hour {
			t.Errorf("ttl(%d) = %s, want 1h", seconds, got)
		}
	}
}

func TestServedAttestedIssuanceRecordsRequesterCustodyWithoutStorageClaims(t *testing.T) {
	fixtures := servedAttestedIssuanceFixtures(t)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.AttestedIssuance = fixtures.Config })
	token := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read")
	publicKey := servedAttestedPublicKeyPEM(t)
	first := servedAttestedIssue(t, h, token, "f30-custody", "k8s_sat", fixtures.K8sSAT, publicKey, http.StatusCreated)
	replay := servedAttestedIssue(t, h, token, "f30-custody", "k8s_sat", fixtures.K8sSAT, publicKey, http.StatusCreated)
	if first.CredentialID != replay.CredentialID || first.CertificatePEM != replay.CertificatePEM {
		t.Fatal("custody recording changed exact-request replay")
	}
	rows, err := h.store.ListCertificatesPage(t.Context(), h.tenant, "00000000-0000-0000-0000-000000000000", nil, 10, nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("projected inventory: count=%d error=%v", len(rows), err)
	}
	got := rows[0]
	if got.KeyOrigin != string(custody.OriginRequester) || got.KeyStorage != "" || got.KeyExportable != "" || got.KeyGeneratedBy != "" {
		t.Fatalf("attested custody must record requester origin only: origin=%q storage=%q exportability=%q actor=%q", got.KeyOrigin, got.KeyStorage, got.KeyExportable, got.KeyGeneratedBy)
	}
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+got.ID, token, nil)
	if status != http.StatusOK || !strings.Contains(string(raw), `"key_origin":"requester"`) || !strings.Contains(string(raw), "did not receive its private key for this issuance") {
		t.Fatalf("served custody metadata: status=%d body=%s", status, raw)
	}
	if !h.hasEvent(t, "certificate.recorded") {
		t.Fatal("custody must travel through the event-backed certificate path")
	}
}

// TestServedAttestedIssuanceEndpointIssuesForK8sAndAWS is the NHI-02 acceptance
// proof. It drives the assembled HTTP API, not the library attesters directly:
// a Kubernetes projected service-account token and an AWS instance-identity
// document both become short-lived X.509-SVIDs signed by the served signer-backed
// CA, while a forged AWS proof is rejected fail-closed.
func TestServedAttestedIssuanceEndpointIssuesForK8sAndAWS(t *testing.T) {
	fixtures := servedAttestedIssuanceFixtures(t)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AttestedIssuance = fixtures.Config
	})
	token := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read")
	publicKeyPEM := servedAttestedPublicKeyPEM(t)

	k8s := servedAttestedIssue(t, h, token, "nhi-02-k8s", "k8s_sat", fixtures.K8sSAT, publicKeyPEM, http.StatusCreated)
	if k8s.Subject != "ns/default/sa/web" || k8s.Attestation.Method != "k8s_sat" {
		t.Fatalf("k8s attested issuance = %+v", k8s)
	}
	assertServedAttestedSVID(t, h, k8s, "spiffe://served.test/_trstctl/v1/tenant/"+h.tenant+"/attested/method/k8s_sat/subject/ns/default/sa/web")

	// AN-5: replay returns the exact original response rather than minting a second
	// SVID or re-verifying the proof.
	replay := servedAttestedIssue(t, h, token, "nhi-02-k8s", "k8s_sat", fixtures.K8sSAT, publicKeyPEM, http.StatusCreated)
	if replay.CertificatePEM != k8s.CertificatePEM || replay.CredentialID != k8s.CredentialID {
		t.Fatalf("idempotent replay changed the SVID: first=%+v replay=%+v", k8s, replay)
	}

	aws := servedAttestedIssue(t, h, token, "nhi-02-aws", "aws_iid", fixtures.AWSIID, publicKeyPEM, http.StatusCreated)
	if aws.Subject != "i-0abc123" || aws.Attestation.Method != "aws_iid" {
		t.Fatalf("aws attested issuance = %+v", aws)
	}
	assertServedAttestedSVID(t, h, aws, "spiffe://served.test/_trstctl/v1/tenant/"+h.tenant+"/attested/method/aws_iid/subject/i-0abc123")

	forged := servedAttestedIssue(t, h, token, "nhi-02-aws-forged", "aws_iid", fixtures.ForgedAWSIID, publicKeyPEM, http.StatusForbidden)
	if forged.CertificatePEM != "" {
		t.Fatalf("forged attestation returned a certificate: %+v", forged)
	}

	for _, eventType := range []string{"attestation.verified", "attestation.bound", "attestation.rejected", "ephemeral.issued", "certificate.recorded"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("served attested issuance did not emit %s", eventType)
		}
	}
}

type servedAttestedFixtures struct {
	Config        AttestedIssuanceConfig
	K8sSAT        []byte
	ExpiredK8sSAT []byte
	AWSIID        []byte
	ForgedAWSIID  []byte
}

func servedAttestedIssuanceFixtures(t *testing.T) servedAttestedFixtures {
	t.Helper()

	awsDoc := []byte(`{"instanceId":"i-0abc123","accountId":"111122223333","region":"us-east-1","instanceType":"m5.large","imageId":"ami-1"}`)
	awsGood, awsRoot, err := crypto.SignCMS(awsDoc)
	if err != nil {
		t.Fatalf("sign aws iid: %v", err)
	}
	awsForged, _, err := crypto.SignCMS(awsDoc)
	if err != nil {
		t.Fatalf("sign forged aws iid: %v", err)
	}

	azureDoc := []byte(`{"vmId":"vm-123","subscriptionId":"sub-123","resourceGroupName":"rg1","location":"eastus","name":"vm1"}`)
	_, azureRoot, err := crypto.SignCMS(azureDoc)
	if err != nil {
		t.Fatalf("sign azure imds fixture: %v", err)
	}

	k8sSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("k8s signer: %v", err)
	}
	t.Cleanup(k8sSigner.Destroy)
	k8sJWK, err := crypto.PublicJWK(k8sSigner.Public(), "k8s-k1")
	if err != nil {
		t.Fatalf("k8s jwk: %v", err)
	}
	k8sSAT := servedK8sSAT(t, k8sSigner, "k8s-k1")
	expiredK8sSAT := servedK8sSATWithExpiry(t, k8sSigner, "k8s-k1", time.Now().Add(-time.Minute))

	gcpSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("gcp signer: %v", err)
	}
	t.Cleanup(gcpSigner.Destroy)
	gcpJWK, err := crypto.PublicJWK(gcpSigner.Public(), "gcp-k1")
	if err != nil {
		t.Fatalf("gcp jwk: %v", err)
	}

	ghSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("github signer: %v", err)
	}
	t.Cleanup(ghSigner.Destroy)
	ghJWK, err := crypto.PublicJWK(ghSigner.Public(), "gh-k1")
	if err != nil {
		t.Fatalf("github jwk: %v", err)
	}

	tpmManufacturer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("tpm manufacturer key: %v", err)
	}
	t.Cleanup(tpmManufacturer.Destroy)
	tpmManufacturerCert, err := crypto.SelfSignedCACert(tpmManufacturer, "NHI-02 TPM Manufacturer", time.Hour)
	if err != nil {
		t.Fatalf("tpm manufacturer cert: %v", err)
	}

	return servedAttestedFixtures{
		Config: AttestedIssuanceConfig{
			Enabled:     true,
			TrustDomain: "served.test",
			DefaultTTL:  10 * time.Minute,
			MaxTTL:      time.Hour,
			Attestors: []attest.Attestor{
				&awsiid.Attestor{Roots: [][]byte{awsRoot}},
				&azureimds.Attestor{Roots: [][]byte{azureRoot}},
				&gcpmeta.Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{gcpJWK}}, Issuer: "https://accounts.google.com", Audience: "trstctl"},
				&githuboidc.Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{ghJWK}}, Audience: "trstctl"},
				&k8ssat.Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{k8sJWK}}, Issuer: "https://kubernetes.default.svc", Audience: "trstctl"},
				&tpmquote.Attestor{ManufacturerRoots: [][]byte{tpmManufacturerCert}, ExpectedNonce: []byte("nhi-02-nonce")},
			},
		},
		K8sSAT:        []byte(k8sSAT),
		ExpiredK8sSAT: []byte(expiredK8sSAT),
		AWSIID:        awsGood,
		ForgedAWSIID:  awsForged,
	}
}

func servedK8sSAT(t *testing.T, signer crypto.DigestSigner, kid string) string {
	t.Helper()
	return servedK8sSATWithExpiry(t, signer, kid, time.Now().Add(time.Hour))
}

func servedK8sSATWithExpiry(t *testing.T, signer crypto.DigestSigner, kid string, exp time.Time) string {
	t.Helper()
	claims := map[string]any{
		"iss": "https://kubernetes.default.svc",
		"aud": []string{"trstctl"},
		"exp": exp.Unix(),
		"sub": "system:serviceaccount:default:web",
		"kubernetes.io": map[string]any{
			"namespace": "default",
			"serviceaccount": map[string]any{
				"name": "web",
				"uid":  "uid-1",
			},
			"pod": map[string]any{"name": "web-abc", "uid": "uid-2"},
		},
	}
	token, err := crypto.SignJWT(signer, kid, claims)
	if err != nil {
		t.Fatalf("sign k8s SAT: %v", err)
	}
	return token
}

func servedAttestedPublicKeyPEM(t *testing.T) string {
	t.Helper()
	workloadKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("workload key: %v", err)
	}
	t.Cleanup(workloadKey.Destroy)
	return string(crypto.MarshalPublicKeyPEM(workloadKey.Public().DER))
}

type servedAttestedIssueResponse struct {
	CertificatePEM string    `json:"certificate_pem"`
	SPIFFEID       string    `json:"spiffe_id"`
	CredentialID   string    `json:"credential_id"`
	Subject        string    `json:"subject"`
	NotAfter       time.Time `json:"not_after"`
	Attestation    struct {
		ID        string   `json:"id"`
		Method    string   `json:"method"`
		Subject   string   `json:"subject"`
		Selectors []string `json:"selectors"`
	} `json:"attestation"`
}

func servedAttestedIssue(t *testing.T, h *servedHarness, token, idemKey, method string, payload []byte, publicKeyPEM string, want int) servedAttestedIssueResponse {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attested-issuance", token, idemKey, map[string]any{
		"method":         method,
		"payload_base64": base64.StdEncoding.EncodeToString(payload),
		"public_key_pem": publicKeyPEM,
		"ttl_seconds":    600,
	})
	if status != want {
		t.Fatalf("attested issuance %s status = %d, want %d; body=%s", method, status, want, body)
	}
	var out servedAttestedIssueResponse
	if status == http.StatusCreated {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode attested issuance response: %v; body=%s", err, body)
		}
	}
	return out
}

func assertServedAttestedSVID(t *testing.T, h *servedHarness, got servedAttestedIssueResponse, wantURI string) {
	t.Helper()
	assertSignedWorkloadIDHandoff(t, got.CertificatePEM, got.SPIFFEID, wantURI)
	if got.CertificatePEM == "" || got.CredentialID == "" || got.NotAfter.IsZero() {
		t.Fatalf("attested SVID response missing certificate/id/expiry: %+v", got)
	}
	block, _ := pem.Decode([]byte(got.CertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("certificate_pem did not decode to one CERTIFICATE block: %.80q", got.CertificatePEM)
	}
	if err := crypto.VerifyLeafSignedByCA(block.Bytes, caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("attested SVID does not verify against served CA: %v", err)
	}
	info, err := certinfo.Inspect(block.Bytes)
	if err != nil {
		t.Fatalf("inspect attested SVID: %v", err)
	}
	if !protoContains(info.URIs, wantURI) {
		t.Fatalf("attested SVID URI SANs = %v, want %s", info.URIs, wantURI)
	}
}
