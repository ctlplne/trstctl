package server

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
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
)

// TestServedAttestedIssuanceEndpointIssuesForK8sAndAWS is the NHI-02 acceptance
// proof. It drives the assembled HTTP API, not the library attesters directly:
// a Kubernetes projected service-account token and an AWS instance-identity
// document both become short-lived X.509-SVIDs signed by the served signer-backed
// CA, while a forged AWS proof is rejected fail-closed.
func TestServedAttestedIssuanceEndpointIssuesForK8sAndAWS(t *testing.T) {
	fixtures := servedAttestedIssuanceFixtures(t)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AttestedIssuance = fixtures.Config
	})
	token := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read")
	publicKeyPEM := servedAttestedPublicKeyPEM(t)

	k8s := servedAttestedIssue(t, h, token, "nhi-02-k8s", "k8s_sat", fixtures.K8sSAT, publicKeyPEM, http.StatusCreated)
	if k8s.Subject != "ns/default/sa/web" || k8s.Attestation.Method != "k8s_sat" {
		t.Fatalf("k8s attested issuance = %+v", k8s)
	}
	assertServedAttestedSVID(t, h, k8s, "spiffe://served.test/ns/default/sa/web")

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
	assertServedAttestedSVID(t, h, aws, "spiffe://served.test/i-0abc123")

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
