// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
	"trstctl.com/trstctl/internal/custody"
)

// A131 through the served issuer: an ACME issuance whose key the device's TPM
// attested as device-bound records that claim on the certificate. The custody
// fields and the evidence read back from PostgreSQL re-verify offline against
// the issued certificate and the operator's TPM root; a retried finalize
// replays the same claim, and different evidence for the same certificate is
// refused rather than replacing it.
func TestServedACMEDeviceAttestedIssuanceRecordsAVerifiableDeviceBoundClaim(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	verifiedAt := time.Now().UTC().Truncate(time.Second)
	identity, err := deviceattesttest.NewTPMIdentity(verifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	keyDigest, err := deviceattest.CSRPublicKeySHA256(identity.CSRDER())
	if err != nil {
		t.Fatal(err)
	}
	binding := []byte(`{"version":1,"tenant_id":"` + h.tenant + `","order_id":"order-device-1","identifier":"host-01.example.test","csr_key_sha256":"` +
		base64.RawURLEncoding.EncodeToString(keyDigest) + `"}`)
	credential, err := identity.CredentialJSON(crypto.SHA256Sum(binding))
	if err != nil {
		t.Fatal(err)
	}
	result, err := deviceattest.ParseAndVerifyTPMDeviceAttestation(credential, crypto.SHA256Sum(binding),
		[][]byte{identity.RootPEM()}, []int64{-7}, verifiedAt)
	if err != nil || !result.DeviceBound {
		t.Fatalf("fixture attestation = %+v, %v", result, err)
	}
	evidence := &ca.DeviceAttestation{
		Format: "tpm-webauthn", Credential: credential, Binding: binding,
		PublicKeySHA256: result.PublicKeySHA256, AttestationCertificateSHA256: result.AttestationCertificateSHA256,
		TrustedRootsSHA256: crypto.SHA256Sum(identity.RootPEM()), VerifiedAt: verifiedAt,
	}
	adapter := protocolCAAdapter{tenantID: h.tenant, issuer: h.srv.newProtocolIssuer(), caCertDER: h.srv.caCertDER}
	request := ca.IssueRequest{
		TenantID: h.tenant, CSR: identity.CSRDER(), DNSNames: []string{"host-01.example.test"},
		TTL: 24 * time.Hour, ProviderIdempotencyKey: "order-device-1", Protocol: "acme", DeviceAttestation: evidence,
	}
	issued, err := adapter.Issue(ctx, request)
	if err != nil {
		t.Fatalf("attested ACME issuance: %v", err)
	}
	info, err := certinfo.Inspect(issued.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, info.SHA256Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if cert.KeyOrigin != string(custody.OriginDevice) || cert.KeyStorage != string(custody.StorageDeviceBound) ||
		cert.KeyExportable != string(custody.NonExportable) || !strings.HasPrefix(cert.KeyGeneratedBy, "tpm-ak:sha256:") {
		t.Fatalf("custody of the attested certificate = %+v", cert)
	}
	retained, err := h.store.GetCertificateKeyAttestation(ctx, h.tenant, cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deviceattest.VerifyTPMCustodyEvidence(deviceattest.TPMCustodyEvidence{
		Credential: retained.Credential, Binding: retained.Binding, VerifiedAt: retained.VerifiedAt,
	}, issued.CertificatePEM, [][]byte{identity.RootPEM()}); err != nil {
		t.Fatalf("evidence read back from PostgreSQL does not re-verify against the issued certificate: %v", err)
	}

	// The served evidence route hands an auditor everything the offline check
	// needs except the roots, which stay the auditor's choice.
	token := seedScopedToken(t, h.store, h.tenant, "certs:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+cert.ID+"/key-attestation", token, nil)
	if status != http.StatusOK {
		t.Fatalf("key attestation route = %d body=%s", status, body)
	}
	var served api.CertificateKeyAttestation
	if err := json.Unmarshal(body, &served); err != nil {
		t.Fatal(err)
	}
	if served.Fingerprint != cert.Fingerprint || !bytes.Equal(served.Credential, credential) || served.Format != "tpm-webauthn" {
		t.Fatalf("served evidence = %+v", served)
	}
	if _, err := deviceattest.VerifyTPMCustodyEvidence(deviceattest.TPMCustodyEvidence{
		Credential: served.Credential, Binding: served.Binding, VerifiedAt: served.VerifiedAt,
	}, []byte(served.CertificatePEM), [][]byte{identity.RootPEM()}); err != nil {
		t.Fatalf("served evidence does not re-verify offline: %v", err)
	}
	plainIdentity, err := deviceattesttest.NewTPMIdentity(verifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	plainIssued, err := adapter.Issue(ctx, ca.IssueRequest{
		TenantID: h.tenant, CSR: plainIdentity.CSRDER(), DNSNames: []string{"host-01.example.test"},
		TTL: 24 * time.Hour, ProviderIdempotencyKey: "order-plain-1", Protocol: "acme",
	})
	if err != nil {
		t.Fatal(err)
	}
	plainInfo, err := certinfo.Inspect(plainIssued.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, plainInfo.SHA256Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if plain.KeyOrigin != string(custody.OriginRequester) {
		t.Fatalf("an unattested ACME certificate claims custody %q", plain.KeyOrigin)
	}
	if status, _ := secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+plain.ID+"/key-attestation", token, nil); status != http.StatusNotFound {
		t.Fatalf("a certificate without a device claim served evidence: %d", status)
	}

	again, err := adapter.Issue(ctx, request)
	if err != nil || !bytes.Equal(again.CertificatePEM, issued.CertificatePEM) {
		t.Fatalf("retried finalize = %v (same certificate %t)", err, bytes.Equal(again.CertificatePEM, issued.CertificatePEM))
	}
	other := *evidence
	other.VerifiedAt = verifiedAt.Add(time.Minute)
	request.DeviceAttestation = &other
	if _, err := adapter.Issue(ctx, request); err == nil {
		t.Fatal("different evidence replaced the certificate's recorded device claim")
	}
}
