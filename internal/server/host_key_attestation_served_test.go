// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/orchestrator"
)

// TestServedTPMHostRenewalSignsOnlyAnAttestedTPMKeyTPMO1 (TPM-O1, served):
// a profile whose host_key_attestation is required (authored only with a
// root) queues its nginx host renewal with key_custody "tpm"; SignJobCSR
// refuses the CSR without an attestation, with one over another job's
// binding, for a key the TPM would let leave, and from another TPM; it signs
// with the TPM's attestation of the CSR's key for this job, and records the
// certificate's custody as a device-origin, device-bound, non-exportable key
// with that evidence, which the key-attestation API returns and which re-verifies
// offline. The agent's receipt must make the same claim: a file-key receipt
// is refused, the device-bound one accepted.
func TestServedTPMHostRenewalSignsOnlyAnAttestedTPMKeyTPMO1(t *testing.T) {
	now := time.Now().UTC()
	hostTPM, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	otherTPM, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{agentJobKindEndpointRenew}, func(d *Deps) {
		d.DefaultProfile = "tpm-web"
	}, withIsolatedTenant)
	token := seedScopedToken(t, h.store, h.tenant, "owners:write", "connectors:write", "certs:issue", "certs:read", "profiles:write", "identities:write")
	post := func(path string, input any, expected int) map[string]json.RawMessage {
		t.Helper()
		code, body := secretsReq(t, h.servedHarness, http.MethodPost, path, token, input)
		if code != expected {
			t.Fatalf("POST %s: HTTP %d, want %d: %s", path, code, expected, body)
		}
		var result map[string]json.RawMessage
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	str := func(raw json.RawMessage) string {
		t.Helper()
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	spec := map[string]any{"max_validity": "12m", "allowed_protocols": []string{"api"}, "allowed_dns_suffixes": []string{"tpm.test"},
		"host_key_attestation": map[string]any{"required": true, "format": "tpm"}}
	if code, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/profiles", token, map[string]any{"name": "tpm-web", "spec": spec}); code != http.StatusBadRequest ||
		!strings.Contains(string(body), "host_key_attestation") {
		t.Fatalf("a required host key attestation without a root: HTTP %d %s", code, body)
	}
	spec["host_key_attestation"] = map[string]any{"required": true, "format": "tpm", "attestation_roots_pem": []string{string(hostTPM.RootPEM())}}
	post("/api/v1/profiles", map[string]any{"name": "tpm-web", "spec": spec}, http.StatusCreated)
	owner := str(post("/api/v1/owners", map[string]any{"kind": "workload", "name": "TPM web"}, http.StatusCreated)["id"])
	target := str(post("/api/v1/connectors/targets", map[string]any{
		"name": "tpm-web", "connector": "nginx", "enabled": true,
		"config": map[string]any{"executor": "agent", "required_agent_role": "host", "required_agent_id": registeredRoleAgentID(t, h),
			"cert_path": "/etc/nginx/tls/web.crt", "key_path": "/etc/nginx/tls/web.key",
			"verify_address": "127.0.0.1:18443", "verify_server_name": "web.tpm.test"},
	}, http.StatusCreated)["id"])
	request := map[string]any{"owner_id": owner, "identity_name": "web.tpm.test", "target_id": target,
		"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}, "reason": "prove a TPM-held host key"}
	request["preview_fingerprint"] = str(post("/api/v1/lifecycle/endpoint-bindings/preview", request, http.StatusOK)["request_fingerprint"])
	post("/api/v1/lifecycle/endpoint-bindings", request, http.StatusCreated)
	if _, err := h.srv.outbox.DispatchOneScoped(t.Context(), h.srv.obHandler, orchestrator.DestinationScope{IncludePrefixes: []string{"ca.issue"}}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	job := claimOneRenewal(t, t.Context(), h)
	var intent RelayDeployIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil {
		t.Fatal(err)
	}
	if intent.KeyCustody != "tpm" || intent.Connector != "nginx" {
		t.Fatalf("queued intent key_custody=%q connector=%q, want tpm nginx", intent.KeyCustody, intent.Connector)
	}

	csrDER, err := hostTPM.CSRDERFor("web.tpm.test")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := deviceattest.HostKeyBinding(job.JobID, csrDER)
	if err != nil {
		t.Fatal(err)
	}
	challenge := crypto.SHA256Sum(binding)
	credential := func(identity *deviceattesttest.TPMIdentity, challenge []byte, deviceBound bool) []byte {
		t.Helper()
		var raw []byte
		var err error
		if deviceBound {
			raw, err = identity.CredentialJSON(challenge)
		} else {
			raw, err = identity.DuplicableCredentialJSON(challenge)
		}
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	otherJob, err := deviceattest.HostKeyBinding(job.JobID+1, csrDER)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(attestation []byte) (*transport.SignJobCSRResponse, error) {
		return h.client.SignJobCSR(t.Context(), &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: csrDER, KeyAttestation: attestation})
	}
	for _, tc := range []struct {
		name        string
		attestation []byte
		want        string
	}{
		{"no attestation", nil, "carries no attestation"},
		{"another job's binding", credential(hostTPM, crypto.SHA256Sum(otherJob), true), "was not accepted"},
		{"a key that could leave the TPM", credential(hostTPM, challenge, false), "could leave the TPM"},
		{"another TPM", credential(otherTPM, challenge, true), "was not accepted"},
	} {
		if _, err := sign(tc.attestation); status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v, want PermissionDenied naming %q", tc.name, err, tc.want)
		}
	}
	valid := credential(hostTPM, challenge, true)
	issued, err := sign(valid)
	if err != nil {
		t.Fatalf("sign with the TPM's attestation: %v", err)
	}
	again, err := sign(valid)
	if err != nil || again.Fingerprint != issued.Fingerprint {
		t.Fatalf("the same request again = %+v, %v; want the same certificate", again, err)
	}

	agentName := h.identity.Identity().CommonName()
	cert, err := h.store.GetCertificateByFingerprint(t.Context(), h.tenant, issued.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if cert.KeyOrigin != string(custody.OriginDevice) || cert.KeyStorage != string(custody.StorageDeviceBound) ||
		cert.KeyExportable != string(custody.NonExportable) || cert.KeyGeneratedBy != agentName {
		t.Fatalf("custody = origin %q storage %q exportable %q generated by %q", cert.KeyOrigin, cert.KeyStorage, cert.KeyExportable, cert.KeyGeneratedBy)
	}
	code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/certificates/"+cert.ID+"/key-attestation", token, nil)
	if code != http.StatusOK {
		t.Fatalf("key attestation: HTTP %d %s", code, body)
	}
	var evidence struct {
		Source         string    `json:"source"`
		Format         string    `json:"format"`
		Credential     []byte    `json:"credential"`
		Binding        []byte    `json:"binding"`
		VerifiedAt     time.Time `json:"verified_at"`
		CertificatePEM string    `json:"certificate_pem"`
	}
	if err := json.Unmarshal(body, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Source != "host_agent_tpm" || evidence.Format != "tpm-webauthn" || string(evidence.Binding) != string(binding) || string(evidence.Credential) != string(valid) {
		t.Fatalf("evidence source %q format %q binding %s", evidence.Source, evidence.Format, evidence.Binding)
	}
	if _, err := deviceattest.VerifyTPMCustodyEvidence(deviceattest.TPMCustodyEvidence{Credential: evidence.Credential, Binding: evidence.Binding, VerifiedAt: evidence.VerifiedAt},
		[]byte(evidence.CertificatePEM), [][]byte{hostTPM.RootPEM()}); err != nil {
		t.Fatalf("offline re-verification of the custody evidence: %v", err)
	}

	detail, digest := simulatedHostVerification(t, h, job, issued.Fingerprint, transport.JobOutcomeVerified)
	id := h.identity.Identity()
	receipt := func(record custody.Record) *transport.ReportJobResultRequest {
		t.Helper()
		req, err := transport.SignedReportWithCustody(id, id.TenantID(), id.CommonName(), job.JobID, job.Attempt,
			transport.JobOutcomeVerified, detail, digest, issued.Fingerprint, record, time.Now().UTC().Unix())
		if err != nil {
			t.Fatal(err)
		}
		return req
	}
	fileKey := custody.Record{Origin: custody.OriginHostAgent, Storage: custody.StorageFile, Exportable: custody.Exportable, GeneratedBy: agentName}
	if _, err := h.client.ReportJobResult(t.Context(), receipt(fileKey)); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("a file-key receipt for a TPM-held key = %v, want a refusal", err)
	}
	tpmKey := custody.Record{Origin: custody.OriginDevice, Storage: custody.StorageDeviceBound, Exportable: custody.NonExportable, GeneratedBy: agentName}
	if accepted, err := h.client.ReportJobResult(t.Context(), receipt(tpmKey)); err != nil || !accepted.Accepted {
		t.Fatalf("the device-bound receipt = %+v, %v", accepted, err)
	}
	after, err := h.store.GetCertificateByFingerprint(t.Context(), h.tenant, issued.Fingerprint)
	if err != nil || after.KeyStorage != string(custody.StorageDeviceBound) || after.KeyExportable != string(custody.NonExportable) {
		t.Fatalf("custody after the receipt = %+v, %v", after, err)
	}
	t.Logf("TPMO1_SERVED_OK fingerprint=%s binding=%s", issued.Fingerprint, binding)
}

// TestServedSignJobCSRRefusesAnAttestationNoJobAskedForTPMO1: a renewal job
// queued without key_custody, under no host key attestation policy, refuses a
// request that carries a key attestation instead of keeping evidence nothing
// asked for.
func TestServedSignJobCSRRefusesAnAttestationNoJobAskedForTPMO1(t *testing.T) {
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{agentJobKindEndpointRenew}, withIsolatedTenant)
	seedRenewalJob(t, t.Context(), h, "renew:tpm-o1-unasked", []string{"plain.example.test"})
	job := claimOneRenewal(t, t.Context(), h)
	key, err := crypto.GenerateHostSubjectKey("plain.example.test", []string{"plain.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	_, err = h.client.SignJobCSR(t.Context(), &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER, KeyAttestation: []byte("{}")})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "asks for no key attestation") {
		t.Fatalf("an unasked attestation = %v, want InvalidArgument", err)
	}
	if _, err := h.client.SignJobCSR(t.Context(), &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER}); err != nil {
		t.Fatalf("the same job without it: %v", err)
	}
}
