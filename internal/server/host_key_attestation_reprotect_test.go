// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
	"trstctl.com/trstctl/internal/store"
)

// TestCAReprotectionOfATPMHeldKeyIsJudgedByItsIdentityProfileTPMO1L1: the
// control plane checks a CA re-protection's TPM attestation under the
// identity's profile, the revision-pinned binding the re-protection resolves
// (caReprotectProfileBinding), since a re-protection job carries no issuance
// binding of its own. With that profile's roots, the TPM's attestation of the
// CSR's key for this job is accepted and its evidence kept; another TPM's is
// not; and without the binding the default profile, which names no TPM roots,
// refuses the CSR, as SignJobCSR did before.
func TestCAReprotectionOfATPMHeldKeyIsJudgedByItsIdentityProfileTPMO1L1(t *testing.T) {
	now := time.Now().UTC()
	hostTPM, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	otherTPM, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "profiles:write")
	for name, spec := range map[string]map[string]any{
		"tpm-o1-l1-web": {"max_validity": "12m", "allowed_protocols": []string{"api"}, "allowed_dns_suffixes": []string{"tpm.test"},
			"host_key_attestation": map[string]any{"required": true, "format": "tpm", "attestation_roots_pem": []string{string(hostTPM.RootPEM())}}},
		"tpm-o1-l1-plain": {"max_validity": "12m", "allowed_protocols": []string{"api"}},
	} {
		if code, body := secretsReq(t, h, http.MethodPost, "/api/v1/profiles", token, map[string]any{"name": name, "spec": spec}); code != http.StatusCreated {
			t.Fatalf("profile %s: HTTP %d %s", name, code, body)
		}
	}
	rec, err := h.store.GetActiveProfile(t.Context(), h.tenant, "tpm-o1-l1-web")
	if err != nil {
		t.Fatal(err)
	}
	identityProfile := &store.OperationApprovalIssuanceBinding{ProfileName: "tpm-o1-l1-web", ProfileID: rec.ID,
		ProfileVersion: rec.Version, ProfileSpecDigest: store.ProfileSpecDigest(rec.Spec)}
	d := &issuanceDispatcher{store: h.store, defaultProfile: "tpm-o1-l1-plain"}
	intent := RelayDeployIntent{Connector: "nginx", KeyCustody: "tpm", ReprotectJobID: "vdec-tpm-o1-l1",
		ReprotectPredecessorFingerprint: "predecessor", ReprotectPredecessorSPKISHA256: "spki", ReprotectTTLSeconds: 3600}
	csrDER, err := hostTPM.CSRDERFor("web.tpm.test")
	if err != nil {
		t.Fatal(err)
	}
	const jobID = 4242
	binding, err := deviceattest.HostKeyBinding(jobID, csrDER)
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := hostTPM.CredentialJSON(crypto.SHA256Sum(binding))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := d.verifyHostKeyAttestation(t.Context(), h.tenant, jobID, intent, identityProfile, csrDER, attestation)
	if err != nil || evidence == nil || evidence.Format != "tpm-webauthn" || string(evidence.Binding) != string(binding) {
		t.Fatalf("under the identity's profile: evidence %+v, %v", evidence, err)
	}
	foreign, err := otherTPM.CredentialJSON(crypto.SHA256Sum(binding))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.verifyHostKeyAttestation(t.Context(), h.tenant, jobID, intent, identityProfile, csrDER, foreign); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("another TPM's attestation = %v, want PermissionDenied", err)
	}
	if _, err := d.verifyHostKeyAttestation(t.Context(), h.tenant, jobID, intent, nil, csrDER, attestation); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "no longer names TPM attestation roots") {
		t.Fatalf("without the identity's profile = %v, want the default profile's refusal", err)
	}
}
