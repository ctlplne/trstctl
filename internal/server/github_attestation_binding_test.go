// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"maps"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
)

// CR-384: metadata added during proof verification must preserve the binding
// for commands already submitted or approved.
func TestGitHubEvidencePreservesLegacyCommandBindings(t *testing.T) {
	legacy := attest.Attestation{
		ID: "verified-workflow", Method: "github_oidc", Subject: "repo:acme/widgets",
		Claims:    map[string]string{"repository": "acme/widgets", "owner": "acme"},
		Selectors: []string{"github:owner:acme", "github:repository:acme/widgets"},
	}
	current := legacy
	current.Claims = maps.Clone(legacy.Claims)
	current.Claims["repository_owner_id"] = "123"
	current.Claims["repository_id"] = "456"
	current.Selectors = append(slices.Clone(legacy.Selectors), "github:repository_id:456", "github:repository_owner_id:123")
	slices.Sort(current.Selectors)

	const tenant = "11111111-1111-4111-8111-111111111111"
	workflow := api.EphemeralCredentialRequest{RequestID: "ephemeral-request", Method: "github_oidc", TTLSeconds: 60}
	issuer := ephemeralIssuerService{
		caID: IssuingCAID(), caCertDER: []byte("public-ca-fixture"), trustDomain: "ci.example.test",
		defaultTTL: time.Minute, maxTTL: time.Hour,
	}
	attempt := attestedIssuerService{caID: "test-ca", caCertDER: []byte("public-ca-fixture")}
	pam := pamService{
		defaultTTL: time.Minute, maxTTL: time.Hour,
		sshTargets: map[pamTargetID]PAMSSHTarget{
			{tenant, "bastion"}: {TenantID: tenant, ID: "bastion", Host: "bastion.example.test", Port: 22},
		},
	}
	pamRequest := api.PAMSessionRequest{
		RequestID: "pam-request", TargetType: pamTargetSSH, TargetID: "bastion", Role: "operator",
		Method: "github_oidc", TTLSeconds: 60, TemplateResolved: true,
	}
	for _, tc := range []struct {
		name   string
		golden string
		digest func(attest.Attestation) (string, error)
	}{
		{"GitHub attempt", "acbee79a20298100112766be582c30685df0392dbbc6c6c45ccdeb00b855fd31", func(proof attest.Attestation) (string, error) {
			return attempt.githubAttemptRequestBinding(proof, []byte("public-key-fixture"), "spiffe://ci.example.test/workflow", time.Minute)
		}},
		{"ephemeral retained command", "b5e26811863da67edd29281ec1e848fe58cbc02545cc147a6a405aa67e06ecac", func(proof attest.Attestation) (string, error) {
			return ephemeralApprovedRequestBinding("workflow-caller", workflow, proof)
		}},
		{"ephemeral approval", "a7b8a080e3ed5215f2fcf59313ae2487e07a10d7fd36765634989215adbcc06c", func(proof attest.Attestation) (string, error) {
			binding, err := issuer.ephemeralApprovalBinding(tenant, workflow, proof)
			if err != nil {
				return "", err
			}
			return binding.Digest()
		}},
		{"PAM approval", "a108995d85ce2e3d2e0d7abb04129a3e9aeadc737f8fc6fa5207e908b9a1d03f", func(proof attest.Attestation) (string, error) {
			return pam.approvalCommandDigest(t.Context(), tenant, "workflow-caller", pamRequest, proof)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, err := tc.digest(legacy)
			if err != nil {
				t.Fatal(err)
			}
			if before != tc.golden {
				t.Errorf("legacy digest = %s, want %s", before, tc.golden)
			}
			after, err := tc.digest(current)
			if err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Errorf("legacy digest %s changed to %s when verified ID evidence was added", before, after)
			}
		})
	}
}
