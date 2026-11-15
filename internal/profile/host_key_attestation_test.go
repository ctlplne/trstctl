// SPDX-License-Identifier: BUSL-1.1

package profile_test

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/profile"
)

// TestHostKeyAttestationPolicyIsExplicitTPMO1: a profile that requires host
// keys in the TPM names the tpm format and at least one PEM root, and survives
// its own JSON; one that does not require it accepts whatever is left in the
// fields, the way an unused device-attest policy does; and a required policy
// without its format or roots, or with a root that is not a certificate, is
// refused when the profile is authored.
func TestHostKeyAttestationPolicyIsExplicitTPMO1(t *testing.T) {
	root := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	valid := webProfile()
	valid.HostKeyAttestation = profile.HostKeyAttestationPolicy{Required: true, Format: "tpm", AttestationRootsPEM: []string{root}}
	if err := valid.ValidateDefinition(); err != nil {
		t.Fatalf("a required TPM policy with a root: %v", err)
	}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.ValidateSpec(raw); err != nil || !strings.Contains(string(raw), `"host_key_attestation":{"required":true,"format":"tpm"`) {
		t.Fatalf("spec %s: %v", raw, err)
	}
	unused := webProfile()
	unused.HostKeyAttestation = profile.HostKeyAttestationPolicy{Format: "other"}
	if err := unused.ValidateDefinition(); err != nil {
		t.Fatalf("a policy that is not required: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*profile.HostKeyAttestationPolicy)
		want   string
	}{
		{"no format", func(p *profile.HostKeyAttestationPolicy) { p.Format = "" }, `format must be "tpm"`},
		{"another format", func(p *profile.HostKeyAttestationPolicy) { p.Format = "android-key" }, `format must be "tpm"`},
		{"no roots", func(p *profile.HostKeyAttestationPolicy) { p.AttestationRootsPEM = nil }, "at least one operator attestation root"},
		{"a root that is not a certificate", func(p *profile.HostKeyAttestationPolicy) { p.AttestationRootsPEM = []string{"not a certificate"} }, "root 0 is not PEM certificate data"},
	} {
		p := valid
		policy := p.HostKeyAttestation
		policy.AttestationRootsPEM = append([]string(nil), policy.AttestationRootsPEM...)
		tc.mutate(&policy)
		p.HostKeyAttestation = policy
		if err := p.ValidateDefinition(); err == nil || !strings.Contains(err.Error(), "host_key_attestation") || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}
