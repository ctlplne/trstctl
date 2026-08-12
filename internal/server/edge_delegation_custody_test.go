// SPDX-License-Identifier: MPL-2.0

package server

import (
	"reflect"
	"testing"
)

func TestEdgeCustodyPolicyDefaultsClosedAndRejectsAmbiguity(t *testing.T) {
	got, err := normalizeEdgeAllowedKeyProviders(nil)
	if err != nil || !reflect.DeepEqual(got, []string{"tpm2"}) {
		t.Fatalf("default allowed providers = %v err=%v, want TPM2 only", got, err)
	}
	if _, err := normalizeEdgeAllowedKeyProviders([]string{"tpm2", "TPM2"}); err == nil {
		t.Fatal("case-folded duplicate provider was accepted")
	}
	if _, err := normalizeEdgeAllowedKeyProviders([]string{"cloud-kms"}); err == nil {
		t.Fatal("unknown provider was accepted into the edge custody policy")
	}
}

func TestEdgeCustodyEvidenceTuplesCannotOverstateProof(t *testing.T) {
	cases := []struct {
		provider   string
		storage    string
		exportable bool
		assurance  string
	}{
		{"tpm2", "device_bound", false, "hardware_key_attested"},
		{"pkcs11", "pkcs11", false, "host_attested_operator_claim"},
		{"software", "file", true, "host_attested_software_exception"},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			provider, got, err := edgeCustodyForProvider(tc.provider)
			if err != nil {
				t.Fatal(err)
			}
			if provider != tc.provider || got.storage != tc.storage || got.exportable != tc.exportable || got.assurance != tc.assurance {
				t.Fatalf("custody tuple = provider:%q storage:%q exportable:%t assurance:%q", provider, got.storage, got.exportable, got.assurance)
			}
		})
	}
}
