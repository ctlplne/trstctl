// SPDX-License-Identifier: BUSL-1.1

package cloudsecret

import (
	"strings"
	"testing"
)

func TestDecodeSourceConfigExactCaseAndCanonicalBytes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		ok   bool
	}{
		{"canonical", `{"providers":[{"provider":"hashicorp-vault","token_ref":"env:APPROVED","allow_private_endpoint":true,"private_egress_cidrs":["10.0.0.0/8"]}]}`, true},
		{"mis-cased reference", `{"providers":[{"provider":"hashicorp-vault","Token_Ref":"env:SECRET"}]}`, false},
		{"mis-cased private grant", `{"providers":[{"provider":"hashicorp-vault","Allow_Private_Endpoint":true}]}`, false},
		{"fold-equal duplicate", `{"providers":[{"provider":"hashicorp-vault","token_ref":"env:APPROVED","Token_Ref":"env:SECRET"}]}`, false},
		{"exact duplicate", `{"providers":[{"provider":"hashicorp-vault","token_ref":"env:APPROVED","token_ref":"env:SECRET"}]}`, false},
		{"unknown field", `{"providers":[{"provider":"hashicorp-vault","another_ref":"env:SECRET"}]}`, false},
		{"mis-cased root", `{"Providers":[{"provider":"hashicorp-vault"}]}`, false},
		{"duplicate root", `{"providers":[],"providers":[{"provider":"hashicorp-vault"}]}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, canonical, err := DecodeSourceConfig([]byte(tt.raw))
			if (err == nil) != tt.ok {
				t.Fatalf("DecodeSourceConfig error = %v, want success %v", err, tt.ok)
			}
			if !tt.ok {
				return
			}
			if len(cfg.Providers) != 1 || cfg.Providers[0].TokenRef != "env:APPROVED" || !cfg.Providers[0].AllowPrivateEndpoint {
				t.Fatalf("decoded config = %+v", cfg)
			}
			if strings.Contains(string(canonical), "Token_Ref") || strings.Contains(string(canonical), "Allow_Private_Endpoint") {
				t.Fatalf("canonical config retains mis-cased key: %s", canonical)
			}
		})
	}
}

func FuzzDecodeSourceConfig(f *testing.F) {
	f.Add([]byte(`{"providers":[{"provider":"hashicorp-vault","token_ref":"env:APPROVED"}]}`))
	f.Add([]byte(`{"providers":[{"provider":"hashicorp-vault","Token_Ref":"env:SECRET"}]}`))
	f.Add([]byte(`{"providers":[{"token_ref":"env:A","token_ref":"env:B"}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		cfg, canonical, err := DecodeSourceConfig(raw)
		if err != nil {
			return
		}
		again, recanonical, err := DecodeSourceConfig(canonical)
		if err != nil || string(recanonical) != string(canonical) || len(again.Providers) != len(cfg.Providers) {
			t.Fatalf("accepted config does not round trip: err=%v canonical=%q", err, canonical)
		}
	})
}
