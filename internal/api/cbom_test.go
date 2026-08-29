// SPDX-License-Identifier: MPL-2.0

package api

import (
	"strings"
	"testing"
)

func TestNormalizeCBOMScanRequestMakesFriendlyInputsExact(t *testing.T) {
	got, err := NormalizeCBOMScanRequest(CBOMScanRequest{
		TLSEndpoints: []string{" HTTPS://API.EXAMPLE.COM ", "api.example.com:443", "[2001:db8::1]"},
		HostConfigs:  []string{" /etc/nginx/*.conf ", "/etc/nginx/*.conf"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.TLSEndpoints, ",") != "[2001:db8::1]:443,api.example.com:443" {
		t.Fatalf("normalized TLS endpoints = %v", got.TLSEndpoints)
	}
	if len(got.HostConfigs) != 1 || got.HostConfigs[0] != "/etc/nginx/*.conf" {
		t.Fatalf("normalized host configs = %v", got.HostConfigs)
	}
}

func TestNormalizeCBOMScanRequestRejectsAmbiguousOrOverbroadInputs(t *testing.T) {
	tests := []CBOMScanRequest{
		{},
		{TLSEndpoints: []string{"https://example.com/admin"}},
		{TLSEndpoints: []string{"example.com:70000"}},
		{HostConfigs: []string{"relative/nginx.conf"}},
		{TLSEndpoints: make([]string, CBOMMaxTLSEndpoints+1)},
	}
	for i, req := range tests {
		if _, err := NormalizeCBOMScanRequest(req); err == nil {
			t.Fatalf("case %d accepted unsafe or ambiguous input: %+v", i, req)
		}
	}
}
