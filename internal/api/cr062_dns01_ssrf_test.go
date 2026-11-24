// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCR062DNS01ConfigRejectsPrivateEndpointsBeforeAppend(t *testing.T) {
	for _, tc := range []struct {
		provider string
		config   string
	}{
		{"webhook", `{"endpoint":"http://127.0.0.1:8080/update"}`},
		{"cloudflare", `{"endpoint":"https://169.254.169.254/latest"}`},
		{"rfc2136", `{"server":"127.0.0.1:53"}`},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			body := `{"name":"test","provider":"` + tc.provider + `","config":` + tc.config + `}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/acme/dns01/provider-configs", strings.NewReader(body))
			if _, err := (&API{}).decodeACMEDNS01ProviderConfigRequest(req); err == nil {
				t.Fatal("tenant DNS-01 config reached the event append path with a private endpoint")
			}
		})
	}
}
