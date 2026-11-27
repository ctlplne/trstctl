// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHAProxyTargetCannotUseItsConfigAsTheCertificateBundle(t *testing.T) {
	for _, config := range []string{
		`{"profile":"host","crt_path":"/lab/haproxy.cfg","config_path":"/lab/haproxy.cfg"}`,
		`{"profile":"host","crt_path":"/lab/tls/../haproxy.cfg","config_path":"/lab/haproxy.cfg"}`,
	} {
		request := json.RawMessage(`{"name":"edge","connector":"haproxy","config":` + config + `}`)
		if _, err := parseDeploymentTargetRequest(request); err == nil || !strings.Contains(err.Error(), "crt_path must differ") {
			t.Fatalf("HAProxy config overwrite accepted or wrong error: %v", err)
		}
	}
	request := json.RawMessage(`{"name":"edge","connector":"haproxy","config":{"profile":"host","crt_path":"/lab/tls/server.pem","config_path":"/lab/haproxy.cfg"}}`)
	if _, err := parseDeploymentTargetRequest(request); err != nil {
		t.Fatalf("distinct certificate and config paths refused: %v", err)
	}
}
