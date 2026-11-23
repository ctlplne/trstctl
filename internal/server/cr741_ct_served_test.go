// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"math"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestCR741ServedFutureSCTNeverEntersEventLog(t *testing.T) {
	log := ctlogtest.NewSigningServer(ctlogtest.WithSCTTimestampMillis(math.MaxInt64))
	t.Cleanup(log.Close)
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "certs:write", "certs:read", string(authz.PrivateEgress))
	_, certPEM := issueCTFixtureCertificate(t, h, "cr741.example.test")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/revocation/ct-submissions", token, map[string]any{
		"certificate_pem":        certPEM,
		"logs":                   []string{log.URL()},
		"log_public_keys":        map[string]string{log.URL(): base64.StdEncoding.EncodeToString(log.PublicKeyDER())},
		"allow_private_endpoint": true,
		"private_egress_cidrs":   []string{serviceNowSinkCIDR(t, log.URL())},
	})
	if status != http.StatusAccepted {
		t.Fatalf("queue CT submission: status %d body %s", status, body)
	}
	claimed, err := h.srv.outbox.DispatchOneScoped(t.Context(), h.srv.obHandler,
		orchestrator.DestinationScope{IncludePrefixes: []string{ctSubmissionDestination}})
	if err != nil || !claimed {
		t.Fatalf("dispatch the hostile CT response: claimed=%v err=%v", claimed, err)
	}
	if h.hasEvent(t, "ct.sct.recorded") || h.hasEvent(t, "ct.submission.delivered") {
		t.Fatal("an out-of-range SCT entered the append-only event log")
	}
}
