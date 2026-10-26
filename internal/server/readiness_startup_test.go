// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// A149: /readyz now proves the two surfaces a restart can leave unservable
// while the datastore, event log, projection tail and signer are all up. With
// the SSH CA served, readiness reads ok for the revocation list and for audit
// history; while the KRL cannot be brought current the replica reads not
// ready and names the cause, and it recovers once the list can be served.
func TestReadinessProvesSSHKRLAndAuditReads(t *testing.T) {
	h := newServedHarness(t, config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}})
	readyz := func() (int, map[string]string) {
		t.Helper()
		resp, err := h.ts.Client().Get(h.ts.URL + "/readyz")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := readAllClose(resp)
		var out struct {
			Checks map[string]string `json:"checks"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("readyz body %s: %v", body, err)
		}
		return resp.StatusCode, out.Checks
	}
	code, checks := readyz()
	if code != http.StatusOK || checks["ssh_krl"] != "ok" || checks["audit_read"] != "ok" {
		t.Fatalf("healthy readiness = %d %v", code, checks)
	}

	ssh := h.srv.protocols.ssh
	ssh.syncMu.Lock()
	verified := ssh.verifiedSnapshot
	ssh.verifiedSnapshot.Generation = "another-generation"
	ssh.syncedFrom = time.Time{}
	ssh.syncMu.Unlock()
	code, checks = readyz()
	if code != http.StatusServiceUnavailable || !strings.Contains(checks["ssh_krl"], "cannot be brought up to date") || checks["audit_read"] != "ok" {
		t.Fatalf("readiness with an unservable KRL = %d %v", code, checks)
	}
	// The probe never copies the internal cause into the public response.
	if strings.Contains(checks["ssh_krl"], "generation") {
		t.Fatalf("readiness leaked the KRL's internal state: %q", checks["ssh_krl"])
	}

	ssh.syncMu.Lock()
	ssh.verifiedSnapshot = verified
	ssh.syncedFrom = time.Time{}
	ssh.syncMu.Unlock()
	if code, checks = readyz(); code != http.StatusOK || checks["ssh_krl"] != "ok" {
		t.Fatalf("readiness after the KRL recovered = %d %v", code, checks)
	}
}
