// SPDX-License-Identifier: BUSL-1.1

package ctmonitor_test

import (
	"context"
	"encoding/pem"
	"os"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog"
	"trstctl.com/trstctl/internal/discovery/ctmonitor"
)

// Part 4: a CT hit the monitor keeps is rated from the logged certificate
// while its bytes are at hand. A leaf whose authority key identifier names
// EM OV TLS CA - G3C is a distrusted-issuer hit; a hit without bytes is rated
// from what the log entry recorded.
func TestPollRatesTheHitsItKeeps(t *testing.T) {
	data, err := os.ReadFile("../../keyposture/testdata/leaf-under-em-ov-tls-ca-g3c.pem") // #nosec G304 -- a fixed test fixture, named by the test itself (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	hit := entry("shop.example.com")
	hit.DER = block.Bytes
	hit.AuthorityKeyID = "34eaea0cebc90adaf9d0c5e2ed9b78c9879e1b6c"
	named := entry("api.example.com")
	named.Issuer = "CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL"
	f := &fakeFetcher{tree: []ctlog.Entry{hit, named, entry("plain.example.com")}}
	m, _ := newMonitor(t, f, false, "example.com")
	_, findings, err := m.Poll(context.Background(), tenant, ctmonitor.LogState{URL: "log-a"})
	if err != nil || len(findings) != 3 {
		t.Fatalf("findings = %+v, %v", findings, err)
	}
	if p := findings[0].Posture; p.DistrustEntry != "EM OV TLS CA - G3C" || p.DistrustHow != "issuer_key_id" || findings[0].AuthorityKeyID == "" {
		t.Fatalf("hit with bytes: %+v", findings[0])
	}
	if p := findings[1].Posture; p.DistrustEntry != "EM DV TLS CA - G3B" || p.DistrustHow != "issuer_name" {
		t.Fatalf("hit without bytes: %+v", findings[1].Posture)
	}
	if !findings[2].Posture.Empty() {
		t.Fatalf("an ordinary hit was rated: %+v", findings[2].Posture)
	}
}
