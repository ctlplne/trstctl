// SPDX-License-Identifier: BUSL-1.1

package cmp_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	cmpsrv "trstctl.com/trstctl/internal/protocols/cmp"
)

// TestMalformedAnchorsFailClosedAtConstruction pins the fail-closed posture
// around the parse-once contract (AUD-201 follow-up E3/V33). The trust anchors
// are static per deployment, yet each message used to re-parse every anchor
// and rebuild the CertPool inside the request path — a malformed anchor then
// surfaced per message as a generic 400 "bad request" after the client's
// message was already parsed. With the anchors parsed ONCE at New, a broken
// trust configuration reads as the mount being unavailable (503) for every
// request. (The parse-once property itself is structural: the request path
// carries only the opaque pre-parsed handle, so a reintroduced per-message
// anchor parse cannot type-check.)
func TestMalformedAnchorsFailClosedAtConstruction(t *testing.T) {
	srv := cmpsrv.New(cmpsrv.Config{
		ProfileName:           "device",
		ClientTrustAnchorsDER: [][]byte{[]byte("not a certificate")},
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/cmp", "application/pkixcmp", bytes.NewReader([]byte{0x30, 0x03, 0x02, 0x01, 0x02}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("request against a mount with malformed anchors = %d, want 503: "+
			"a broken trust configuration must read as the mount being unavailable, not as the client's message being bad", resp.StatusCode)
	}
}
