// SPDX-License-Identifier: BUSL-1.1

package netsec_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/trust"
	"trstctl.com/trstctl/internal/crypto/trust/trusttest"
	"trstctl.com/trstctl/internal/netsec"
)

// Part 2 of the eMudhra response: every transport netsec builds carries the
// runtime distrust list. A chain through a distrusted intermediate key or a
// distrusted root is refused with the entry named; the same server verifies
// again once the entry is gone.
func TestNetsecTransportsRefuseDistrustedChains(t *testing.T) {
	srv := trusttest.New(t)
	client := netsec.InsecureLoopbackClient(5 * time.Second) // loopback is the only place a test server lives
	trusttest.TrustRoots(t, client.Transport.(*http.Transport), srv.RootsPEM)
	get := func() error {
		resp, err := client.Get(srv.URL)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	}
	if err := get(); err != nil {
		t.Fatalf("clean chain refused: %v", err)
	}
	trusttest.Install(t, srv.IntermediateList)
	err := get()
	var de *trust.DistrustError
	if err == nil || !errors.As(err, &de) || de.Entry.Name != "trusttest intermediate key" || !strings.Contains(err.Error(), "distrusted") {
		t.Fatalf("distrusted intermediate = %v, want the entry named", err)
	}
	trusttest.Install(t, srv.RootList)
	if err := get(); err == nil || !strings.Contains(err.Error(), "trusttest root") {
		t.Fatalf("distrusted root = %v", err)
	}
	if err := trust.SetOperator(nil); err != nil {
		t.Fatal(err)
	}
	if err := get(); err != nil {
		t.Fatalf("chain refused after the operator entry was removed: %v", err)
	}
	// SafeTransport carries the same check (it cannot dial loopback, so prove
	// the configuration rather than a handshake).
	if tr := netsec.SafeTransport(); tr.TLSClientConfig == nil || tr.TLSClientConfig.VerifyConnection == nil {
		t.Fatal("SafeTransport has no distrust check")
	}
}
