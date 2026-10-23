// SPDX-License-Identifier: BUSL-1.1

package netsec_test

import (
	"errors"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/crypto/trust"
	"trstctl.com/trstctl/internal/crypto/trust/trusttest"
	"trstctl.com/trstctl/internal/netsec"
)

// Every binary hardens the process default transport first thing in main, so
// third-party code that uses http.DefaultClient is covered by the runtime
// distrust list as well. The call is idempotent.
func TestHardenProcessDefaultsCoversTheDefaultClient(t *testing.T) {
	netsec.HardenProcessDefaults()
	netsec.HardenProcessDefaults()
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("http.DefaultTransport is %T", http.DefaultTransport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.VerifyConnection == nil {
		t.Fatal("the process default transport carries no distrust check")
	}
	srv := trusttest.New(t)
	// Trust the test root on the default transport for this test only.
	trusttest.TrustRoots(t, tr, srv.RootsPEM)
	t.Cleanup(func() { tr.TLSClientConfig.RootCAs = nil })
	resp, err := http.DefaultClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("clean chain through the default client: %v", err)
	}
	_ = resp.Body.Close()
	trusttest.Install(t, srv.IntermediateList)
	_, err = http.DefaultClient.Get(srv.URL)
	var de *trust.DistrustError
	if err == nil || !errors.As(err, &de) || de.Entry.Name != "trusttest intermediate key" {
		t.Fatalf("distrusted chain through http.DefaultClient = %v, want the entry named", err)
	}
}
