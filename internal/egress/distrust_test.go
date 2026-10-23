// SPDX-License-Identifier: BUSL-1.1

package egress_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/trust"
	"trstctl.com/trstctl/internal/crypto/trust/trusttest"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/netsec"
)

// The egress guard's wrapped transports carry the runtime distrust list too,
// so an air-gapped deployment that allowlists a host still refuses a
// distrusted chain from it; a plain transport handed to the guard leaves
// hardened and cloned.
func TestGuardTransportsRefuseDistrustedChains(t *testing.T) {
	srv := trusttest.New(t)
	guard, err := egress.NewGuard(egress.Config{Enabled: true, AllowPrivate: true, AllowHosts: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	base := netsec.InsecureLoopbackClient(5 * time.Second).Transport.(*http.Transport)
	trusttest.TrustRoots(t, base, srv.RootsPEM)
	client := &http.Client{Transport: guard.WrapTransport(base), Timeout: 5 * time.Second}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("clean chain refused through the guard: %v", err)
	}
	_ = resp.Body.Close()
	trusttest.Install(t, srv.IntermediateList)
	_, err = client.Get(srv.URL)
	var de *trust.DistrustError
	if err == nil || !errors.As(err, &de) {
		t.Fatalf("distrusted chain through the guard = %v", err)
	}
	// A plain default transport handed to the guard is hardened without
	// touching the process default.
	wrapped := guard.WrapTransport(http.DefaultTransport)
	if wrapped == http.RoundTripper(http.DefaultTransport) {
		t.Fatal("the guard returned the process default transport unhardened")
	}
	if cfg := http.DefaultTransport.(*http.Transport).TLSClientConfig; cfg != nil && cfg.VerifyConnection != nil {
		t.Fatal("the process default transport was mutated")
	}
	if netsec.HardenedDefaultTransport().TLSClientConfig.VerifyConnection == nil || netsec.HardenedClient(time.Second).Transport.(*http.Transport).TLSClientConfig.VerifyConnection == nil {
		t.Fatal("the hardened default transport has no distrust check")
	}
}
