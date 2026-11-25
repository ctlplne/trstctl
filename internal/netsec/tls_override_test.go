// SPDX-License-Identifier: BUSL-1.1

package netsec_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/trust"
	"trstctl.com/trstctl/internal/crypto/trust/trusttest"
	"trstctl.com/trstctl/internal/netsec"
)

func TestAdoptTLSConfigKeepsEgressDialerAndDistrust(t *testing.T) {
	srv := trusttest.New(t)
	source, err := mtls.HTTPTransport(srv.RootsPEM)
	if err != nil {
		t.Fatal(err)
	}
	client := netsec.InsecureLoopbackClient(5 * time.Second)
	destination, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("safe client transport = %T", client.Transport)
	}
	dial := destination.DialContext
	if err := netsec.AdoptTLSConfig(destination, source); err != nil {
		t.Fatal(err)
	}
	if destination.DialContext == nil || dial == nil || destination.TLSClientConfig == source.TLSClientConfig {
		t.Fatal("TLS adoption lost the scoped dialer or reused a mutable source configuration")
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("clean server through adopted TLS: %v", err)
	}
	_ = resp.Body.Close()
	trusttest.Install(t, srv.IntermediateList)
	_, err = client.Get(srv.URL)
	var distrusted *trust.DistrustError
	if !errors.As(err, &distrusted) {
		t.Fatalf("adopted TLS accepted a distrusted peer: %v", err)
	}
	if err := netsec.AdoptTLSConfig(destination, nil); err == nil {
		t.Fatal("missing source configuration was accepted")
	}
	source.TLSClientConfig.InsecureSkipVerify = true
	if err := netsec.AdoptTLSConfig(destination, source); err == nil {
		t.Fatal("a source that disables certificate verification was accepted")
	}
}
