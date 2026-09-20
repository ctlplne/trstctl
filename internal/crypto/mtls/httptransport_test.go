// SPDX-License-Identifier: BUSL-1.1

package mtls_test

import (
	"crypto/tls"
	"os"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

func TestHTTPTransportForServerNamePinsRootNameAndTLSFloor(t *testing.T) {
	material, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), "private-ca.example.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, err := os.ReadFile(material.ControlPlane.PeerCAFile)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := mtls.HTTPTransportForServerName(rootPEM, "private-ca.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("server-auth transport did not install the operator root")
	}
	if transport.TLSClientConfig.ServerName != "private-ca.example.test" {
		t.Fatalf("server name = %q, want configured private-CA identity", transport.TLSClientConfig.ServerName)
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS minimum = %#x, want TLS 1.2 for external-CA compatibility", transport.TLSClientConfig.MinVersion)
	}
}
