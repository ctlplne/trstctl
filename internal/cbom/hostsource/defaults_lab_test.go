// SPDX-License-Identifier: BUSL-1.1

package hostsource_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cbom/hostsource"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

// TLS 1.0 and 1.1 wire versions, to cap a probe below TLS 1.2.
const (
	labTLS10 uint16 = 0x0301
	labTLS11 uint16 = 0x0302
)

// TestHostDefaultsAgreeWithTheEndpointScanX2L7Lab (scripts/labs/
// product-defaults.sh): stock HAProxy and OpenSSL from Alpine's own packages
// serve TLS with their packaged defaults, a HAProxy listener stating no
// minimum or curves and openssl s_server with the packaged openssl.cnf. The
// host scan over the container's haproxy.cfg, openssl.cnf and apk database
// claims each default; the endpoint scan of each listener then finds the
// claimed minimum the lowest version it accepts, and accepts the hybrid
// X25519MLKEM768 exactly when that is the claimed default group.
func TestHostDefaultsAgreeWithTheEndpointScanX2L7Lab(t *testing.T) {
	dir := os.Getenv("TRSTCTL_X2L7_LAB_DIR")
	endpoints := map[string]string{"haproxy": os.Getenv("TRSTCTL_X2L7_HAPROXY_ADDR"), "openssl-config": os.Getenv("TRSTCTL_X2L7_OPENSSL_ADDR")}
	if dir == "" || endpoints["haproxy"] == "" || endpoints["openssl-config"] == "" {
		t.Skip("lab test: scripts/labs/product-defaults.sh starts the listeners and sets TRSTCTL_X2L7_LAB_DIR and the two addresses")
	}
	findings, err := hostsource.New(filepath.Join(dir, "haproxy.cfg"), filepath.Join(dir, "openssl.cnf")).
		WithAllowedRoots(dir).WithPackageDatabases(filepath.Join(dir, "installed")).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	claimed := map[string]map[string]string{"haproxy": {}, "openssl-config": {}}
	for _, f := range findings {
		if f.ConfigSource != "default" {
			continue
		}
		if f.Protocol != "" {
			claimed[f.Library]["protocol"] = f.Protocol
		}
		if f.Algorithm != "" {
			claimed[f.Library]["group"] = f.Algorithm
		}
		t.Logf("claimed %s default %s%s (%s)", f.Library, f.Protocol, f.Algorithm, f.ProductVersion)
	}
	for library, addr := range endpoints {
		lowest := ""
		for _, v := range []struct {
			name string
			max  uint16
		}{{"TLSv1.0", labTLS10}, {"TLSv1.1", labTLS11}, {"TLSv1.2", tlsprobe.TLSVersion12}, {"TLSv1.3", tlsprobe.TLSVersion13}} {
			if _, err := tlsprobe.Probe(context.Background(), addr, tlsprobe.WithMaxVersion(v.max), tlsprobe.WithTimeout(10*time.Second)); err == nil {
				lowest = v.name
				break
			}
		}
		_, hybridErr := tlsprobe.Probe(context.Background(), addr, tlsprobe.WithRequiredHybridGroup(), tlsprobe.WithTimeout(10*time.Second))
		hybrid := hybridErr == nil
		claim := claimed[library]
		if claim["protocol"] == "" || claim["protocol"] != lowest {
			t.Errorf("%s at %s: the host scan claims %q as the default minimum, the endpoint's lowest accepted version is %q", library, addr, claim["protocol"], lowest)
		}
		if claim["group"] == "" || hybrid != (claim["group"] == "X25519MLKEM768") {
			t.Errorf("%s at %s: the host scan claims %q as the default group; a handshake offering only X25519MLKEM768 succeeded=%v", library, addr, claim["group"], hybrid)
		}
		t.Logf("X2L7_LAB %s: claimed %s / %s; endpoint lowest %s, X25519MLKEM768 accepted=%v", library, claim["protocol"], claim["group"], lowest, hybrid)
	}
}
