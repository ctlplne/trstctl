// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"net"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

type fakeKMIPRuntime struct {
	addr   string
	served bool
	closed bool
}

func (r *fakeKMIPRuntime) Addr() string { return r.addr }
func (r *fakeKMIPRuntime) Serve(_ context.Context, ln net.Listener) error {
	r.served = true
	return ln.Close()
}
func (r *fakeKMIPRuntime) Close() { r.closed = true }

func TestKMIPServedThroughEditionFactory(t *testing.T) {
	runtime := &fakeKMIPRuntime{addr: "127.0.0.1:0"}
	h := newServedHarness(t, config.Protocols{KMIP: config.KMIPProtocol{
		Enabled:      true,
		TenantID:     servedTestTenant,
		CertFile:     "kmip-server.crt",
		KeyFile:      "kmip-server.key",
		ClientCAFile: "kmip-clients.crt",
	}}, func(d *Deps) {
		d.KMIPFactory = func(KMIPFactoryDeps) (KMIPRuntime, error) {
			return runtime, nil
		}
	})
	if !h.srv.KMIPServed() {
		t.Fatal("KMIP listener was not mounted through the edition factory")
	}
	posture := h.srv.transitRuntimePosture(true, servedTestTenant, servedTestTenant)
	if !posture.KMIPConfigured || !posture.KMIPServed || !posture.KMIPTenantBound || posture.KMIPListening || posture.KMIPAddress != runtime.addr {
		t.Fatalf("KMIP startup posture = %+v, want configured tenant-bound runtime not yet listening", posture)
	}
	otherTenant := h.srv.transitRuntimePosture(true, servedTestTenant, "22222222-2222-4222-8222-222222222222")
	if otherTenant.KMIPConfigured || otherTenant.KMIPServed || otherTenant.KMIPListening || otherTenant.KMIPTenantBound || otherTenant.KMIPAddress != "" {
		t.Fatalf("KMIP posture leaked another tenant's runtime state: %+v", otherTenant)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen KMIP seam socket: %v", err)
	}
	if err := h.srv.ServeKMIP(context.Background(), ln); err != nil {
		t.Fatalf("ServeKMIP via edition runtime: %v", err)
	}
	if !runtime.served {
		t.Fatal("ServeKMIP did not delegate to the edition runtime")
	}
	if h.srv.transitRuntimePosture(true, servedTestTenant, servedTestTenant).KMIPListening {
		t.Fatal("completed KMIP runtime still reported a listening socket")
	}
}
