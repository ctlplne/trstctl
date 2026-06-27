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
}
