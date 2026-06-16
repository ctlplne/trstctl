package serving

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/policy"
)

func handler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) })
}

func TestRegistryRoutesByLongestPrefix(t *testing.T) {
	r := NewRegistry()
	if err := r.Mount(Surface{Name: "est", Prefix: "/.well-known/est", Handler: handler("est")}); err != nil {
		t.Fatal(err)
	}
	if err := r.Mount(Surface{Name: "spiffe", Prefix: "/spiffe", Handler: handler("spiffe")}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()
	for path, want := range map[string]string{"/.well-known/est/cacerts": "est", "/spiffe/x509": "spiffe"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(want))
		resp.Body.Read(buf)
		resp.Body.Close()
		if string(buf) != want {
			t.Errorf("%s -> %q, want %q", path, buf, want)
		}
	}
}

func TestRegistryStartHealthGatesAndRollsBack(t *testing.T) {
	var stopped []string
	mk := func(name string, order int, ready error) Surface {
		return Surface{
			Name: name, Prefix: "/" + name, Handler: handler(name), Order: order,
			Ready:    func(context.Context) error { return ready },
			Shutdown: func(context.Context) error { stopped = append(stopped, name); return nil },
		}
	}
	r := NewRegistry()
	_ = r.Mount(mk("a", 1, nil))
	_ = r.Mount(mk("b", 2, errors.New("not ready"))) // b fails readiness
	_ = r.Mount(mk("c", 3, nil))
	if err := r.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded despite a failed readiness probe")
	}
	// a was started then rolled back; c never started.
	if len(stopped) != 1 || stopped[0] != "a" {
		t.Errorf("rollback drained %v, want [a]", stopped)
	}
}

func TestRegistryShutdownReverseOrder(t *testing.T) {
	var stopped []string
	mk := func(name string, order int) Surface {
		return Surface{
			Name: name, Prefix: "/" + name, Handler: handler(name), Order: order,
			Ready:    func(context.Context) error { return nil },
			Shutdown: func(context.Context) error { stopped = append(stopped, name); return nil },
		}
	}
	r := NewRegistry()
	_ = r.Mount(mk("a", 1))
	_ = r.Mount(mk("b", 2))
	_ = r.Mount(mk("c", 3))
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.Started(); len(got) != 3 {
		t.Fatalf("started %v", got)
	}
	if err := r.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(stopped) != 3 || stopped[0] != "c" || stopped[2] != "a" {
		t.Errorf("shutdown order = %v, want reverse [c,b,a]", stopped)
	}
}

type stubGate struct {
	allow  bool
	reason string
}

func (g stubGate) Evaluate(context.Context, policy.Input) (policy.Decision, error) {
	return policy.Decision{Allow: g.allow, Reason: g.reason}, nil
}

func TestGateMutatingBlocksAndPermits(t *testing.T) {
	backend := handler("issued")

	denied := httptest.NewServer(GateMutating(stubGate{allow: false, reason: "no"}, policy.ActionIssue, "t1", backend))
	defer denied.Close()
	// A mutating request is blocked.
	resp, _ := http.Post(denied.URL+"/issue", "application/json", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST under deny = %d, want 403", resp.StatusCode)
	}
	// A read passes through even under deny.
	resp, _ = http.Get(denied.URL + "/status")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET under deny = %d, want 200 (reads not gated)", resp.StatusCode)
	}

	allowed := httptest.NewServer(GateMutating(stubGate{allow: true}, policy.ActionIssue, "t1", backend))
	defer allowed.Close()
	resp, _ = http.Post(allowed.URL+"/issue", "application/json", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST under allow = %d, want 200", resp.StatusCode)
	}
}
