package egress

import (
	"errors"
	"net/http"
	"testing"
)

func TestGuardBlocksPublicHTTPAndCountsTrips(t *testing.T) {
	g, err := NewGuard(Config{Enabled: true, AllowPrivate: true})
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	if err := g.CheckURL("https://telemetry.trstctl.com/v1/usage"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("public URL err = %v, want ErrBlocked", err)
	}
	if g.Trips() != 1 {
		t.Fatalf("Trips = %d, want 1", g.Trips())
	}
	if err := g.CheckURL("http://127.0.0.1:4318/v1/traces"); err != nil {
		t.Fatalf("private loopback should be allowed: %v", err)
	}
	if trips := g.Trips(); trips != 1 {
		t.Fatalf("allowed private URL changed trips to %d", trips)
	}
}

func TestGuardHonorsExplicitHostAndCIDRAllowlist(t *testing.T) {
	g, err := NewGuard(Config{
		Enabled:      true,
		AllowPrivate: false,
		AllowHosts:   []string{"collector.airgap.local"},
		AllowCIDRs:   []string{"203.0.113.0/24"},
	})
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	for _, raw := range []string{
		"https://collector.airgap.local/v1/traces",
		"https://203.0.113.10/status",
	} {
		if err := g.CheckURL(raw); err != nil {
			t.Fatalf("%s should be allowlisted: %v", raw, err)
		}
	}
	if err := g.CheckURL("https://198.51.100.10/status"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("non-allowlisted IP err = %v, want ErrBlocked", err)
	}
}

func TestRoundTripperBlocksBeforeDial(t *testing.T) {
	g, err := NewGuard(Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	tripped := false
	rt := g.WrapTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		tripped = true
		return nil, nil
	}))
	req, err := http.NewRequest(http.MethodGet, "https://updates.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.RoundTrip(req); !errors.Is(err, ErrBlocked) {
		t.Fatalf("RoundTrip err = %v, want ErrBlocked", err)
	}
	if tripped {
		t.Fatal("blocked request reached the wrapped transport")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
