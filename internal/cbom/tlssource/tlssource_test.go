package tlssource_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/cbom/tlssource"
	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

func TestScanReportsProtocolAndKey(t *testing.T) {
	der, _, err := ctlogtest.IssueCert("svc", "svc.example.com") // ECDSA P-256
	if err != nil {
		t.Fatal(err)
	}
	// A fake handshake negotiating TLS 1.0 and presenting the cert.
	prober := func(context.Context, string) (tlsprobe.Result, error) {
		return tlsprobe.Result{TLSVersion: 0x0301, PeerCertificates: [][]byte{der}}, nil
	}

	src := tlssource.New([]string{"host.example.com:443"}, tlssource.WithProber(prober))
	findings, err := src.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	p := cbom.DefaultPolicy()
	var proto, key cbom.Finding
	for _, f := range findings {
		switch f.Kind {
		case cbom.AssetTLSEndpoint:
			proto = f
		case cbom.AssetCertKey:
			key = f
		}
	}
	if proto.Protocol != "TLSv1.0" {
		t.Errorf("protocol = %q, want TLSv1.0", proto.Protocol)
	}
	if c := cbom.Classify(proto, p); c.Strength != cbom.StrengthWeak || !c.OutOfPolicy {
		t.Errorf("TLSv1.0 classification = %+v, want weak + out-of-policy", c)
	}
	if key.KeyBits != 256 {
		t.Errorf("key bits = %d, want 256", key.KeyBits)
	}
	if c := cbom.Classify(key, p); !c.QuantumVulnerable {
		t.Errorf("ECDSA key should be flagged quantum-vulnerable: %+v", c)
	}
}

func TestScanSkipsUnreachable(t *testing.T) {
	prober := func(context.Context, string) (tlsprobe.Result, error) {
		return tlsprobe.Result{}, errors.New("connection refused")
	}
	findings, err := tlssource.New([]string{"down:443"}, tlssource.WithProber(prober)).Scan(context.Background())
	if err != nil {
		t.Fatalf("an unreachable endpoint must not error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}
