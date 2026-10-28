// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/workloadapi"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/protocols/spiffe"
)

// TestHostWorkloadAPIMatchesADarwinWorkloadByPath is A204 on the Mac: the host
// Workload API attests a darwin caller's executable from its audit token, so a
// registration entry that requires unix:path issues an SVID to the stock
// go-spiffe client built at that path and refuses the same client copied to
// another path, whose uid and gid selectors are identical.
func TestHostWorkloadAPIMatchesADarwinWorkloadByPath(t *testing.T) {
	const (
		nodeID   = "spiffe://served.test/agent/host-a"
		workload = "spiffe://served.test/payments"
	)
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the stock go-spiffe client")
	}
	dir, err := os.MkdirTemp("", "trstctl-a204-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	client := filepath.Join(dir, "payments-client")
	build := exec.Command(goBin, "build", "-o", client, ".") // #nosec G204 -- test builds a fixed local fixture (CWE-78)
	build.Dir = filepath.Join("testdata", "gospiffe-client")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the stock go-spiffe client: %v\n%s", err, out)
	}
	resolved, err := filepath.EvalSymlinks(client)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(client) // #nosec G304 G703 -- test reads the binary it just built (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other-client")
	if err := os.WriteFile(other, binary, 0o700); err != nil { // #nosec G306 G703 -- test copies its own executable fixture (CWE-22)
		t.Fatal(err)
	}

	h := newServedHarness(t, config.Protocols{
		SPIFFE: config.SPIFFEProtocol{
			Enabled: true, TenantID: servedTestTenant, TrustDomain: "served.test",
			SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
		},
	})
	if h.srv.protocols == nil || h.srv.protocols.spiffe == nil {
		t.Skip("this build serves no SPIFFE trust domain")
	}
	wl, err := spiffe.New(spiffe.Config{
		Issuer:      &spiffe.CAIssuer{CACertDER: h.srv.caCertDER, CASigner: h.srv.caSigner},
		TenantID:    servedTestTenant,
		TrustDomain: "served.test",
		Entries: []spiffe.RegistrationEntry{{
			SPIFFEID: workload, Selectors: []string{"unix:path:" + resolved}, ParentID: nodeID,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "w.sock")
	upstream := &pathRecordingUpstream{
		hostWorkloadUpstream: hostWorkloadUpstream{wl: wl, nodeID: nodeID, spiffeID: workload},
		selectors:            make(chan []string, 64),
	}
	srv := workloadapi.New(upstream, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, socket) }()
	t.Cleanup(func() { cancel(); <-done })
	waitForSocket(t, socket, 5*time.Second)

	run := func(path string) (servedGoSpiffeResult, string, error) {
		t.Helper()
		runCtx, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		cmd := exec.CommandContext(runCtx, path, "unix://"+socket) // #nosec G204 -- test runs the client it built (CWE-78)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		var result servedGoSpiffeResult
		if err == nil {
			err = json.Unmarshal(out, &result)
		}
		return result, stderr.String(), err
	}
	matched, stderr, err := run(client)
	if err != nil || matched.ID != workload || !matched.HasPrivateKey {
		t.Fatalf("the client at %s = %+v %v\n%s; want %s", resolved, matched, err, stderr, workload)
	}
	if !containsString(upstream.lastSelectors(), "unix:path:"+resolved) {
		t.Fatalf("the host sent selectors %v, want unix:path:%s", upstream.lastSelectors(), resolved)
	}
	if refused, stderr, err := run(other); err == nil {
		t.Fatalf("the same client at another path got %+v; want a refusal", refused)
	} else if !containsString(upstream.lastSelectors(), "unix:path:"+filepath.Join(filepath.Dir(resolved), "other-client")) {
		t.Fatalf("the refused client was attested as %v (%s)", upstream.lastSelectors(), stderr)
	}
	t.Logf("A204_DARWIN_PATH_OK matched=%s refused=%s", resolved, filepath.Join(filepath.Dir(resolved), "other-client"))
}

// pathRecordingUpstream records the selectors the host attested last.
type pathRecordingUpstream struct {
	hostWorkloadUpstream
	selectors chan []string
}

func (p *pathRecordingUpstream) FetchWorkloadSVID(ctx context.Context, publicKeyDER []byte, selectors, audience []string) (*workloadapi.SVIDSet, error) {
	p.record(selectors)
	return p.hostWorkloadUpstream.FetchWorkloadSVID(ctx, publicKeyDER, selectors, audience)
}

func (p *pathRecordingUpstream) record(selectors []string) {
	select {
	case p.selectors <- append([]string(nil), selectors...):
	default:
	}
}

func (p *pathRecordingUpstream) lastSelectors() []string {
	var last []string
	for {
		select {
		case s := <-p.selectors:
			last = s
		default:
			return last
		}
	}
}
