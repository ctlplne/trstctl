// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package observe

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// X1 on Linux: stock OpenSSL, OpenSSH, curl and ldapsearch on loopback,
// observed by Capture. It runs only in the proof container
// (runners/x1-linux-proof.sh), which grants CAP_NET_RAW and installs the
// tools; the report it writes is the evidence.
func TestCaptureStockTrafficOnLoopbackX1(t *testing.T) {
	out := os.Getenv("TRSTCTL_X1_PROOF_OUT")
	if out == "" {
		t.Skip("runs inside the X1 proof container")
	}
	ports := []uint16{4412, 4413, 2222, 8080, 3389}
	agg := NewAggregate(64)
	asm := NewAssembler(ports, 512, 30*time.Second, agg.Add)
	ctx, cancel := context.WithCancel(context.Background())
	captured := make(chan error, 1)
	go func() { captured <- Capture(ctx, "lo", ports, 2048, asm) }()
	time.Sleep(300 * time.Millisecond)

	traffic := exec.Command("/bin/sh", "/proof/traffic.sh")
	traffic.Stdout, traffic.Stderr = os.Stderr, os.Stderr
	if err := traffic.Run(); err != nil {
		t.Fatalf("proof traffic: %v", err)
	}
	items, _ := agg.Changed()

	// Budget: TLS 1.3 hybrid handshakes as fast as one client opens them.
	cpuBefore, _ := Footprint()
	observedBefore := asm.Stats().Observations
	start := time.Now()
	load := exec.Command("/bin/sh", "-c", "openssl s_time -connect 127.0.0.1:4413 -new -time 5 >/dev/null 2>&1")
	_ = load.Run()
	wall := time.Since(start)
	time.Sleep(500 * time.Millisecond)
	cpuAfter, heap := Footprint()
	stats := asm.Stats()
	cancel()
	if err := <-captured; err != nil {
		t.Fatal(err)
	}
	handshakes := stats.Observations - observedBefore
	cpuShare := (cpuAfter - cpuBefore) / wall.Seconds()

	report, err := json.MarshalIndent(map[string]any{
		"items": items, "stats": stats, "load_handshakes": handshakes, "load_seconds": wall.Seconds(),
		"handshakes_per_second": float64(handshakes) / wall.Seconds(), "observer_cpu_share": cpuShare, "observer_heap_bytes": heap,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, report, 0o600); err != nil { // #nosec G703 -- the lab runner names the report path in the test environment, never a request (CWE-22)
		t.Fatal(err)
	}
	for _, marker := range []string{"x1-app-data", "x1-secret-path", "x1-bind-secret", "x1-admin"} {
		if strings.Contains(string(report), marker) {
			t.Fatalf("the observer kept payload bytes (%s)", marker)
		}
	}

	find := func(port uint16, kind string) *Item {
		for i := range items {
			if items[i].Server.Port() == port && items[i].Kind == kind {
				return &items[i]
			}
		}
		return nil
	}
	if it := find(4412, "tls_handshake"); it == nil || it.Obs.TLSVersion != "TLSv1.2" || it.Certificate == nil ||
		it.Certificate.KeyAlgorithm != "RSA" || it.Certificate.PublicKeyBits != 2048 {
		t.Fatalf("TLS 1.2 with its certificate: %+v", it)
	}
	if it := find(4413, "tls_handshake"); it == nil || it.Obs.TLSVersion != "TLSv1.3" || it.Obs.Group != "X25519MLKEM768" ||
		!it.Obs.CertificateHidden || it.Certificate != nil {
		t.Fatalf("TLS 1.3 with X25519MLKEM768: %+v", it)
	}
	if it := find(2222, "ssh_kex"); it == nil || it.Obs.KexAlgorithm != "mlkem768x25519-sha256" {
		t.Fatalf("SSH key exchange: %+v", it)
	}
	for _, port := range []uint16{8080, 3389} {
		if it := find(port, "plaintext_protocol"); it == nil || !it.Obs.Plaintext {
			t.Fatalf("plaintext on %d: %+v", port, it)
		}
	}
	// The budget at the measured rate: under half a core and 64 MiB of heap,
	// with nothing dropped.
	if handshakes < 50 || cpuShare > 0.5 || heap > 64<<20 || stats.TableFull != 0 {
		t.Fatalf("budget: %d handshakes in %s, CPU share %.3f, heap %d bytes, stats %+v", handshakes, wall, cpuShare, heap, stats)
	}
}

// X1-L2 on Linux: TLS between two network namespaces over QinQ (an 802.1ad
// outer tag, an 802.1Q inner tag) and over a single 802.1Q tag on a veth
// pair, observed on a mirror port: tc mirrors both directions of the trunk
// into a dummy device as received frames, as a switch's SPAN port does. The
// kernel moves a frame's outer tag out of band, a QinQ frame's inner tag
// stays in the frame, and the filter reads through it. It runs only in the
// X1-L2 proof container (runners/x1l2-linux-proof.sh), which is privileged to
// create the namespace, the VLAN devices and the mirror.
func TestCaptureQinQTrafficX1L2(t *testing.T) {
	out := os.Getenv("TRSTCTL_X1L2_PROOF_OUT")
	if out == "" {
		t.Skip("runs inside the X1-L2 proof container")
	}
	setup := exec.Command("/bin/sh", "/proof/vlan-setup.sh")
	setup.Stdout, setup.Stderr = os.Stderr, os.Stderr
	if err := setup.Run(); err != nil {
		t.Fatalf("VLAN setup: %v", err)
	}
	ports := []uint16{4414, 4415}
	agg := NewAggregate(64)
	asm := NewAssembler(ports, 512, 30*time.Second, agg.Add)
	ctx, cancel := context.WithCancel(context.Background())
	captured := make(chan error, 1)
	go func() { captured <- Capture(ctx, "span0", ports, 2048, asm) }()
	time.Sleep(300 * time.Millisecond)
	traffic := exec.Command("/bin/sh", "/proof/vlan-traffic.sh")
	traffic.Stdout, traffic.Stderr = os.Stderr, os.Stderr
	if err := traffic.Run(); err != nil {
		t.Fatalf("VLAN traffic: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	items, _ := agg.Changed()
	stats := asm.Stats()
	cancel()
	if err := <-captured; err != nil {
		t.Fatal(err)
	}
	report, err := json.MarshalIndent(map[string]any{"items": items, "stats": stats}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, report, 0o600); err != nil { // #nosec G703 -- the lab runner names the report path in the test environment, never a request (CWE-22)
		t.Fatal(err)
	}
	find := func(server string) *Item {
		for i := range items {
			if items[i].Server.String() == server && items[i].Kind == "tls_handshake" {
				return &items[i]
			}
		}
		return nil
	}
	// 4414 over QinQ, 4415 over a single 802.1Q tag.
	if it := find("10.77.0.1:4414"); it == nil || it.Obs.TLSVersion != "TLSv1.3" || it.Obs.Group != "X25519MLKEM768" {
		t.Fatalf("TLS 1.3 over QinQ: %+v (stats %+v)", it, stats)
	}
	if it := find("10.78.0.1:4415"); it == nil || it.Obs.TLSVersion != "TLSv1.3" {
		t.Fatalf("TLS 1.3 over 802.1Q: %+v (stats %+v)", it, stats)
	}
}
