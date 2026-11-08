// SPDX-License-Identifier: BUSL-1.1

//go:build linux && (amd64 || arm64)

package sessionobserve

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// bpfHandles counts this process's open BPF objects and perf events: the
// probes hold them while attached, and the kernel detaches a probe when the
// last one closes.
func bpfHandles(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err == nil && (strings.HasPrefix(target, "anon_inode:bpf") || target == "anon_inode:[perf_event]") {
			n++
		}
	}
	return n
}

func fingerprint(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- the proof traffic's own output (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	_, value, ok := strings.Cut(strings.TrimSpace(string(raw)), "=")
	if !ok {
		t.Fatalf("%s: %q is not an openssl fingerprint", path, raw)
	}
	return strings.ToLower(strings.ReplaceAll(value, ":", ""))
}

// TestSessionObserverReadsStockTLSSessionsX5 is X5 on Linux: stock OpenSSL 3
// servers and clients and curl on loopback (testdata/traffic.sh), observed
// through the libraries they load. Each TLS 1.3 session shows its
// key-exchange group and the peer's certificate fingerprint, which TLS 1.3
// never sends in the clear: the server's for each client, the client's for
// the mutual-TLS server. A HelloRetryRequest reports the group it settled,
// and TLS 1.2 its curve and RSA certificate. No application data byte —
// four markers sent both ways — reaches the observer, every byte the probes
// copied lies in a plaintext handshake record, and Close leaves no probe
// attached. It needs BPF privileges and the host PID namespace, so it runs
// only where TRSTCTL_X5_PROOF_OUT and TRSTCTL_X5_TRAFFIC are set: the proof
// container and the ubuntu-latest CI job; the report it writes is the
// evidence.
func TestSessionObserverReadsStockTLSSessionsX5(t *testing.T) {
	out, traffic := os.Getenv("TRSTCTL_X5_PROOF_OUT"), os.Getenv("TRSTCTL_X5_TRAFFIC")
	if out == "" || traffic == "" {
		t.Skip("runs in the X5 proof container or CI job, with BPF privileges and stock OpenSSL")
	}
	libs, err := DefaultLibraries()
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	var mu sync.Mutex
	var sessions []Session
	type tapped struct {
		Type   uint32
		PID    uint32
		SSL    uint64
		Dir    int64
		Offset uint64
		Data   []byte
	}
	var taps []tapped
	asm := NewAssembler(4096, func(s Session) {
		mu.Lock()
		defer mu.Unlock()
		sessions = append(sessions, s)
	})
	baseline := bpfHandles(t)
	o, err := open(libs, asm, func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		taps = append(taps, tapped{Type: e.Type, PID: e.PID, SSL: e.SSL, Dir: e.Ret, Offset: e.Offset, Data: bytes.Clone(e.Data)})
	})
	if err != nil {
		t.Fatal(err)
	}
	attached := bpfHandles(t)

	cmd := exec.Command("/bin/sh", traffic) // #nosec G204 G702 -- the proof's own traffic script, named by the proof runner (CWE-78)
	cmd.Env = append(os.Environ(), "X5_WORK="+work)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("proof traffic: %v", err)
	}
	time.Sleep(3 * time.Second) // the reader drains and handshakes settle
	stats := asm.Stats()
	stats.RingDrops = o.RingDrops()
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	detached := bpfHandles(t)

	mu.Lock()
	defer mu.Unlock()
	// The probes see every process that maps the libraries; the proof keeps
	// only its own, which run from the copies in work.
	var mine []Session
	for _, s := range sessions {
		if strings.HasPrefix(s.Executable, work+"/") {
			mine = append(mine, s)
		}
	}
	report, err := json.MarshalIndent(map[string]any{
		"libraries": libs, "sessions": mine, "stats": stats, "events_tapped": len(taps),
		"bpf_handles": map[string]int{"before": baseline, "attached": attached, "after_close": detached},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, report, 0o600); err != nil { // #nosec G703 -- the proof names its report path in the environment, never a request (CWE-22)
		t.Fatal(err)
	}

	// No application data: not in what the probes copied, not in the report.
	for _, marker := range []string{"x5-client-app-data", "x5-server-app-data", "x5-secret-path", "x5-header-secret"} {
		for _, tap := range taps {
			if bytes.Contains(tap.Data, []byte(marker)) {
				t.Fatalf("the probes copied application data (%s) from pid %d", marker, tap.PID)
			}
		}
		if strings.Contains(string(report), marker) {
			t.Fatalf("the report carries application data (%s)", marker)
		}
	}
	// Every copied byte lies in a plaintext handshake record.
	type direction struct {
		pid uint32
		ssl uint64
		dir int64
	}
	streams := map[direction][]byte{}
	for _, tap := range taps {
		if tap.Type == eventRecord {
			k := direction{tap.PID, tap.SSL, tap.Dir}
			if uint64(len(streams[k])) == tap.Offset {
				streams[k] = append(streams[k], tap.Data...)
			}
		}
	}
	for k, b := range streams {
		for len(b) >= 5 {
			if b[0] != 0x16 {
				t.Fatalf("pid %d copied a record of type 0x%02x", k.pid, b[0])
			}
			n := 5 + (int(b[3])<<8 | int(b[4]))
			if n > len(b) {
				break
			}
			b = b[n:]
		}
	}

	hybrid, err := os.ReadFile(filepath.Join(work, "expect-group")) // #nosec G304 -- the proof traffic's own output (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	group := strings.TrimSpace(string(hybrid))
	fpServer, fpClient, fpRSA := fingerprint(t, filepath.Join(work, "fp-server")), fingerprint(t, filepath.Join(work, "fp-client")),
		fingerprint(t, filepath.Join(work, "fp-rsa"))
	find := func(process, side, version, group, peer string, retry bool) *Session {
		for i := range mine {
			s := &mine[i]
			if filepath.Base(s.Executable) == process && s.Side == side && s.Obs.TLSVersion == version && s.Obs.Group == group &&
				s.HelloRetry == retry && s.Peer != nil && s.Peer.SHA256 == peer {
				return s
			}
		}
		return nil
	}
	for _, want := range []struct {
		name, process, side, version, group, peer string
		retry                                     bool
	}{
		{"TLS 1.3 client, mutual TLS", "x5-openssl", "client", "TLSv1.3", group, fpServer, false},
		{"TLS 1.3 server, the client's certificate", "x5-openssl", "server", "TLSv1.3", group, fpClient, false},
		{"curl over TLS 1.3", "x5-curl", "client", "TLSv1.3", group, fpServer, false},
		{"TLS 1.2 client, RSA certificate", "x5-openssl", "client", "TLSv1.2", "x25519", fpRSA, false},
		{"TLS 1.3 after a HelloRetryRequest", "x5-openssl", "client", "TLSv1.3", "secp256r1", fpServer, true},
	} {
		if find(want.process, want.side, want.version, want.group, want.peer, want.retry) == nil {
			t.Errorf("no %s session (%s %s %s, peer %s, retry %v) among %d of the proof's sessions", want.name, want.process,
				want.version, want.group, want.peer, want.retry, len(mine))
		}
	}
	if rsa := find("x5-openssl", "client", "TLSv1.2", "x25519", fpRSA, false); rsa != nil &&
		(rsa.Peer.KeyAlgorithm != "RSA" || rsa.Peer.PublicKeyBits != 2048) {
		t.Errorf("TLS 1.2 peer certificate %+v, want RSA 2048", rsa.Peer)
	}
	if attached <= baseline || detached != baseline {
		t.Errorf("BPF handles: %d before, %d attached, %d after Close; want the probes gone after Close", baseline, attached, detached)
	}
	if stats.RingDrops != 0 || stats.Gaps != 0 {
		t.Errorf("the proof lost events: %+v", stats)
	}
}
