// SPDX-License-Identifier: BUSL-1.1

package sessionobserve

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"trstctl.com/trstctl/internal/crypto"
)

// TestProbeObjectsMatchTheirSourceX5 checks the committed probe objects, for
// both architectures, against what the Go side attaches and reads: they were
// built from the source as it stands (scripts/gen-sessionobserve-bpf.sh
// records its digest), carry the license the kernel requires for reading user
// memory, define every program the probe table attaches — an entry program in
// a uprobe section, a return program in a uretprobe section — and the maps
// with their bounds. Nothing else is in them.
func TestProbeObjectsMatchTheirSourceX5(t *testing.T) {
	source, err := os.ReadFile("bpf/sessionobserve.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := os.ReadFile("bpf/sessionobserve.bpf.c.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if got := crypto.SHA256Hex(source); strings.TrimSpace(string(recorded)) != got {
		t.Fatalf("bpf/sessionobserve.bpf.c (sha256 %s) is not the source the objects were built from (%s): run make sessionobserve-bpf and commit the objects",
			got, strings.TrimSpace(string(recorded)))
	}
	wantMaps := map[string]struct {
		typ ebpf.MapType
		max uint32
	}{
		"windows": {ebpf.Hash, 16384}, "bios": {ebpf.LRUHash, 65536}, "ssls": {ebpf.LRUHash, 65536},
		"streams": {ebpf.LRUHash, 65536}, "reads": {ebpf.Hash, 16384}, "writes": {ebpf.Hash, 16384},
		"events": {ebpf.RingBuf, 1 << 22}, "drops": {ebpf.PerCPUArray, 1},
		"libssl_layout": {ebpf.Array, 1}, "libssl_text": {ebpf.LRUHash, 16384},
	}
	for _, arch := range []string{"x86", "arm64"} {
		raw, err := os.ReadFile("bpf/sessionobserve_" + arch + "_bpfel.o") // #nosec G304 -- the committed probe objects beside the test (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s object: %v", arch, err)
		}
		attached := map[string]bool{}
		for _, p := range probes {
			prog := spec.Programs[p.program]
			if prog == nil {
				t.Fatalf("%s object has no program %s for %s", arch, p.program, p.symbol)
			}
			section := "uprobe/"
			if p.ret {
				section = "uretprobe/"
			}
			if prog.Type != ebpf.Kprobe || !strings.HasPrefix(prog.SectionName, section) || prog.License != "Dual BSD/GPL" {
				t.Errorf("%s program %s: type %v, section %q, license %q", arch, p.program, prog.Type, prog.SectionName, prog.License)
			}
			attached[p.program] = true
		}
		for name := range spec.Programs {
			if !attached[name] {
				t.Errorf("%s object has program %s that nothing attaches", arch, name)
			}
		}
		for name, want := range wantMaps {
			m := spec.Maps[name]
			if m == nil || m.Type != want.typ || m.MaxEntries != want.max {
				t.Errorf("%s map %s = %+v, want %v with %d entries", arch, name, m, want.typ, want.max)
			}
		}
		for name := range spec.Maps {
			if _, ok := wantMaps[name]; !ok {
				t.Errorf("%s object has unexpected map %s", arch, name)
			}
		}
	}
}
