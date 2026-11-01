// SPDX-License-Identifier: BUSL-1.1

package observe

// A classic BPF program (linux/filter.h) that keeps only TCP segments to or
// from a watched port, so the kernel drops everything else before it is
// copied to the observer. It reads untagged IPv4 (no fragments) and IPv6 (no
// extension headers before TCP); other frames are dropped in the kernel.

const (
	bpfLdHAbs  = 0x28 // BPF_LD | BPF_H | BPF_ABS
	bpfLdBAbs  = 0x30 // BPF_LD | BPF_B | BPF_ABS
	bpfLdHInd  = 0x48 // BPF_LD | BPF_H | BPF_IND
	bpfLdxBMsh = 0xb1 // BPF_LDX | BPF_B | BPF_MSH
	bpfJeqK    = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfJsetK   = 0x45 // BPF_JMP | BPF_JSET | BPF_K
	bpfRetK    = 0x06 // BPF_RET | BPF_K
)

// MaxWatchedPorts keeps every jump inside classic BPF's 8-bit offsets.
const MaxWatchedPorts = 32

type bpfInsn struct {
	Code   uint16
	Jt, Jf uint8
	K      uint32
}

// portFilterProgram builds the filter; frames it accepts are cut to snaplen.
func portFilterProgram(ports []uint16, snaplen uint32) []bpfInsn {
	if len(ports) > MaxWatchedPorts {
		ports = ports[:MaxWatchedPorts]
	}
	type insn struct {
		code   uint16
		k      uint32
		jt, jf string // label of the jump target; "" is the next instruction
	}
	var prog []insn
	label := map[string]int{}
	mark := func(name string) { label[name] = len(prog) }
	matchPorts := func(offsetCode uint16, k uint32, miss string) {
		prog = append(prog, insn{code: offsetCode, k: k})
		for i, p := range ports {
			jf := ""
			if i == len(ports)-1 {
				jf = miss
			}
			prog = append(prog, insn{code: bpfJeqK, k: uint32(p), jt: "accept", jf: jf})
		}
	}
	prog = append(prog, insn{code: bpfLdHAbs, k: 12})
	prog = append(prog, insn{code: bpfJeqK, k: 0x0800, jf: "v6"})
	prog = append(prog, insn{code: bpfLdBAbs, k: 23})
	prog = append(prog, insn{code: bpfJeqK, k: 6, jf: "drop"})
	prog = append(prog, insn{code: bpfLdHAbs, k: 20})
	prog = append(prog, insn{code: bpfJsetK, k: 0x1fff, jt: "drop"})
	prog = append(prog, insn{code: bpfLdxBMsh, k: 14})
	matchPorts(bpfLdHInd, 14, "v4dst")
	mark("v4dst")
	matchPorts(bpfLdHInd, 16, "drop")
	mark("v6")
	prog = append(prog, insn{code: bpfJeqK, k: 0x86dd, jf: "drop"})
	prog = append(prog, insn{code: bpfLdBAbs, k: 20})
	prog = append(prog, insn{code: bpfJeqK, k: 6, jf: "drop"})
	matchPorts(bpfLdHAbs, 54, "v6dst")
	mark("v6dst")
	matchPorts(bpfLdHAbs, 56, "drop")
	mark("accept")
	prog = append(prog, insn{code: bpfRetK, k: snaplen})
	mark("drop")
	prog = append(prog, insn{code: bpfRetK, k: 0})

	out := make([]bpfInsn, len(prog))
	for i, in := range prog {
		jump := func(target string) uint8 {
			if target == "" {
				return 0
			}
			return uint8(label[target] - i - 1) // #nosec G115 -- a forward jump inside this fixed program of fewer than 32 instructions (CWE-190)
		}
		out[i] = bpfInsn{Code: in.code, K: in.k, Jt: jump(in.jt), Jf: jump(in.jf)}
	}
	return out
}
