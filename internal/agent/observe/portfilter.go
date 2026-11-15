// SPDX-License-Identifier: BUSL-1.1

package observe

import "strconv"

// A classic BPF program (linux/filter.h) that keeps only TCP segments and UDP
// datagrams (QUIC and DTLS, X1-L4) to or from a watched port, so the kernel
// drops everything else before it is copied to the observer. The ports sit at
// the same offsets in both transport headers. It reads IPv4 and IPv6,
// untagged or behind up to maxVLANTags in-band VLAN tags (802.1Q 0x8100,
// 802.1ad 0x88a8; X1-L2, X1-L2R): a trunk mirror's frames, and a QinQ frame
// whose outer tag the kernel moved out of band, keep their inner tags in the
// data. A later IPv4 fragment of TCP or UDP carries no ports and an IPv6
// packet with extension headers puts them where the filter cannot follow, so
// both are passed up, where Assembler.Frame reassembles and walks them inside
// its bounds (X1-L2R). Other frames are dropped in the kernel. The link
// header's length is carried in X, so one set of port checks serves every
// tagging.

const (
	bpfLdHAbs  = 0x28 // BPF_LD | BPF_H | BPF_ABS
	bpfLdBAbs  = 0x30 // BPF_LD | BPF_B | BPF_ABS
	bpfLdHInd  = 0x48 // BPF_LD | BPF_H | BPF_IND
	bpfLdBInd  = 0x50 // BPF_LD | BPF_B | BPF_IND
	bpfLdxImm  = 0x01 // BPF_LDX | BPF_W | BPF_IMM
	bpfLdxBMsh = 0xb1 // BPF_LDX | BPF_B | BPF_MSH
	bpfAluAndK = 0x54 // BPF_ALU | BPF_AND | BPF_K
	bpfAluLshK = 0x64 // BPF_ALU | BPF_LSH | BPF_K
	bpfAluAddX = 0x0c // BPF_ALU | BPF_ADD | BPF_X
	bpfMiscTax = 0x07 // BPF_MISC | BPF_TAX
	bpfJa      = 0x05 // BPF_JMP | BPF_JA
	bpfJeqK    = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfJsetK   = 0x45 // BPF_JMP | BPF_JSET | BPF_K
	bpfRetK    = 0x06 // BPF_RET | BPF_K
)

// The VLAN tag protocol identifiers the filter reads through.
const (
	tpid8021Q  = 0x8100
	tpid8021AD = 0x88a8
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
	// Link layer: A is the EtherType after the tags, X the header's length.
	// Each depth reads the next EtherType and either walks one more tag or
	// stops with X at the network header.
	for depth := 0; depth <= maxVLANTags; depth++ {
		mark("tag" + strconv.Itoa(depth))
		prog = append(prog, insn{code: bpfLdHAbs, k: uint32(12 + 4*depth)}) // #nosec G115 -- depth is at most maxVLANTags (CWE-190)
		if depth < maxVLANTags {
			next := "tag" + strconv.Itoa(depth+1)
			prog = append(prog, insn{code: bpfJeqK, k: tpid8021Q, jt: next})
			prog = append(prog, insn{code: bpfJeqK, k: tpid8021AD, jt: next})
		}
		prog = append(prog, insn{code: bpfLdxImm, k: uint32(14 + 4*depth)}) // #nosec G115 -- depth is at most maxVLANTags (CWE-190)
		prog = append(prog, insn{code: bpfJa, jt: "l3"})
	}
	mark("l3")
	prog = append(prog, insn{code: bpfJeqK, k: 0x0800, jf: "v6"})
	// IPv4: TCP or UDP; a later fragment is passed up for reassembly, and
	// otherwise X moves past the header (IHL) to the ports.
	prog = append(prog, insn{code: bpfLdBInd, k: 9})
	prog = append(prog, insn{code: bpfJeqK, k: 6, jt: "v4l4"})
	prog = append(prog, insn{code: bpfJeqK, k: 17, jf: "drop"})
	mark("v4l4")
	prog = append(prog, insn{code: bpfLdHInd, k: 6})
	prog = append(prog, insn{code: bpfJsetK, k: 0x1fff, jt: "accept"})
	prog = append(prog, insn{code: bpfLdBInd, k: 0})
	prog = append(prog, insn{code: bpfAluAndK, k: 0x0f})
	prog = append(prog, insn{code: bpfAluLshK, k: 2})
	prog = append(prog, insn{code: bpfAluAddX})
	prog = append(prog, insn{code: bpfMiscTax})
	matchPorts(bpfLdHInd, 0, "v4dst")
	mark("v4dst")
	matchPorts(bpfLdHInd, 2, "drop")
	mark("v6")
	prog = append(prog, insn{code: bpfJeqK, k: 0x86dd, jf: "drop"})
	prog = append(prog, insn{code: bpfLdBInd, k: 6})
	prog = append(prog, insn{code: bpfJeqK, k: 6, jt: "v6l4"})
	prog = append(prog, insn{code: bpfJeqK, k: 17, jt: "v6l4"})
	// An extension header before the transport header is walked in user
	// space (isIPv6ExtensionHeader).
	for _, next := range []uint32{0, 43, 44, 51, 60, 135} {
		prog = append(prog, insn{code: bpfJeqK, k: next, jt: "accept"})
	}
	prog = append(prog, insn{code: bpfJa, jt: "drop"})
	mark("v6l4")
	matchPorts(bpfLdHInd, 40, "v6dst")
	mark("v6dst")
	matchPorts(bpfLdHInd, 42, "drop")
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
			return uint8(label[target] - i - 1) // #nosec G115 -- a forward jump inside this fixed program, under 255 instructions at MaxWatchedPorts (CWE-190)
		}
		if in.code == bpfJa {
			// An unconditional jump carries its distance in K.
			out[i] = bpfInsn{Code: in.code, K: uint32(label[in.jt] - i - 1)} // #nosec G115 -- a forward jump inside this fixed program (CWE-190)
			continue
		}
		out[i] = bpfInsn{Code: in.code, K: in.k, Jt: jump(in.jt), Jf: jump(in.jf)}
	}
	return out
}
