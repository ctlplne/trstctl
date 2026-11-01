// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package observe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// Capture reads frames from iface until ctx ends and feeds the TCP segments
// of the watched ports to a. It needs CAP_NET_RAW. A classic BPF program in the
// kernel drops every other packet before it reaches this process, and each
// frame is cut to snaplen, so a busy link costs little more than the watched
// handshakes do.
func Capture(ctx context.Context, iface string, ports []uint16, snaplen int, a *Assembler) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("observe: interface %q: %w", iface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("observe: open packet socket (needs CAP_NET_RAW): %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	program := portFilter(ports, uint32(snaplen)) // #nosec G115 -- snaplen is a small configured frame size
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER,
		&unix.SockFprog{Len: uint16(len(program)), Filter: &program[0]}); err != nil {
		return fmt.Errorf("observe: attach port filter: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		return fmt.Errorf("observe: bind %q: %w", iface, err)
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 200_000}); err != nil {
		return fmt.Errorf("observe: receive timeout: %w", err)
	}
	buf := make([]byte, snaplen)
	for ctx.Err() == nil {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("observe: read %q: %w", iface, err)
		}
		// On a loopback or a host interface each frame this host sends is
		// also delivered as outgoing; the received copy is enough.
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		if seg, ok := DecodeFrame(buf[:n]); ok {
			a.Segment(seg, time.Now())
		}
	}
	return nil
}

// portFilter converts the port filter to the kernel's instruction type.
func portFilter(ports []uint16, snaplen uint32) []unix.SockFilter {
	program := portFilterProgram(ports, snaplen)
	out := make([]unix.SockFilter, len(program))
	for i, in := range program {
		out[i] = unix.SockFilter{Code: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	return out
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Footprint is the observer process's CPU time so far and heap in use, the
// budget an operator compares against the traffic it observed.
func Footprint() (cpuSeconds float64, heapBytes uint64) {
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err == nil {
		cpuSeconds = time.Duration(usage.Utime.Nano() + usage.Stime.Nano()).Seconds()
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return cpuSeconds, mem.HeapInuse
}
