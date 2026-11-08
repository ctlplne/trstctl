// SPDX-License-Identifier: BUSL-1.1

//go:build linux && (amd64 || arm64)

package sessionobserve

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Libraries names the OpenSSL 3 libraries the probes attach to. Every process
// that maps these files is observed; a container whose image carries its own
// copy is observed through that copy's path (for example
// /proc/<pid>/root/usr/lib/libssl.so.3).
type Libraries struct {
	SSL    string
	Crypto string
}

// libraryDirs are where distributions put OpenSSL 3.
var libraryDirs = []string{
	"/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/lib/aarch64-linux-gnu",
	"/usr/lib64", "/lib64", "/usr/lib", "/lib", "/usr/local/lib64", "/usr/local/lib",
}

// DefaultLibraries finds libssl.so.3 and libcrypto.so.3 side by side in the
// usual places.
func DefaultLibraries() (Libraries, error) {
	for _, dir := range libraryDirs {
		libs := Libraries{SSL: filepath.Join(dir, "libssl.so.3"), Crypto: filepath.Join(dir, "libcrypto.so.3")}
		if regular(libs.SSL) && regular(libs.Crypto) {
			return libs, nil
		}
	}
	return Libraries{}, errors.New("no OpenSSL 3 libssl.so.3 and libcrypto.so.3 found; name them with --observe-tls-libraries")
}

func regular(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// Observer is the attached probes and the reader that feeds an Assembler.
type Observer struct {
	coll    *ebpf.Collection
	links   []link.Link
	reader  *ringbuf.Reader
	asm     *Assembler
	tap     func(Event)
	stop    chan struct{}
	done    sync.WaitGroup
	closeMu sync.Mutex
	closed  bool
}

// Open loads the probes, attaches them to libs and starts feeding asm. It
// needs CAP_BPF and CAP_PERFMON (or CAP_SYS_ADMIN); Close detaches every
// probe.
func Open(libs Libraries, asm *Assembler) (*Observer, error) {
	return open(libs, asm, nil)
}

func open(libs Libraries, asm *Assembler, tap func(Event)) (*Observer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("session observer: lift the locked-memory limit for BPF maps: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(programObject))
	if err != nil {
		return nil, fmt.Errorf("session observer: read the probe program: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("session observer: load the probe program (needs CAP_BPF and CAP_PERFMON): %w", err)
	}
	o := &Observer{coll: coll, asm: asm, tap: tap, stop: make(chan struct{})}
	asm.executable = executable
	layout, err := libsslLayout(libs.SSL)
	if err != nil {
		_ = o.Close()
		return nil, err
	}
	if err := coll.Maps["libssl_layout"].Put(uint32(0), layout); err != nil {
		_ = o.Close()
		return nil, fmt.Errorf("session observer: record libssl's layout: %w", err)
	}
	ssl, err := link.OpenExecutable(libs.SSL)
	if err != nil {
		_ = o.Close()
		return nil, fmt.Errorf("session observer: open %s: %w", libs.SSL, err)
	}
	crypto, err := link.OpenExecutable(libs.Crypto)
	if err != nil {
		_ = o.Close()
		return nil, fmt.Errorf("session observer: open %s: %w", libs.Crypto, err)
	}
	for _, p := range probes {
		ex := ssl
		if p.crypto {
			ex = crypto
		}
		prog := coll.Programs[p.program]
		if prog == nil {
			_ = o.Close()
			return nil, fmt.Errorf("session observer: the probe program has no %s", p.program)
		}
		var l link.Link
		if p.ret {
			l, err = ex.Uretprobe(p.symbol, prog, nil)
		} else {
			l, err = ex.Uprobe(p.symbol, prog, nil)
		}
		if err != nil {
			_ = o.Close()
			return nil, fmt.Errorf("session observer: attach to %s: %w", p.symbol, err)
		}
		o.links = append(o.links, l)
	}
	if o.reader, err = ringbuf.NewReader(coll.Maps["events"]); err != nil {
		_ = o.Close()
		return nil, fmt.Errorf("session observer: open the event ring: %w", err)
	}
	o.done.Add(2)
	go o.read()
	go o.sweep()
	return o, nil
}

func (o *Observer) read() {
	defer o.done.Done()
	for {
		rec, err := o.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		e, err := DecodeEvent(rec.RawSample)
		if err != nil {
			continue
		}
		if o.tap != nil {
			o.tap(e)
		}
		o.asm.Add(e, time.Now())
	}
}

func (o *Observer) sweep() {
	defer o.done.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-o.stop:
			return
		case now := <-ticker.C:
			o.asm.Sweep(now)
		}
	}
}

// RingDrops is how many events the probes had no ring-buffer room for.
func (o *Observer) RingDrops() uint64 {
	m := o.coll.Maps["drops"]
	if m == nil {
		return 0
	}
	var perCPU []uint64
	if err := m.Lookup(uint32(0), &perCPU); err != nil {
		return 0
	}
	var total uint64
	for _, n := range perCPU {
		total += n
	}
	return total
}

// Close detaches every probe and stops the reader. It is safe to call more
// than once.
func (o *Observer) Close() error {
	o.closeMu.Lock()
	defer o.closeMu.Unlock()
	if o.closed {
		return nil
	}
	o.closed = true
	var errs []error
	for _, l := range o.links {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	o.links = nil
	if o.reader != nil {
		if err := o.reader.Close(); err != nil {
			errs = append(errs, err)
		}
		close(o.stop)
		o.done.Wait()
	}
	o.coll.Close()
	return errors.Join(errs...)
}

// sslLayout is struct layout: where SSL_set0_rbio and the executable segment
// holding it sit in the libssl file. The probes turn it into each process's
// libssl code range, to keep only the certificates libssl itself parses.
type sslLayout struct {
	Symbol uint64
	Start  uint64
	Size   uint64
}

func libsslLayout(path string) (sslLayout, error) {
	f, err := elf.Open(path)
	if err != nil {
		return sslLayout{}, fmt.Errorf("session observer: read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	syms, err := f.DynamicSymbols()
	if err != nil {
		return sslLayout{}, fmt.Errorf("session observer: %s symbols: %w", path, err)
	}
	for _, sym := range syms {
		if sym.Name != "SSL_set0_rbio" || sym.Value == 0 {
			continue
		}
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && sym.Value >= p.Vaddr && sym.Value < p.Vaddr+p.Memsz {
				return sslLayout{Symbol: sym.Value, Start: p.Vaddr, Size: p.Memsz}, nil
			}
		}
	}
	return sslLayout{}, fmt.Errorf("session observer: %s has no SSL_set0_rbio in an executable segment; is it OpenSSL 3's libssl?", path)
}

// executable reads a process's executable path; the probes report host PIDs.
func executable(pid uint32) string {
	path, err := os.Readlink("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/exe")
	if err != nil {
		return ""
	}
	return path
}
