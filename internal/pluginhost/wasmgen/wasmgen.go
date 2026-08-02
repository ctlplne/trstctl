// SPDX-License-Identifier: MPL-2.0

// Package wasmgen builds minimal WASM guest modules against the plugin host's
// capability ABI.
//
// It exists because the ABI passes paths and payloads as (pointer, length) pairs
// into the guest's own linear memory, so any fixture or reference plugin has to
// OWN a memory and preload it. Hand-encoded byte slices without a memory section
// can only call a host function that ignores its arguments — which is exactly how
// the capability sandbox came to be a stub whose tests looked green.
//
// This is deliberately not a general WASM encoder. It emits one shape: a module
// importing a single host function, owning one page of memory preloaded with a
// data segment, and exporting entry points that call that import with constant
// arguments. A general encoder would be a lot of untested code for a security
// test to depend on.
package wasmgen

// Section ids from the WebAssembly binary format, in the order a module must
// present them.
const (
	sectionType   byte = 1
	sectionImport byte = 2
	sectionFunc   byte = 3
	sectionMemory byte = 5
	sectionExport byte = 7
	sectionCode   byte = 10
	sectionData   byte = 11

	typeI32     byte = 0x7f
	funcTypeTag byte = 0x60

	opI32Const byte = 0x41
	opCall     byte = 0x10
	opEnd      byte = 0x0b
)

// ULEB encodes n as unsigned LEB128, the length/index encoding used throughout
// the binary format.
func ULEB(n uint32) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			out = append(out, b|0x80)
			continue
		}
		return append(out, b)
	}
}

// SLEB encodes n as signed LEB128, which is what i32.const takes.
func SLEB(n int32) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		signBit := b & 0x40
		if (n == 0 && signBit == 0) || (n == -1 && signBit != 0) {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

func vec(count int, body []byte) []byte { return append(ULEB(uint32(count)), body...) }

func section(id byte, payload []byte) []byte {
	out := []byte{id}
	out = append(out, ULEB(uint32(len(payload)))...)
	return append(out, payload...)
}

func name(s string) []byte { return append(ULEB(uint32(len(s))), s...) }

// Export is one exported entry point: its name, and the constant arguments the
// generated body passes to the imported host function before returning its
// result. An Export with no Args returns Const instead of calling the import,
// which is how a conformance entry point ("run") stays free of privileged calls.
type Export struct {
	Name  string
	Args  []int32
	Const int32
}

// Module builds a guest module that imports env.<fn> taking nParams i32
// arguments and returning i32, owns and exports one page of linear memory
// preloaded with data at offset 0, and exports each entry in exports.
//
// The imported function occupies function index 0; the exported bodies follow.
func Module(fn string, nParams int, data []byte, exports []Export) []byte {
	params := make([]byte, 0, nParams)
	for i := 0; i < nParams; i++ {
		params = append(params, typeI32)
	}
	// type 0: (i32 x nParams) -> i32, the host function. type 1: () -> i32, bodies.
	hostType := append([]byte{funcTypeTag}, vec(nParams, params)...)
	hostType = append(hostType, vec(1, []byte{typeI32})...)
	bodyType := append([]byte{funcTypeTag}, vec(0, nil)...)
	bodyType = append(bodyType, vec(1, []byte{typeI32})...)
	types := section(sectionType, vec(2, append(hostType, bodyType...)))

	imp := append(name("env"), name(fn)...)
	imp = append(imp, 0x00, 0x00) // kind: func, type index 0
	imports := section(sectionImport, vec(1, imp))

	var funcDecls []byte
	for range exports {
		funcDecls = append(funcDecls, ULEB(1)...) // each body has type 1
	}
	funcs := section(sectionFunc, vec(len(exports), funcDecls))

	mems := section(sectionMemory, vec(1, []byte{0x00, 0x01})) // limits: min 1 page

	var exportEntries []byte
	for i, e := range exports {
		exportEntries = append(exportEntries, name(e.Name)...)
		exportEntries = append(exportEntries, 0x00)                 // kind: func
		exportEntries = append(exportEntries, ULEB(uint32(i+1))...) // index 0 is the import
	}
	exportEntries = append(exportEntries, name("memory")...)
	exportEntries = append(exportEntries, 0x02, 0x00) // kind: memory, index 0
	exportSec := section(sectionExport, vec(len(exports)+1, exportEntries))

	var bodies []byte
	for _, e := range exports {
		body := vec(0, nil) // no locals
		if len(e.Args) == 0 {
			body = append(body, opI32Const)
			body = append(body, SLEB(e.Const)...)
		} else {
			for _, a := range e.Args {
				body = append(body, opI32Const)
				body = append(body, SLEB(a)...)
			}
			body = append(body, opCall, 0x00)
		}
		body = append(body, opEnd)
		bodies = append(bodies, ULEB(uint32(len(body)))...)
		bodies = append(bodies, body...)
	}
	code := section(sectionCode, vec(len(exports), bodies))

	seg := []byte{0x00, opI32Const, 0x00, opEnd} // active, memory 0, offset 0
	seg = append(seg, ULEB(uint32(len(data)))...)
	seg = append(seg, data...)
	dataSec := section(sectionData, vec(1, seg))

	out := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00} // magic + version
	for _, s := range [][]byte{types, imports, funcs, mems, exportSec, code, dataSec} {
		out = append(out, s...)
	}
	return out
}

// WriteGuest builds a plugin whose entry points call cap_write(path, content).
//
// Memory layout: the path at offset 0, the content immediately after it, so the
// four ABI arguments are (0, len(path), len(path), len(content)).
func WriteGuest(path, content string, entries ...string) []byte {
	if len(entries) == 0 {
		entries = []string{"run"}
	}
	args := []int32{0, int32(len(path)), int32(len(path)), int32(len(content))}
	exports := make([]Export, 0, len(entries))
	for _, e := range entries {
		exports = append(exports, Export{Name: e, Args: args})
	}
	return Module("cap_write", 4, []byte(path+content), exports)
}

// ReadGuest builds a plugin that calls cap_read(path, out=1024, cap=256,
// outLen=2048). The out buffer and length cell sit clear of the path bytes inside
// the single page this module owns.
func ReadGuest(path string, entries ...string) []byte {
	if len(entries) == 0 {
		entries = []string{"run"}
	}
	args := []int32{0, int32(len(path)), 1024, 256, 2048}
	exports := make([]Export, 0, len(entries))
	for _, e := range entries {
		exports = append(exports, Export{Name: e, Args: args})
	}
	return Module("cap_read", 5, []byte(path), exports)
}

// DialGuest builds a plugin that calls cap_dial(addr).
func DialGuest(addr string, entries ...string) []byte {
	if len(entries) == 0 {
		entries = []string{"run"}
	}
	args := []int32{0, int32(len(addr))}
	exports := make([]Export, 0, len(entries))
	for _, e := range entries {
		exports = append(exports, Export{Name: e, Args: args})
	}
	return Module("cap_dial", 2, []byte(addr), exports)
}
