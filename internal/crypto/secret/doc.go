// Package secret provides memory-safe buffers for secret key material (AN-8).
//
// A Buffer keeps its bytes in a dedicated, page-aligned mmap region that, on
// Linux, is locked into RAM (mlock, so it is never swapped to disk) and
// excluded from core dumps (madvise MADV_DONTDUMP). Every Buffer is explicitly
// zeroized on Destroy (a manual zero loop kept alive with runtime.KeepAlive).
// On non-Linux platforms the locking and dump-protection are best-effort no-ops
// and the buffer is an ordinary allocation that is still zeroized; Linux is the
// production target.
//
// Secret material must live in []byte, never string: Go's garbage collector may
// freely copy strings and a string's bytes cannot be wiped. This package is
// marked as key-handling so the trstctllint AN-8 rule forbids any string-typed
// field, parameter, or result here.
package secret

//trstctl:keymaterial
