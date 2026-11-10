// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Pool configuration can contain private environment values. Keep the framed
// aggregate in one locked buffer; do not leave private fields in a streaming
// hash object's heap buffer after the snapshot is released.
type poolHashBuffer struct {
	held *secret.Buffer
	used int
}

func newPoolHashBuffer() (*poolHashBuffer, error) {
	held, err := secret.New(2 << 20)
	if err != nil {
		return nil, err
	}
	return &poolHashBuffer{held: held}, nil
}
func (b *poolHashBuffer) destroy() {
	if b.held != nil {
		b.held.Destroy()
		b.held = nil
	}
}

// field and digest touch the locked region only inside Buffer.Use, which holds
// its read lock for the whole access (ARCH-014): Bytes() would release the
// lock before the slice is read, so a concurrent destroy could wipe and unmap
// the region under the copy or the hash.
func (b *poolHashBuffer) field(value []byte) error {
	return b.held.Use(func(raw []byte) error {
		if len(value) > 2<<20 || b.used > len(raw)-8-len(value) {
			return errors.New("windows pool: private configuration exceeds snapshot byte bound")
		}
		binary.LittleEndian.PutUint64(raw[b.used:], uint64(len(value)))
		b.used += 8
		copy(raw[b.used:], value)
		b.used += len(value)
		return nil
	})
}

func (b *poolHashBuffer) digest() string {
	var sum [sha256.Size]byte
	_ = b.held.Use(func(raw []byte) error {
		sum = sha256.Sum256(raw[:b.used])
		return nil
	})
	return hex.EncodeToString(sum[:])
}
