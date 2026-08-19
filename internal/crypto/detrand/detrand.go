// SPDX-License-Identifier: MPL-2.0

// Package detrand provides a deterministic byte stream derived from a seed, for
// the rare cases where an encoder's randomness must be a pure function of its
// input. It lives in the crypto boundary (AN-3): it is the only place outside the
// rest of internal/crypto that uses crypto/sha256 for this purpose.
//
// Its sole use is making keystore encoding (PKCS#12, JKS) reproducible: salts and
// IVs are derived from the credential being packaged rather than from
// rand.Reader, so re-encoding the same credential yields byte-identical output
// and a keystore deployment is idempotent (AN-5/AN-6). This is sound because
// those salts are not secret — they are stored in the keystore in the clear — and
// remain unique per distinct credential. It must NOT be used to generate keys,
// nonces for AEADs over varying plaintexts, or any value that must be
// unpredictable.
package detrand

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
)

// reader is a SHA-256 counter-mode stream: block_i = SHA256(seed || i).
type reader struct {
	seed [sha256.Size]byte
	ctr  uint64
	buf  []byte
}

// New returns a deterministic io.Reader whose stream is a function of the
// concatenated seed parts. The same parts always yield the same stream.
func New(parts ...[]byte) io.Reader {
	h := sha256.New()
	for _, p := range parts {
		// Length-prefix each part so distinct part boundaries cannot collide.
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		// This is deterministic stream-domain separation for public keystore
		// salts/IVs, not password verification.
		// codeql[go/weak-sensitive-data-hashing]
		h.Write(p)
	}
	r := &reader{}
	copy(r.seed[:], h.Sum(nil))
	return r
}

// Read fills p with the next bytes of the deterministic stream. It never fails
// and never returns a short read.
func (r *reader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(r.buf) == 0 {
			block := make([]byte, 0, sha256.Size+8)
			block = append(block, r.seed[:]...)
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], r.ctr)
			r.ctr++
			block = append(block, c[:]...)
			sum := sha256.Sum256(block)
			r.buf = sum[:]
		}
		m := copy(p[n:], r.buf)
		r.buf = r.buf[m:]
		n += m
	}
	return n, nil
}
