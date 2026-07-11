// SPDX-License-Identifier: MPL-2.0

package secret

import "io"

const wipeIOChunkSize = 32 << 10

// Drain consumes reader through one owned fixed-size buffer until EOF. Every
// observed byte is wiped before the next read and the full allocation is wiped
// again before return. It is the unbounded counterpart used for child stdout and
// stderr pipes, where stopping at a byte limit could deadlock a noisy child.
func Drain(reader io.Reader) error {
	buffer := make([]byte, wipeIOChunkSize)
	defer Wipe(buffer)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			Wipe(buffer[:n])
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
}

// ReadBounded reads at most limit bytes directly into one caller-owned buffer.
// The caller owns the returned slice and must Wipe it. On any non-EOF read
// failure, ReadBounded wipes the entire allocation before returning the error.
//
// This deliberately does not use io.ReadAll or io.Copy: those helpers may grow
// through backing arrays the caller can no longer reach or use pooled scratch
// buffers whose former contents cannot be explicitly destroyed (AN-8).
func ReadBounded(reader io.Reader, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, nil
	}
	buffer := make([]byte, limit)
	used := 0
	for used < len(buffer) {
		n, err := reader.Read(buffer[used:])
		used += n
		if err == io.EOF {
			return buffer[:used:used], nil
		}
		if err != nil {
			Wipe(buffer)
			return nil, err
		}
		if n == 0 {
			Wipe(buffer)
			return nil, io.ErrNoProgress
		}
	}
	return buffer, nil
}

// DrainBounded consumes at most limit bytes through one fixed-size owned
// scratch buffer. Every chunk is wiped before the next read and the full
// allocation is wiped again before return. Callers may deliberately ignore the
// error when a response body is advisory, but no upstream bytes remain in a Go
// I/O pool (AN-8).
func DrainBounded(reader io.Reader, limit int) error {
	if limit <= 0 {
		return nil
	}
	size := limit
	if size > wipeIOChunkSize {
		size = wipeIOChunkSize
	}
	buffer := make([]byte, size)
	defer Wipe(buffer)
	remaining := limit
	for remaining > 0 {
		chunk := len(buffer)
		if chunk > remaining {
			chunk = remaining
		}
		n, err := reader.Read(buffer[:chunk])
		if n > 0 {
			Wipe(buffer[:n])
			remaining -= n
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
