// SPDX-License-Identifier: BUSL-1.1

package secret_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
)

type retainingReader struct {
	data     []byte
	readErr  error
	observed [][]byte
}

func (r *retainingReader) Read(dst []byte) (int, error) {
	if len(r.data) == 0 {
		if r.readErr != nil {
			err := r.readErr
			r.readErr = nil
			return 0, err
		}
		return 0, io.EOF
	}
	n := copy(dst, r.data)
	r.data = r.data[n:]
	r.observed = append(r.observed, dst[:n])
	return n, nil
}

func TestDrainBoundedWipesEveryOwnedReadBuffer(t *testing.T) {
	probe := bytes.Repeat([]byte("receiver-echo-secret"), 4096)
	reader := &retainingReader{data: probe}
	if err := secret.DrainBounded(reader, len(probe)); err != nil {
		t.Fatalf("DrainBounded: %v", err)
	}
	assertObservedWiped(t, reader.observed)
}

func TestDrainWipesEveryOwnedReadBufferUntilEOF(t *testing.T) {
	probe := bytes.Repeat([]byte("unbounded-child-echo-secret"), 8192)
	reader := &retainingReader{data: probe}
	if err := secret.Drain(reader); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	assertObservedWiped(t, reader.observed)
}

func TestReadBoundedReturnsWipeableOwnedBufferAndWipesReadFailure(t *testing.T) {
	reader := &retainingReader{data: []byte("receiver-echo-secret")}
	got, err := secret.ReadBounded(reader, 1024)
	if err != nil {
		t.Fatalf("ReadBounded: %v", err)
	}
	secret.Wipe(got)
	assertObservedWiped(t, reader.observed)

	failure := &retainingReader{
		data:    []byte("partial-receiver-secret"),
		readErr: errors.New("untrusted read failure"),
	}
	if got, err := secret.ReadBounded(failure, 1024); err == nil || got != nil {
		t.Fatalf("ReadBounded failure = (%x, %v), want nil buffer and error", got, err)
	}
	assertObservedWiped(t, failure.observed)
}

func assertObservedWiped(t *testing.T, observed [][]byte) {
	t.Helper()
	if len(observed) == 0 {
		t.Fatal("reader observed no destination buffer")
	}
	for _, view := range observed {
		if !bytes.Equal(view, make([]byte, len(view))) {
			t.Fatalf("owned I/O buffer retained receiver bytes: %x", view)
		}
	}
}
