// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"errors"
	"strings"
	"testing"
)

type auditVerifyCloseErrorReader struct {
	*strings.Reader
	err error
}

func (r auditVerifyCloseErrorReader) Close() error { return r.err }

type auditVerifyReadCloseError struct {
	readErr  error
	closeErr error
}

func (r auditVerifyReadCloseError) Read([]byte) (int, error) { return 0, r.readErr }
func (r auditVerifyReadCloseError) Close() error             { return r.closeErr }

func TestAuditVerifyReadCloserReturnsCloseFailure(t *testing.T) {
	closeErr := errors.New("fixture close failure")
	raw, err := readAuditVerifyReadCloser(auditVerifyCloseErrorReader{
		Reader: strings.NewReader("artifact"), err: closeErr,
	}, 32)
	if string(raw) != "artifact" || !errors.Is(err, closeErr) {
		t.Fatalf("read/close = %q, %v; want bytes plus close failure", raw, err)
	}
}

func TestAuditVerifyReadCloserJoinsReadAndCloseFailures(t *testing.T) {
	readErr := errors.New("fixture read failure")
	closeErr := errors.New("fixture close failure")
	raw, err := readAuditVerifyReadCloser(auditVerifyReadCloseError{
		readErr: readErr, closeErr: closeErr,
	}, 32)
	if raw != nil || !errors.Is(err, readErr) || !errors.Is(err, closeErr) {
		t.Fatalf("joined read/close = %q, %v; want both failures", raw, err)
	}
}
