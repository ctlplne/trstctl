// Package bodylimit provides strict request-body size enforcement for protocol
// handlers that parse attacker-controlled bytes.
package bodylimit

import (
	"errors"
	"io"
)

// ErrTooLarge marks a request body that exceeded its protocol cap.
var ErrTooLarge = errors.New("request body too large")

// ReadAll reads r only up to limit+1 bytes and fails when the body exceeds limit.
// io.LimitReader alone silently returns a valid prefix; protocol parsers need this
// overflow byte so a valid prefix plus attacker-controlled suffix cannot be accepted.
func ReadAll(r io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, ErrTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrTooLarge
	}
	return body, nil
}
