// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"errors"
	"time"
)

// feedCapturedFrame contains an unexpected parser panic at the capture boundary.
// The caller must stop using this assembler after an error: a panic may have
// interrupted a state update, and replay must not report a partial capture.
func feedCapturedFrame(a *Assembler, frame []byte, at time.Time) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("observe: parser failed on captured frame")
		}
	}()
	a.Frame(frame, at)
	return nil
}
