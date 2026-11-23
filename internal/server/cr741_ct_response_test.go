// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"
	"math"
	"testing"
	"time"
)

func TestCR741FutureSCTResponseRejectedBeforeEventAppend(t *testing.T) {
	for _, timestamp := range []int64{math.MaxInt64, time.Now().Add(10 * time.Minute).UnixMilli()} {
		body := []byte(fmt.Sprintf(`{"sct_version":0,"id":"fixture","timestamp":%d,"signature":"fixture"}`, timestamp))
		if got, err := validateCTSCTResponse(body); err == nil {
			t.Errorf("future SCT timestamp %d accepted as %d", timestamp, got)
		}
	}
}
