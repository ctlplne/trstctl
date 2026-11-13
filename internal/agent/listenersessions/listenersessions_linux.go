// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package listenersessions

import "time"

func observe(port int, since time.Time) (Observation, error) {
	return observeProc("/proc", port, since, time.Now())
}
