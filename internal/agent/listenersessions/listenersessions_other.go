// SPDX-License-Identifier: BUSL-1.1

//go:build !linux

package listenersessions

import "time"

func observe(int, time.Time) (Observation, error) { return Observation{}, ErrUnsupported }
