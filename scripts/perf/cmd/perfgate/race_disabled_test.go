// SPDX-License-Identifier: BUSL-1.1

//go:build !race

package main

const (
	raceInstrumentationEnabled = false
	liveProfileSamples         = 64
)
