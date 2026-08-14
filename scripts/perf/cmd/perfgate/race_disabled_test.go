// SPDX-License-Identifier: MPL-2.0

//go:build !race

package main

const (
	raceInstrumentationEnabled = false
	liveProfileSamples         = 64
)
