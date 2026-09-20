// SPDX-License-Identifier: BUSL-1.1

//go:build race

package main

// The race detector deliberately adds synchronization and memory-tracking work.
// Whole-repository coverage adds another timing wrapper. This lane therefore runs
// a small but complete realistic/peak route proof: every served hot path still runs
// in both phases, while the signer child remains inside the live stack's bounded
// lifetime. Makefile separately runs 64 realistic and 128 peak samples without
// instrumentation; that production-timing receipt remains the blocking SLO wall.
const (
	raceInstrumentationEnabled = true
	liveProfileSamples         = 4
)
