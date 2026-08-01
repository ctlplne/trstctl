// SPDX-License-Identifier: MPL-2.0

//go:build race

package main

// The race detector deliberately adds synchronization and memory-tracking work.
// Its run proves safety and coverage, but its wall-clock timings are not production
// timings. Makefile runs the same SLO test again without instrumentation and keeps
// that second invocation blocking.
const raceInstrumentationEnabled = true
