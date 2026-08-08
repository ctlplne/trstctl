// SPDX-License-Identifier: MPL-2.0

//go:build windows

package main

import "os"

// restartSelf exits so the supervisor starts the just-staged binary (epic A5).
//
// Windows has no exec: a process cannot replace its own image. The staged
// binary already sits at the service's configured path (the old one beside it
// as .old), so whatever starts the agent next — the Service Control Manager's
// recovery action, a scheduled task, or an operator — starts the new build.
// Deployments using --service should configure service recovery to restart;
// without it the agent stays down after an upgrade, which the ring then
// reports as silence and halts on. That is documented in docs/limitations.md
// rather than papered over here with a spawned orphan that would not be the
// service process.
func restartSelf() error {
	os.Exit(0)
	return nil
}
