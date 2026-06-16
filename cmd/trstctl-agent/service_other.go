//go:build !windows

package main

import "fmt"

// handleService reports that service mode is Windows-only. On Linux and macOS
// the agent runs as a foreground process (interactive, or under systemd /
// launchd, which manage it externally).
func handleService(action string, _ agentOptions) error {
	return fmt.Errorf("--service is only supported on Windows (got %q); run the agent in the foreground instead", action)
}
