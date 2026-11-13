// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package secretrender

import "errors"

// sendServiceControl: only Windows has a Service Control Manager; a template
// naming a service is refused before anything runs.
func sendServiceControl(string, uint32) error {
	return errors.New("secretrender: service reloads are Windows-only")
}
