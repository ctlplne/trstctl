// SPDX-License-Identifier: BUSL-1.1

//go:build !linux

package decoy

import (
	"context"
	"errors"
)

// errNeedsLinux says decoy files are watched with fanotify or inotify.
var errNeedsLinux = errors.New("decoy: watching decoy files needs Linux (fanotify or inotify)")

// Watcher holds an armed decoy watch; none can be armed off Linux.
type Watcher struct{}

// Mechanism is empty: nothing watches.
func (w *Watcher) Mechanism() string { return "" }

// Run reports nothing.
func (w *Watcher) Run(context.Context, func(Access)) error { return errNeedsLinux }

// Arm needs Linux.
func Arm([]Decoy) (*Watcher, error) { return nil, errNeedsLinux }

// Watch needs Linux.
func Watch(context.Context, []Decoy, func(Access)) (string, error) { return "", errNeedsLinux }
