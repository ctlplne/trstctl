//go:build !windows

// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"context"
	"errors"
)

type unsupportedTaskDriver struct{}

func newNativeTaskDriver() taskDriver { return unsupportedTaskDriver{} }
func (unsupportedTaskDriver) discover(context.Context, string) ([]Task, error) {
	return nil, errors.New("windows tasks require an enrolled Windows host")
}
func (unsupportedTaskDriver) inspect(context.Context, string) (Task, error) {
	return Task{}, errors.New("windows tasks require an enrolled Windows host")
}
func (unsupportedTaskDriver) update(context.Context, Task, []byte) error {
	return errors.New("windows tasks require an enrolled Windows host")
}
func (unsupportedTaskDriver) run(context.Context, Task) (TaskRunProof, error) {
	return TaskRunProof{}, errors.New("windows tasks require an enrolled Windows host")
}
