//go:build !windows

// SPDX-License-Identifier: BUSL-1.1
package winaccounts

import "context"

type unsupportedRotationDriver struct{}

func newNativeRotationDriver() rotationDriver { return unsupportedRotationDriver{} }
func (unsupportedRotationDriver) Inspect(context.Context, RotationBinding) (RotationState, error) {
	return RotationState{}, ErrUnsupported
}
func (unsupportedRotationDriver) SetPassword(context.Context, RotationBinding, []byte) error {
	return ErrUnsupported
}
func (unsupportedRotationDriver) Authenticate(context.Context, RotationBinding, []byte) (string, error) {
	return "", ErrUnsupported
}
