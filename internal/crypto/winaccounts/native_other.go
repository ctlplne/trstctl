//go:build !windows

// SPDX-License-Identifier: BUSL-1.1
package winaccounts

import "context"

type unavailableDriver struct{}

func newNativeDriver() driver                                      { return unavailableDriver{} }
func (unavailableDriver) Machine(context.Context) (Machine, error) { return Machine{}, ErrUnsupported }
func (unavailableDriver) Administrators(context.Context, func(Member) error) error {
	return ErrUnsupported
}
func (unavailableDriver) User(context.Context, string) (Account, error) {
	return Account{}, ErrUnsupported
}
