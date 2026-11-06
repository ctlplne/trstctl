// SPDX-License-Identifier: BUSL-1.1
//go:build !windows

package windependents

import (
	"context"
	"errors"
)

type unsupportedServiceDriver struct{}

func newNativeServiceDriver() serviceDriver { return unsupportedServiceDriver{} }
func (unsupportedServiceDriver) discover(context.Context, string) ([]Service, error) {
	return nil, errors.New("windows services require an enrolled Windows host")
}
func (unsupportedServiceDriver) inspect(context.Context, string) (Service, error) {
	return Service{}, errors.New("windows services require an enrolled Windows host")
}
func (unsupportedServiceDriver) update(context.Context, Service, []byte) error {
	return errors.New("windows services require an enrolled Windows host")
}
func (unsupportedServiceDriver) restart(context.Context, Service) (Runtime, error) {
	return Runtime{}, errors.New("windows services require an enrolled Windows host")
}
