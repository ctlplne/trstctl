//go:build !windows

// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"context"
	"errors"
)

type unsupportedPoolDriver struct{}

func newNativePoolDriver() poolDriver { return unsupportedPoolDriver{} }
func (unsupportedPoolDriver) discover(context.Context, string) ([]Pool, error) {
	return nil, errors.New("IIS pools require an enrolled Windows host")
}
func (unsupportedPoolDriver) inspect(context.Context, string) (Pool, error) {
	return Pool{}, errors.New("IIS pools require an enrolled Windows host")
}
func (unsupportedPoolDriver) update(context.Context, Pool, []byte) (Pool, error) {
	return Pool{}, errors.New("IIS pools require an enrolled Windows host")
}
func (unsupportedPoolDriver) restart(context.Context, Pool) (PoolRestartProof, error) {
	return PoolRestartProof{}, errors.New("IIS pools require an enrolled Windows host")
}
func (unsupportedPoolDriver) workers(context.Context, string) ([]PoolWorker, error) {
	return nil, errors.New("IIS pools require an enrolled Windows host")
}
