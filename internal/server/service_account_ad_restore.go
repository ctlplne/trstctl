// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
)

// Only the explicit AD profile advertises native recovery. A provider with no
// inverse API must not accidentally satisfy this capability through a no-op.
type configuredADRotationProvider struct{ *configuredDynamicProvider }

func (p *configuredADRotationProvider) RestoreStaticCredential(ctx context.Context, role, ref string, credential []byte) error {
	if !p.AllowsStaticRotation(role) {
		return errors.New("server: AD restore role is not allowed")
	}
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return err
	}
	defer closeBackend()
	restorer, ok := backend.(interface {
		RestoreStaticCredential(context.Context, string, string, []byte) error
	})
	if !ok {
		return errors.New("server: AD backend cannot restore its native credential")
	}
	return restorer.RestoreStaticCredential(ctx, role, ref, credential)
}
