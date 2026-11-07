// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"trstctl.com/trstctl/internal/dynsecret"
)

func (p *configuredADRotationProvider) VerifyStaticPreparedCredential(ctx context.Context, req dynsecret.GenerateRequest, prepared, credential []byte) error {
	binding := p.StaticRotationBinding(req.Role)
	if binding == "" || !req.Static {
		return errors.New("server: final AD proof requires its exact static preparation")
	}
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return err
	}
	defer closeBackend()
	verifier, ok := backend.(interface {
		VerifyStaticPreparedCredential(context.Context, dynsecret.GenerateRequest, []byte, []byte, string) error
	})
	if !ok {
		return errors.New("server: AD backend cannot prove its prepared final generation")
	}
	return verifier.VerifyStaticPreparedCredential(ctx, req, prepared, credential, binding)
}

func (p *configuredADRotationProvider) ValidateStaticRecoveryCredential(req dynsecret.GenerateRequest, raw []byte) error {
	dn, ok := p.cfg.RoleBindings[req.Role]
	if !ok || !req.Static || req.LeaseID == "" || p.StaticRotationBinding(req.Role) == "" {
		return errors.New("server: exact static AD recovery role required")
	}
	if err := dynsecret.ValidateADRecoveryCredential(raw, dn); err != nil {
		return err
	}
	return dynsecret.ValidateADRecoveryCredential(raw, req.Predecessor)
}
