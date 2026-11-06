// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/dynsecret"
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

func (p *configuredADRotationProvider) StaticRotationBinding(role string) string {
	if !p.AllowsStaticRotation(role) || p.RotationPhase(role) != dynsecret.RotationSinglePhase {
		return ""
	}
	raw, err := json.Marshal(struct {
		Role   string                             `json:"role"`
		Config config.DynamicSecretProviderConfig `json:"config"`
	}{role, p.cfg})
	if err != nil {
		return ""
	}
	return crypto.SHA256Hex(raw)
}
func (p *configuredADRotationProvider) PrepareStaticCredential(ctx context.Context, req dynsecret.GenerateRequest) ([]byte, error) {
	binding := p.StaticRotationBinding(req.Role)
	if binding == "" || !req.Static {
		return nil, errors.New("server: AD static preparation is not allowed")
	}
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return nil, err
	}
	defer closeBackend()
	preparer, ok := backend.(interface {
		PrepareStaticCredential(context.Context, dynsecret.GenerateRequest, string) ([]byte, error)
	})
	if !ok {
		return nil, errors.New("server: AD backend has no bound preparation")
	}
	return preparer.PrepareStaticCredential(ctx, req, binding)
}
func (p *configuredADRotationProvider) GenerateStaticPrepared(ctx context.Context, req dynsecret.GenerateRequest, prepared []byte) (dynsecret.Credential, error) {
	binding := p.StaticRotationBinding(req.Role)
	if binding == "" || !req.Static {
		return dynsecret.Credential{}, errors.New("server: AD prepared apply is not allowed")
	}
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return dynsecret.Credential{}, err
	}
	defer closeBackend()
	applier, ok := backend.(interface {
		GenerateStaticPrepared(context.Context, dynsecret.GenerateRequest, []byte, string) (string, []byte, error)
	})
	if !ok {
		return dynsecret.Credential{}, errors.New("server: AD backend has no prepared apply")
	}
	ref, value, err := applier.GenerateStaticPrepared(ctx, req, prepared, binding)
	return dynsecret.Credential{BackendRef: ref, Secret: value, Metadata: map[string]string{"role": req.Role, "provider_type": p.cfg.Type}}, err
}
func (p *configuredADRotationProvider) RestorePreparedStaticCredential(ctx context.Context, req dynsecret.GenerateRequest, prepared, old []byte) error {
	binding := p.StaticRotationBinding(req.Role)
	if binding == "" || !req.Static {
		return errors.New("server: AD prepared recovery is not allowed")
	}
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return err
	}
	defer closeBackend()
	restorer, ok := backend.(interface {
		RestorePreparedStaticCredential(context.Context, dynsecret.GenerateRequest, []byte, []byte, string) error
	})
	if !ok {
		return errors.New("server: AD backend has no prepared recovery")
	}
	return restorer.RestorePreparedStaticCredential(ctx, req, prepared, old, binding)
}
