// SPDX-License-Identifier: BUSL-1.1

package host

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/native"
	"trstctl.com/trstctl/internal/connector/wasm/abi"
	"trstctl.com/trstctl/internal/pluginhost"
)

// bound is a family's connector whose operations run in the module. Name,
// grant and Close come from the host-built instance, which never runs an
// operation itself.
type bound struct {
	rt          *Runtime
	native      connector.Connector
	family      string
	config      native.Target
	credentials map[string][]byte
}

func (b *bound) Name() string                   { return b.native.Name() }
func (b *bound) Capabilities() pluginhost.Grant { return b.native.Capabilities() }

// Close releases what the host-built instance owns (for example a keystore
// password); the module's copies died with their instances.
func (b *bound) Close() {
	if closer, ok := b.native.(interface{ Close() }); ok {
		closer.Close()
	}
}

func (b *bound) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	_, err := b.run(ctx, sb, abi.Call{Op: abi.OpDeploy, Deployment: &dep})
	return err
}

// run invokes one operation and returns the guest's result, its error rebuilt
// on this side.
func (b *bound) run(ctx context.Context, sb connector.Sandbox, call abi.Call) (abi.Result, error) {
	call.Family, call.Config, call.Credentials = b.family, b.config, b.credentials
	result, err := b.rt.invoke(ctx, sb, call)
	if err != nil {
		return abi.Result{}, err
	}
	return result, result.Error.Decode()
}

// The optional operations are separate types, so each binding exposes exactly
// the operations its family implements: hosts discover them by type assertion.

type readbackOp struct{ b *bound }

func (o readbackOp) Readback(ctx context.Context, sb connector.Sandbox, target string) (connector.Installed, error) {
	result, err := o.b.run(ctx, sb, abi.Call{Op: abi.OpReadback, TargetName: target})
	if err != nil {
		return connector.Installed{}, err
	}
	if result.Installed == nil {
		return connector.Installed{}, fmt.Errorf("connector sandbox: %s readback returned nothing", o.b.family)
	}
	return *result.Installed, nil
}

type previewOp struct{ b *bound }

func (o previewOp) Preview(ctx context.Context, sb connector.Sandbox, target string) (connector.Preview, error) {
	result, err := o.b.run(ctx, sb, abi.Call{Op: abi.OpPreview, TargetName: target})
	if err != nil {
		return connector.Preview{}, err
	}
	if result.Preview == nil {
		return connector.Preview{}, fmt.Errorf("connector sandbox: %s preview returned nothing", o.b.family)
	}
	return *result.Preview, nil
}

type rollbackOp struct{ b *bound }

func (o rollbackOp) Rollback(ctx context.Context, sb connector.Sandbox, rb connector.Rollback) error {
	_, err := o.b.run(ctx, sb, abi.Call{Op: abi.OpRollback, Rollback: &rb})
	return err
}

type legacyRollbackOp struct{ b *bound }

func (o legacyRollbackOp) RollbackLegacy(ctx context.Context, sb connector.Sandbox, rb connector.Rollback) error {
	_, err := o.b.run(ctx, sb, abi.Call{Op: abi.OpRollbackLegacy, Rollback: &rb})
	return err
}

type takedownOp struct{ b *bound }

func (o takedownOp) Takedown(ctx context.Context, sb connector.Sandbox, td connector.Takedown) error {
	_, err := o.b.run(ctx, sb, abi.Call{Op: abi.OpTakedown, Takedown: &td})
	return err
}

type postureOp struct{ b *bound }

func (o postureOp) ReadTLSPosture(ctx context.Context, sb connector.Sandbox, target string) (connector.TLSPosture, error) {
	result, err := o.b.run(ctx, sb, abi.Call{Op: abi.OpReadTLSPosture, TargetName: target})
	if err != nil {
		return connector.TLSPosture{}, err
	}
	if result.Posture == nil {
		return connector.TLSPosture{}, fmt.Errorf("connector sandbox: %s posture read returned nothing", o.b.family)
	}
	return *result.Posture, nil
}

func (o postureOp) ApplyTLSPosture(ctx context.Context, sb connector.Sandbox, target string, posture connector.TLSPosture) error {
	_, err := o.b.run(ctx, sb, abi.Call{Op: abi.OpApplyTLSPosture, TargetName: target, Posture: &posture})
	return err
}

type applianceKeyOp struct{ b *bound }

func (o applianceKeyOp) GenerateApplianceKey(ctx context.Context, sb connector.Sandbox, req connector.ApplianceKeyRequest) (connector.ApplianceKey, error) {
	result, err := o.b.run(ctx, sb, abi.Call{Op: abi.OpGenerateApplianceKey, ApplianceKeyRequest: &req})
	if err != nil {
		return connector.ApplianceKey{}, err
	}
	if result.ApplianceKey == nil {
		return connector.ApplianceKey{}, fmt.Errorf("connector sandbox: %s key generation returned nothing", o.b.family)
	}
	return *result.ApplianceKey, nil
}

func (o applianceKeyOp) InstallWithApplianceKey(ctx context.Context, sb connector.Sandbox, dep connector.Deployment, key connector.ApplianceKey) error {
	_, err := o.b.run(ctx, sb, abi.Call{Op: abi.OpInstallWithApplianceKey, Deployment: &dep, ApplianceKey: &key})
	return err
}

// operations is the optional-operation set of a connector.
type operations uint8

const (
	opsReadback operations = 1 << iota
	opsPreview
	opsRollback
	opsLegacyRollback
	opsTakedown
	opsPosture
	opsApplianceKey
)

func operationsOf(c connector.Connector) operations {
	var ops operations
	if _, ok := c.(connector.Readbacker); ok {
		ops |= opsReadback
	}
	if _, ok := c.(connector.Previewer); ok {
		ops |= opsPreview
	}
	if _, ok := c.(connector.Rollbacker); ok {
		ops |= opsRollback
	}
	if _, ok := c.(connector.LegacyRollbacker); ok {
		ops |= opsLegacyRollback
	}
	if _, ok := c.(connector.Takedowner); ok {
		ops |= opsTakedown
	}
	if _, ok := c.(connector.TLSPostureConnector); ok {
		ops |= opsPosture
	}
	if _, ok := c.(connector.ApplianceKeyGenerator); ok {
		ops |= opsApplianceKey
	}
	return ops
}

// The bindings, one per optional-operation set a shipped family has.
type (
	plainBinding   struct{ *bound }
	previewBinding struct {
		*bound
		previewOp
	}
	postureBinding struct {
		*bound
		postureOp
	}
	rebindBinding struct {
		*bound
		readbackOp
		rollbackOp
	}
	rebindPreviewBinding struct {
		*bound
		readbackOp
		previewOp
		rollbackOp
	}
	rebindKeyBinding struct {
		*bound
		readbackOp
		rollbackOp
		applianceKeyOp
	}
	rebindTakedownBinding struct {
		*bound
		readbackOp
		rollbackOp
		legacyRollbackOp
		takedownOp
	}
	applianceBinding struct {
		*bound
		readbackOp
		rollbackOp
		legacyRollbackOp
		takedownOp
		applianceKeyOp
	}
)

// withOperations wraps b in the binding whose operation set is exactly
// built's. A family with a set no binding covers is refused rather than bound
// with operations missing or invented.
func (b *bound) withOperations(built connector.Connector) (connector.Connector, error) {
	rb, pv, rk := readbackOp{b}, previewOp{b}, rollbackOp{b}
	legacy, td, posture, key := legacyRollbackOp{b}, takedownOp{b}, postureOp{b}, applianceKeyOp{b}
	switch ops := operationsOf(built); ops {
	case 0:
		return plainBinding{b}, nil
	case opsPreview:
		return previewBinding{b, pv}, nil
	case opsPosture:
		return postureBinding{b, posture}, nil
	case opsReadback | opsRollback:
		return rebindBinding{b, rb, rk}, nil
	case opsReadback | opsPreview | opsRollback:
		return rebindPreviewBinding{b, rb, pv, rk}, nil
	case opsReadback | opsRollback | opsApplianceKey:
		return rebindKeyBinding{b, rb, rk, key}, nil
	case opsReadback | opsRollback | opsLegacyRollback | opsTakedown:
		return rebindTakedownBinding{b, rb, rk, legacy, td}, nil
	case opsReadback | opsRollback | opsLegacyRollback | opsTakedown | opsApplianceKey:
		return applianceBinding{b, rb, rk, legacy, td, key}, nil
	default:
		return nil, fmt.Errorf("connector sandbox: no binding covers %s's operations (%07b)", b.family, ops)
	}
}
