// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"context"
	"errors"
)

type servicePhaseDriver interface {
	stop(context.Context, Service) (Runtime, error)
	start(context.Context, Service) (Runtime, error)
}

func (s *Services) rotationPhase(ctx context.Context, target Service, start bool) (Runtime, error) {
	if err := s.inspectBound(ctx, target); err != nil {
		return Runtime{}, err
	}
	current, err := s.driver.inspect(ctx, target.Name)
	if err != nil {
		return Runtime{}, err
	}
	if !sameServiceBinding(target, current) {
		return Runtime{}, errors.New("windows service: phase authority changed")
	}
	if !target.WasRunning {
		if current.WasRunning {
			return Runtime{}, errors.New("windows service: originally stopped state changed")
		}
		return Runtime{}, nil
	}
	driver, ok := s.driver.(servicePhaseDriver)
	if !ok {
		return Runtime{}, errors.New("windows service: separate native rotation phases unavailable")
	}
	var result Runtime
	if start {
		result, err = driver.start(ctx, target)
	} else {
		result, err = driver.stop(ctx, target)
	}
	if err != nil {
		return Runtime{}, err
	}
	if start {
		if !result.Running || result.ProcessID == 0 || result.AccountSID != target.AccountSID {
			return Runtime{}, errors.New("windows service: phase process identity unproven")
		}
	} else if result.Running || result.ProcessID != 0 {
		return Runtime{}, errors.New("windows service: stop phase did not reach a stopped state")
	}
	return result, nil
}

// StopForRotation permits dependency-aware reverse stop order before any start.
func (s *Services) StopForRotation(ctx context.Context, target Service) (Runtime, error) {
	return s.rotationPhase(ctx, target, false)
}

// StartAfterRotation restores only a service whose reviewed state was running.
func (s *Services) StartAfterRotation(ctx context.Context, target Service) (Runtime, error) {
	return s.rotationPhase(ctx, target, true)
}
