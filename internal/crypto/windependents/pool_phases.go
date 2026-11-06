// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"context"
	"errors"
)

type poolPhaseDriver interface {
	stop(context.Context, Pool) (PoolRestartProof, error)
	start(context.Context, Pool, PoolRestartProof) (PoolRestartProof, error)
}

func validateStoppedPool(pool Pool, proof PoolRestartProof) error {
	copy := proof
	copy.StartedObserved = pool.WasStarted
	if proof.StartedObserved {
		return errors.New("windows pool: stop evidence already claims a start")
	}
	return validatePoolRestart(pool, copy)
}
func (p *Pools) StopForRotation(ctx context.Context, pool Pool) (PoolRestartProof, error) {
	if e := p.inspectBound(ctx, pool); e != nil {
		return PoolRestartProof{}, e
	}
	current, e := p.driver.inspect(ctx, pool.Name)
	if e != nil {
		return PoolRestartProof{}, e
	}
	if !samePoolBinding(pool, current) {
		return PoolRestartProof{}, errors.New("windows pool: stop authority changed")
	}
	if !pool.WasStarted {
		workers, e := p.driver.workers(ctx, pool.Name)
		if e != nil {
			return PoolRestartProof{}, e
		}
		if current.WasStarted || len(workers) != 0 {
			return PoolRestartProof{}, errors.New("windows pool: originally stopped state changed")
		}
		return PoolRestartProof{Name: pool.Name, AccountSID: pool.AccountSID, ConfigSHA256: pool.ConfigSHA256, StoppedObserved: true}, nil
	}
	driver, ok := p.driver.(poolPhaseDriver)
	if !ok {
		return PoolRestartProof{}, errors.New("windows pool: separate native phases unavailable")
	}
	proof, e := driver.stop(ctx, pool)
	if e != nil {
		return PoolRestartProof{}, e
	}
	if e = validateStoppedPool(pool, proof); e != nil {
		return PoolRestartProof{}, e
	}
	return proof, nil
}
func (p *Pools) StartAfterRotation(ctx context.Context, pool Pool, stopped PoolRestartProof) (PoolRestartProof, error) {
	if e := p.inspectBound(ctx, pool); e != nil {
		return PoolRestartProof{}, e
	}
	if e := validateStoppedPool(pool, stopped); e != nil {
		return PoolRestartProof{}, e
	}
	if !pool.WasStarted {
		current, e := p.driver.inspect(ctx, pool.Name)
		if e != nil {
			return PoolRestartProof{}, e
		}
		workers, e := p.driver.workers(ctx, pool.Name)
		if e != nil {
			return PoolRestartProof{}, e
		}
		if current.WasStarted || len(workers) != 0 {
			return PoolRestartProof{}, errors.New("windows pool: originally stopped pool was started")
		}
		return stopped, nil
	}
	driver, ok := p.driver.(poolPhaseDriver)
	if !ok {
		return PoolRestartProof{}, errors.New("windows pool: separate native phases unavailable")
	}
	proof, e := driver.start(ctx, pool, stopped)
	if e != nil {
		return PoolRestartProof{}, e
	}
	if e = validatePoolRestart(pool, proof); e != nil {
		return PoolRestartProof{}, e
	}
	return proof, nil
}

func (p *Pools) CheckRotationSnapshot(ctx context.Context, pool Pool) error {
	if e := p.inspectBound(ctx, pool); e != nil {
		return e
	}
	current, e := p.driver.inspect(ctx, pool.Name)
	if e != nil {
		return e
	}
	if !samePoolBinding(pool, current) || pool.WasStarted != current.WasStarted {
		return errors.New("windows pool: reviewed native state changed")
	}
	return nil
}

// ValidateStoppedPoolProof checks public state evidence without any native I/O.
func ValidateStoppedPoolProof(pool Pool, proof PoolRestartProof) error {
	return validateStoppedPool(pool, proof)
}
func ValidatePoolRestartProof(pool Pool, proof PoolRestartProof) error {
	return validatePoolRestart(pool, proof)
}
