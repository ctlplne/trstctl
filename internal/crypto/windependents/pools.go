// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"trstctl.com/trstctl/internal/crypto/secret"
	"unicode/utf8"
)

type Pool struct {
	Name               string `json:"name"`
	AccountSID         string `json:"account_sid"`
	ConfigSHA256       string `json:"config_sha256"`
	EncryptionProvider string `json:"encryption_provider"`
	PasswordProtected  bool   `json:"password_protected"`
	WasStarted         bool   `json:"was_started"`
}
type PoolWorker struct {
	ProcessID  uint32 `json:"process_id"`
	AccountSID string `json:"account_sid"`
}
type PoolRestartProof struct {
	Name            string   `json:"name"`
	AccountSID      string   `json:"account_sid"`
	ConfigSHA256    string   `json:"config_sha256"`
	WasStarted      bool     `json:"was_started"`
	StoppedObserved bool     `json:"stopped_observed"`
	StartedObserved bool     `json:"started_observed"`
	PreviousPIDs    []uint32 `json:"previous_pids"`
}
type poolDriver interface {
	discover(context.Context, string) ([]Pool, error)
	inspect(context.Context, string) (Pool, error)
	update(context.Context, Pool, []byte) (Pool, error)
	restart(context.Context, Pool) (PoolRestartProof, error)
	workers(context.Context, string) ([]PoolWorker, error)
}
type Pools struct{ driver poolDriver }

func NewPools() *Pools { return &Pools{driver: newNativePoolDriver()} }
func validPoolName(value string) bool {
	if len(value) == 0 || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/\\<>:\"|?*") {
		return false
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func validatePool(pool Pool) error {
	hash, err := hex.DecodeString(pool.ConfigSHA256)
	if !validPoolName(pool.Name) || !validAccountSID(pool.AccountSID) || err != nil || len(hash) != 32 || pool.ConfigSHA256 != strings.ToLower(pool.ConfigSHA256) || len(pool.EncryptionProvider) == 0 || len(pool.EncryptionProvider) > 256 || !utf8.ValidString(pool.EncryptionProvider) || strings.ContainsAny(pool.EncryptionProvider, "\x00\r\n") {
		return errors.New("windows pool: invalid frozen native identity/configuration")
	}
	return nil
}
func samePoolBinding(left, right Pool) bool {
	return left.Name == right.Name && left.AccountSID == right.AccountSID && left.ConfigSHA256 == right.ConfigSHA256 && left.EncryptionProvider == right.EncryptionProvider
}
func (p *Pools) Discover(ctx context.Context, sid string) ([]Pool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validAccountSID(sid) {
		return nil, errors.New("windows pool: invalid selected account SID")
	}
	found, err := p.driver.discover(ctx, sid)
	if err != nil {
		return nil, err
	}
	if len(found) > 256 {
		return nil, errors.New("windows pool: selected dependent count exceeds bound")
	}
	seen := map[string]bool{}
	for _, pool := range found {
		key := strings.ToLower(pool.Name)
		if validatePool(pool) != nil || pool.AccountSID != sid || seen[key] {
			return nil, errors.New("windows pool: native discovery returned inconsistent authority")
		}
		seen[key] = true
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Name < found[j].Name })
	return found, nil
}
func (p *Pools) inspectBound(ctx context.Context, pool Pool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validatePool(pool); err != nil {
		return err
	}
	actual, err := p.driver.inspect(ctx, pool.Name)
	if err != nil {
		return err
	}
	if !samePoolBinding(pool, actual) {
		return errors.New("windows pool: native identity/configuration/provider changed")
	}
	return nil
}
func (p *Pools) UpdatePassword(ctx context.Context, pool Pool, password []byte) error {
	if err := validateServicePassword(password); err != nil {
		return err
	}
	if err := p.inspectBound(ctx, pool); err != nil {
		return err
	}
	held, err := secret.NewFrom(password)
	if err != nil {
		return err
	}
	defer held.Destroy()
	var readback Pool
	err = held.Use(func(value []byte) error {
		var updateErr error
		readback, updateErr = p.driver.update(ctx, pool, value)
		return updateErr
	})
	if err != nil {
		return err
	}
	if !samePoolBinding(pool, readback) || !readback.PasswordProtected {
		return errors.New("windows pool: native encrypted credential readback is unproven")
	}
	return nil
}
func validatePoolRestart(pool Pool, proof PoolRestartProof) error {
	if proof.Name != pool.Name || proof.AccountSID != pool.AccountSID || proof.ConfigSHA256 != pool.ConfigSHA256 || proof.WasStarted != pool.WasStarted || !proof.StoppedObserved || proof.StartedObserved != pool.WasStarted || len(proof.PreviousPIDs) > 128 {
		return errors.New("windows pool: native state-preserving restart is unproven")
	}
	seen := map[uint32]bool{}
	for _, pid := range proof.PreviousPIDs {
		if pid == 0 || seen[pid] {
			return errors.New("windows pool: invalid predecessor worker set")
		}
		seen[pid] = true
	}
	return nil
}
func (p *Pools) Restart(ctx context.Context, pool Pool) (PoolRestartProof, error) {
	if err := p.inspectBound(ctx, pool); err != nil {
		return PoolRestartProof{}, err
	}
	proof, err := p.driver.restart(ctx, pool)
	if err != nil {
		return PoolRestartProof{}, err
	}
	if err := validatePoolRestart(pool, proof); err != nil {
		return PoolRestartProof{}, err
	}
	return proof, nil
}

// VerifyWorkers is called after the independent functional probe warms a pool.
// Pool Started alone may have no worker and can never satisfy this identity proof.
func (p *Pools) VerifyWorkers(ctx context.Context, pool Pool, proof PoolRestartProof) ([]PoolWorker, error) {
	if err := validatePoolRestart(pool, proof); err != nil {
		return nil, err
	}
	if err := p.inspectBound(ctx, pool); err != nil {
		return nil, err
	}
	workers, err := p.driver.workers(ctx, pool.Name)
	if err != nil {
		return nil, err
	}
	if len(workers) > 128 || (pool.WasStarted && len(workers) == 0) || (!pool.WasStarted && len(workers) != 0) {
		return nil, errors.New("windows pool: fresh native worker set is unproven")
	}
	previous := map[uint32]bool{}
	for _, pid := range proof.PreviousPIDs {
		previous[pid] = true
	}
	seen := map[uint32]bool{}
	for _, worker := range workers {
		if worker.ProcessID == 0 || worker.AccountSID != pool.AccountSID || previous[worker.ProcessID] || seen[worker.ProcessID] {
			return nil, errors.New("windows pool: native worker is stale or has a different account")
		}
		seen[worker.ProcessID] = true
	}
	return workers, nil
}

// ValidatePoolSnapshot validates public frozen native authority.
func ValidatePoolSnapshot(pool Pool) error { return validatePool(pool) }
