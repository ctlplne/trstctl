// SPDX-License-Identifier: BUSL-1.1
// Package windependents performs narrowly bound native Windows credential
// maintenance. Only public account and configuration metadata leave the package.
package windependents

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"
	"trstctl.com/trstctl/internal/crypto/secret"
	"unicode/utf8"
)

// Service is a discovered native object. Its private command line contributes
// to ConfigSHA256 inside the crypto boundary; it is never returned as metadata.
type Service struct {
	Name         string   `json:"name"`
	AccountSID   string   `json:"account_sid"`
	ConfigSHA256 string   `json:"config_sha256"`
	Dependencies []string `json:"dependencies,omitempty"`
	WasRunning   bool     `json:"was_running"`
}

// Runtime proves the native process identity only. A separate configured
// functional probe must prove the service did useful work before completion.
type Runtime struct {
	Running    bool   `json:"running"`
	ProcessID  uint32 `json:"process_id,omitempty"`
	AccountSID string `json:"account_sid,omitempty"`
}

type serviceDriver interface {
	discover(context.Context, string) ([]Service, error)
	inspect(context.Context, string) (Service, error)
	update(context.Context, Service, []byte) error
	restart(context.Context, Service) (Runtime, error)
}
type Services struct{ driver serviceDriver }

func NewServices() *Services { return &Services{driver: newNativeServiceDriver()} }
func validServiceName(name string) bool {
	if len(name) == 0 || len(name) > 256 || !utf8.ValidString(name) || strings.ContainsAny(name, "/\\") {
		return false
	}
	for _, r := range name {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func validAccountSID(sid string) bool {
	if len(sid) > 184 {
		return false
	}
	parts := strings.Split(sid, "-")
	if len(parts) != 8 || parts[0] != "S" || parts[1] != "1" || parts[2] != "5" || parts[3] != "21" {
		return false
	}
	for i := 4; i < len(parts); i++ {
		v, err := strconv.ParseUint(parts[i], 10, 32)
		if err != nil || strconv.FormatUint(v, 10) != parts[i] || (i == 7 && v == 0) {
			return false
		}
	}
	return true
}
func validateService(target Service) error {
	hash, err := hex.DecodeString(target.ConfigSHA256)
	if !validServiceName(target.Name) || !validAccountSID(target.AccountSID) || err != nil || len(hash) != 32 || target.ConfigSHA256 != strings.ToLower(target.ConfigSHA256) || len(target.Dependencies) > 128 {
		return errors.New("windows service: invalid frozen native authority")
	}
	seen := map[string]bool{}
	for _, name := range target.Dependencies {
		key := strings.ToLower(name)
		if !validServiceName(name) || seen[key] {
			return errors.New("windows service: invalid native dependencies")
		}
		seen[key] = true
	}
	return nil
}
func validateServicePassword(password []byte) error {
	if len(password) < 16 || len(password) > 1024 || !utf8.Valid(password) {
		return errors.New("windows service: invalid bounded credential")
	}
	for _, b := range password {
		if b == 0 {
			return errors.New("windows service: NUL in credential")
		}
	}
	return nil
}
func sameServiceBinding(expected, current Service) bool {
	return expected.Name == current.Name && expected.AccountSID == current.AccountSID && expected.ConfigSHA256 == current.ConfigSHA256 && slices.Equal(expected.Dependencies, current.Dependencies)
}
func (s *Services) Discover(ctx context.Context, accountSID string) ([]Service, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validAccountSID(accountSID) {
		return nil, errors.New("windows service: invalid managed account SID")
	}
	found, err := s.driver.discover(ctx, accountSID)
	if err != nil {
		return nil, err
	}
	if len(found) > 256 {
		return nil, errors.New("windows service: dependent count exceeds bound")
	}
	seen := map[string]bool{}
	for _, target := range found {
		key := strings.ToLower(target.Name)
		if validateService(target) != nil || target.AccountSID != accountSID || seen[key] {
			return nil, errors.New("windows service: discovery returned inconsistent native authority")
		}
		seen[key] = true
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Name < found[j].Name })
	return found, nil
}
func (s *Services) inspectBound(ctx context.Context, target Service) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateService(target); err != nil {
		return err
	}
	current, err := s.driver.inspect(ctx, target.Name)
	if err != nil {
		return err
	}
	if !sameServiceBinding(target, current) {
		return errors.New("windows service: native account or configuration changed")
	}
	return nil
}
func (s *Services) UpdatePassword(ctx context.Context, target Service, password []byte) error {
	if err := validateServicePassword(password); err != nil {
		return err
	}
	if err := s.inspectBound(ctx, target); err != nil {
		return err
	}
	held, err := secret.NewFrom(password)
	if err != nil {
		return err
	}
	defer held.Destroy()
	return held.Use(func(value []byte) error { return s.driver.update(ctx, target, value) })
}
func (s *Services) RestartAndVerifyIdentity(ctx context.Context, target Service) (Runtime, error) {
	if err := s.inspectBound(ctx, target); err != nil {
		return Runtime{}, err
	}
	observed, err := s.driver.restart(ctx, target)
	if err != nil {
		return Runtime{}, err
	}
	if target.WasRunning {
		if !observed.Running || observed.ProcessID == 0 || observed.AccountSID != target.AccountSID {
			return Runtime{}, errors.New("windows service: fresh native process identity was not verified")
		}
	} else if observed.Running {
		return Runtime{}, errors.New("windows service: stopped dependent was unexpectedly started")
	}
	return observed, nil
}

// ValidateServiceSnapshot validates public frozen native authority.
func ValidateServiceSnapshot(target Service) error { return validateService(target) }

// ValidAccountSID checks the canonical native domain/local SAM account SID.
func ValidAccountSID(sid string) bool { return validAccountSID(sid) }
