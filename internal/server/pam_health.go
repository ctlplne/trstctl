// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"reflect"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A258: credential health. A brokered account is a PAM target whose provider
// holds a credential; once per interval, at a slot its name spreads over the
// interval, the worker signs in with that credential and changes nothing. A
// sign-in the server judged and refused (rejected, expired, locked) is never
// repeated with the same credential: until the stored credential changes, or
// an operator checks the account now, it reads failing and is not tried
// again, so no check counts toward a lockout twice. A check that never
// reached a sign-in exchange (dial, TLS, a timeout) is retried twice in its
// slot. Checks run one at a time, at most pamHealthBatch per pass.

const (
	pamHealthBatch        = 32
	pamHealthCheckTimeout = 15 * time.Second
	pamHealthRetries      = 2
	// pamHealthCheckNowSpacing bounds an operator's checks of one account.
	pamHealthCheckNowSpacing = time.Minute
	pamHealthNotSupported    = "not_supported"
)

// pamHealthAccount names a brokered account.
type pamHealthAccount struct {
	tenantID, targetType, targetID, providerID string
}

type pamHealthState struct {
	next time.Time
	// checking is set while a check of the account runs outside the lock.
	checking bool
	// judged is the keyed digest of the credential the server last judged
	// and refused; nil when the last check did not judge it.
	judged *[32]byte
	// primed marks an account whose recorded status was judged before this
	// process started: its current credential is taken as the judged one.
	primed bool
	status string
}

// pamCredentialChecker is a provider that can sign in with its stored
// credential (configuredDynamicProvider; test providers may implement it).
type pamCredentialChecker interface {
	DynamicSecretCredentialDigest(ctx context.Context, key []byte) ([32]byte, error)
	DynamicSecretCheckSignIn(ctx context.Context) string
}

// pamHealth is the worker's state: the per-account schedule and judged
// digests, and the process-local key the digests are made with.
type pamHealth struct {
	mu     sync.Mutex
	key    []byte
	states map[pamHealthAccount]*pamHealthState
	primed bool
}

func newPAMHealth() (*pamHealth, error) {
	key, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	return &pamHealth{key: key, states: map[pamHealthAccount]*pamHealthState{}}, nil
}

// pamHealthSlot is the account's first check time after after: the
// interval's grid shifted by an offset its name fixes, so checks spread over
// the interval and stay on the same slots across restarts.
func pamHealthSlot(a pamHealthAccount, after time.Time, interval time.Duration) time.Time {
	h := fnv.New64a()
	_, _ = h.Write([]byte(a.tenantID + "/" + a.targetType + "/" + a.targetID))
	offset := time.Duration(h.Sum64() % uint64(interval)) // #nosec G115 -- a positive interval in nanoseconds, never negative (CWE-190)
	slot := after.Truncate(interval).Add(offset)
	for !slot.After(after) {
		slot = slot.Add(interval)
	}
	return slot
}

// RunPAMAccountHealth runs the credential health worker until ctx ends.
func (s *Server) RunPAMAccountHealth(ctx context.Context) {
	if s.pam == nil {
		<-ctx.Done()
		return
	}
	s.pam.RunAccountHealth(ctx)
}

// RunAccountHealth checks every brokered account once per interval.
func (s *pamService) RunAccountHealth(ctx context.Context) {
	tick := min(time.Second, s.healthInterval/4)
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.healthPass(ctx)
	}
}

// healthAccounts lists the brokered accounts: the deployment's own database
// targets and every tenant's enabled registered ones.
func (s *pamService) healthAccounts(ctx context.Context) ([]pamHealthAccount, error) {
	seen := map[pamHealthAccount]bool{}
	var out []pamHealthAccount
	for key, target := range s.databases {
		a := pamHealthAccount{key.tenantID, key.targetType, key.id, target.cfg.ProviderID}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	registered, err := s.store.ListEnabledProviderPAMTargets(ctx)
	if err != nil {
		return nil, err
	}
	for _, rec := range registered {
		if !isPAMDatabaseType(rec.TargetType) {
			continue
		}
		a := pamHealthAccount{rec.TenantID, rec.TargetType, rec.ID, rec.ProviderID}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out, nil
}

func (s *pamService) healthPass(ctx context.Context) {
	if s.health == nil {
		return
	}
	accounts, err := s.healthAccounts(ctx)
	if err != nil {
		return
	}
	s.health.mu.Lock()
	if !s.health.primed {
		if err := s.primeHealth(ctx, accounts); err != nil {
			s.health.mu.Unlock()
			return
		}
		s.health.primed = true
	}
	now := s.clock()
	live := map[pamHealthAccount]bool{}
	var due []pamHealthAccount
	for _, a := range accounts {
		live[a] = true
		st := s.health.states[a]
		if st == nil {
			st = &pamHealthState{next: pamHealthSlot(a, now, s.healthInterval)}
			s.health.states[a] = st
		}
		if now.Before(st.next) || st.checking || len(due) == pamHealthBatch {
			continue
		}
		st.next = pamHealthSlot(a, now, s.healthInterval)
		due = append(due, a)
	}
	for a := range s.health.states {
		if !live[a] {
			delete(s.health.states, a)
		}
	}
	s.health.mu.Unlock()
	for _, a := range due {
		if ctx.Err() != nil {
			return
		}
		s.checkAccount(ctx, a, false)
	}
}

// primeHealth marks the accounts whose recorded status was judged before this
// process started: their current credential is taken as the one the server
// refused, so a restart never adds a sign-in with it.
func (s *pamService) primeHealth(ctx context.Context, accounts []pamHealthAccount) error {
	tenants := map[string]bool{}
	for _, a := range accounts {
		tenants[a.tenantID] = true
	}
	for tenantID := range tenants {
		recorded, err := s.store.ListPAMAccountHealth(ctx, tenantID)
		if err != nil {
			return err
		}
		for _, a := range accounts {
			if a.tenantID != tenantID {
				continue
			}
			if h, ok := recorded[[2]string{a.targetType, a.targetID}]; ok && dynsecret.SignInJudged(h.Status) {
				s.health.states[a] = &pamHealthState{next: pamHealthSlot(a, s.clock(), s.healthInterval), primed: true, status: h.Status}
			}
		}
	}
	return nil
}

func (s *pamService) healthChecker(a pamHealthAccount) pamCredentialChecker {
	for _, provider := range s.providers.ForTenant(a.tenantID) {
		if provider != nil && provider.Name() == a.providerID {
			checker, _ := provider.(pamCredentialChecker)
			return checker
		}
	}
	return nil
}

// checkAccount signs in once (retrying only when no sign-in exchange took
// place) unless the credential is the one the server already refused; now
// is an operator's check, which signs in regardless. The sign-in runs outside
// the lock; the account is marked so no second check of it starts meanwhile.
// It records the outcome and reports whether it signed in.
func (s *pamService) checkAccount(ctx context.Context, a pamHealthAccount, now bool) bool {
	s.health.mu.Lock()
	st := s.health.states[a]
	if st == nil {
		st = &pamHealthState{next: pamHealthSlot(a, s.clock(), s.healthInterval)}
		s.health.states[a] = st
	}
	if st.checking {
		s.health.mu.Unlock()
		return false
	}
	st.checking = true
	judged, primed, previous := st.judged, st.primed, st.status
	s.health.mu.Unlock()

	status, attempts, digest, signedIn := s.signIn(ctx, a, judged, primed, now)

	s.health.mu.Lock()
	defer s.health.mu.Unlock()
	st.checking = false
	if primed && digest != nil {
		st.primed, st.judged = false, digest
	}
	if !signedIn {
		if status == pamHealthNotSupported && previous != pamHealthNotSupported {
			st.status = status
			_ = s.recordHealth(ctx, a, status, 0)
		}
		return false
	}
	if dynsecret.SignInJudged(status) {
		st.judged = digest
	} else {
		st.judged = nil
	}
	st.status = status
	_ = s.recordHealth(ctx, a, status, attempts)
	return true
}

// signIn is one account's check outside the lock: the credential's digest,
// then — unless it is the judged one, or a primed account's — the sign-in.
func (s *pamService) signIn(ctx context.Context, a pamHealthAccount, judged *[32]byte, primed, now bool) (string, int, *[32]byte, bool) {
	checker := s.healthChecker(a)
	if checker == nil {
		return pamHealthNotSupported, 0, nil, false
	}
	dctx, cancel := context.WithTimeout(ctx, pamHealthCheckTimeout)
	digest, err := checker.DynamicSecretCredentialDigest(dctx, s.health.key)
	cancel()
	if err != nil {
		return "", 0, nil, false
	}
	if !now && (primed || (judged != nil && *judged == digest)) {
		return "", 0, &digest, false // refused before and unchanged: not tried again
	}
	status, attempts := dynsecret.SignInError, 0
	for try := 0; try <= pamHealthRetries; try++ {
		cctx, cancel := context.WithTimeout(ctx, pamHealthCheckTimeout)
		status = checker.DynamicSecretCheckSignIn(cctx)
		cancel()
		if status == pamHealthNotSupported {
			return status, 0, &digest, false
		}
		attempts++
		if status != dynsecret.SignInUnreachable {
			break
		}
		select {
		case <-ctx.Done():
			return "", attempts, &digest, false
		case <-time.After(time.Duration(try+1) * time.Second):
		}
	}
	return status, attempts, &digest, true
}

func (s *pamService) recordHealth(ctx context.Context, a pamHealthAccount, status string, attempts int) error {
	return s.appendProject(ctx, a.tenantID, projections.EventPAMAccountHealthChecked, projections.PAMAccountHealthChecked{
		TargetType: a.targetType, TargetID: a.targetID, ProviderID: a.providerID, Status: status, Attempts: attempts,
		CheckedAt: s.clock().UTC(),
	})
}

// CheckPAMAccountHealth is the served broker's check of one account now.
func (s *Server) CheckPAMAccountHealth(ctx context.Context, tenantID, targetType, id string) (api.PAMTarget, error) {
	if s.pam == nil {
		return api.PAMTarget{}, api.ErrPAMUnavailable
	}
	return s.pam.CheckPAMAccountHealth(ctx, tenantID, targetType, id)
}

// CheckPAMAccountHealth is an operator's check of one account now (A258):
// it signs in once even with a credential the server refused before — the
// operator asserts the account was repaired — at most once a minute.
func (s *pamService) CheckPAMAccountHealth(ctx context.Context, tenantID, targetType, id string) (api.PAMTarget, error) {
	if s.health == nil {
		return api.PAMTarget{}, api.ErrPAMUnavailable
	}
	if !isPAMDatabaseType(targetType) {
		return api.PAMTarget{}, fmt.Errorf("%w: only a provider-backed target has a stored credential to check", api.ErrPAMInvalid)
	}
	target, err := s.databaseTarget(ctx, tenantID, targetType, id)
	if err != nil {
		return api.PAMTarget{}, err
	}
	a := pamHealthAccount{tenantID, targetType, strings.TrimSpace(id), target.cfg.ProviderID}
	recorded, err := s.store.ListPAMAccountHealth(ctx, tenantID)
	if err != nil {
		return api.PAMTarget{}, err
	}
	if h, ok := recorded[[2]string{a.targetType, a.targetID}]; ok && s.clock().Sub(h.CheckedAt) < pamHealthCheckNowSpacing {
		return api.PAMTarget{}, fmt.Errorf("%w: the account was checked less than a minute ago", api.ErrPAMRejected)
	}
	if !s.checkAccount(ctx, a, true) {
		return api.PAMTarget{}, fmt.Errorf("%w: the account's credential could not be checked now", api.ErrPAMRejected)
	}
	return s.GetPAMTarget(ctx, tenantID, targetType, id)
}

// healthView is a target's recorded credential health for reads.
func healthView(h store.PAMAccountHealth) *api.PAMAccountHealth {
	return &api.PAMAccountHealth{Status: h.Status, Attempts: h.Attempts, CheckedAt: h.CheckedAt.UTC(), FailingSince: h.FailingSince,
		NotRetried: dynsecret.SignInJudged(h.Status)}
}

// providerCredentialRefs are every reference to a credential a provider's
// configuration names; a change to any of them changes its digest.
func providerCredentialRefs(cfg config.DynamicSecretProviderConfig) []string {
	v := reflect.ValueOf(cfg)
	var refs []string
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		if field.Type.Kind() == reflect.String && strings.HasSuffix(field.Name, "Ref") {
			refs = append(refs, field.Name+"="+v.Field(i).String())
		}
	}
	return refs
}

// DynamicSecretCredentialDigest is a keyed digest of every credential the
// provider's configuration references, read now; the key is the process's
// own, so the digest means nothing outside it.
func (p *configuredDynamicProvider) DynamicSecretCredentialDigest(ctx context.Context, key []byte) ([32]byte, error) {
	var material []byte
	defer func() { secret.Wipe(material) }()
	for _, ref := range providerCredentialRefs(p.cfg) {
		name, value, _ := strings.Cut(ref, "=")
		if strings.TrimSpace(value) == "" {
			continue
		}
		buf, err := p.credentials.resolve(ctx, p.tenantID, value)
		if err != nil {
			return [32]byte{}, err
		}
		err = buf.Use(func(b []byte) error {
			material = append(material, name...)
			material = binary.BigEndian.AppendUint64(material, uint64(len(b)))
			material = append(material, b...)
			return nil
		})
		buf.Destroy()
		if err != nil {
			return [32]byte{}, err
		}
	}
	var out [32]byte
	copy(out[:], crypto.HMACSHA256(key, material))
	return out, nil
}

// DynamicSecretCheckSignIn opens the provider's backend with its credentials
// read now and signs in once, changing nothing. Opening a MySQL or MongoDB
// backend is itself the sign-in.
func (p *configuredDynamicProvider) DynamicSecretCheckSignIn(ctx context.Context) string {
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return dynsecret.SignInStatusOf(err)
	}
	defer closeBackend()
	checker, ok := backend.(dynsecret.SignInChecker)
	if !ok {
		return pamHealthNotSupported
	}
	return dynsecret.SignInStatusOf(checker.CheckSignIn(ctx))
}
