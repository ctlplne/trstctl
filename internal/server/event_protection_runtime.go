// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"errors"
	"fmt"
	"path/filepath"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// eventProtectionRuntime owns one independent custodian for one opened source.
// Attach its options before events.Open recovery. Keep it until workers stop
// and the log closes; never replace the custodian of a running event log.
type eventProtectionRuntime struct {
	policy     eventprivacy.SourcePolicy
	admission  *eventprivacy.SourceAdmission
	reader     *eventprivacy.SourceKeys
	custody    *eventprotect.FileAuthority
	authority  *eventprivacy.DestructionAuthority
	probeSlots chan struct{}
}

func newEventProtectionRuntime(cfg *config.Config, st *store.Store, key *jose.SigningKey, extraBackupRoots ...string) (*eventProtectionRuntime, error) {
	if cfg == nil || st == nil || key == nil {
		return nil, errors.New("server: event protection requires source coordination and pinned audit evidence trust")
	}
	var roots []string
	var err error
	if cfg.Privacy.EventProtection.KeyDirectory != "" || cfg.Privacy.EventProtection.VerificationKeysFile != "" {
		roots, err = eventProtectionBackupRoots(cfg, extraBackupRoots...)
		if err != nil {
			return nil, err
		}
	}
	var verification *jose.JWKSet
	if cfg.Privacy.EventProtection.VerificationKeysFile != "" {
		verification, err = eventprotect.LoadVerificationKeysFile(cfg.Privacy.EventProtection.VerificationKeysFile, roots)
		if err != nil {
			return nil, fmt.Errorf("server: load independently pinned event evidence verification keys: %w", err)
		}
	}
	r := &eventProtectionRuntime{policy: eventprivacy.SourcePolicy{Trust: key.JWKS(), VerificationKeys: verification}, probeSlots: make(chan struct{}, 1)}
	r.admission = &eventprivacy.SourceAdmission{Guard: st, Policy: r.policy}
	r.reader = &eventprivacy.SourceKeys{Policy: r.policy}
	if cfg.Privacy.EventProtection.KeyDirectory != "" {
		r.authority = eventprivacy.NewDestructionAuthority()
		r.custody, err = eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: cfg.Privacy.EventProtection.KeyDirectory, BackupRoots: roots, Locker: st, EvidenceKey: key, VerificationKeys: verification, DestructionAuthority: r.authority})
		if err != nil {
			return nil, err
		}
		r.admission.Custody = r.custody
		r.reader.Custody = r.custody
	}
	return r, nil
}

func eventProtectionBackupRoots(cfg *config.Config, extra ...string) ([]string, error) {
	paths := []string{cfg.NATS.StoreDir, cfg.Postgres.DataDir, cfg.Signer.KeyStoreDir, cfg.Signer.AuthSecretFile, cfg.Audit.SigningKeyFile, cfg.Audit.ArchiveDir, cfg.Backup.Directory, cfg.CA.CertFile, cfg.Secrets.KEKFile}
	paths = append(paths, extra...)
	seen := map[string]bool{}
	var roots []string
	for _, path := range paths {
		if path == "" {
			continue
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		if !seen[absolute] {
			seen[absolute] = true
			roots = append(roots, absolute)
		}
	}
	if len(roots) == 0 {
		return nil, errors.New("server: event custody requires explicit ordinary backup boundaries")
	}
	return roots, nil
}

func (r *eventProtectionRuntime) openOptions() []events.OpenOption {
	return []events.OpenOption{
		func(log *events.Log) {
			r.policy.Log = log
			r.admission.Policy.Log = log
			r.reader.Policy.Log = log
			r.admission.Holds = eventprivacy.RetainedHoldPolicy{Policy: r.policy}
		},
		events.WithEventProtection(events.EventProtection{Admission: r.admission, Keys: r.reader}),
	}
}

func (r *eventProtectionRuntime) projectionOptions() []projections.Option {
	options := []projections.Option{projections.WithEventProtectionOffboardPolicy(&r.policy)}
	activation := &eventprivacy.ActivationVerifier{Policy: r.policy}
	completion := &eventprivacy.CompletionVerifier{Policy: r.policy}
	if r.custody != nil {
		activation.Custody = r.custody
		completion.Custody = r.custody
	}
	return append(options, projections.WithEventProtectionActivationVerifier(activation), projections.WithEventProtectionCompletionVerifier(completion))
}

func (r *eventProtectionRuntime) Close() error {
	if r == nil || r.custody == nil {
		return nil
	}
	return r.custody.Close()
}
