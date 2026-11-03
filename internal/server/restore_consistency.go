// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/historycontinuity"
	"trstctl.com/trstctl/internal/secrets"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// What a restore drill proves beyond health (A246): the restored state is the
// backup's, read back through the restored keys. Events are compared with the
// backup record for record, each CA key the deployment relies on is checked
// against the certificate that names it, and every stored secret value is
// opened. A failure is a backup.RestoreInconsistency naming the check.

// verifyRestoredConsistency runs the event check and then the key and secret
// checks against an isolated target, before anything else writes to it.
func verifyRestoredConsistency(
	ctx context.Context,
	cfg *config.Config,
	dir string,
	st *store.Store,
	log *events.Log,
	signer SignerProvider,
	auditKey *jose.SigningKey,
	result *fullRestoreResult,
) error {
	n, err := verifyRestoredEvents(ctx, cfg, log, filepath.Join(dir, "events.jsonl"), auditKey)
	if err != nil {
		return &backup.RestoreInconsistency{Check: backup.ConsistencyEvents, Err: err}
	}
	result.EventsVerified = n
	client := signer.Client()
	n, err = verifyRestoredKeys(ctx, cfg.CA.CertFile, st, func(ctx context.Context, handle string) (crypto.PublicKey, error) {
		remote, err := client.SignerForHandle(ctx, handle)
		if err != nil {
			return crypto.PublicKey{}, err
		}
		return remote.Public(), nil
	})
	if err != nil {
		return &backup.RestoreInconsistency{Check: backup.ConsistencyKeys, Err: err}
	}
	result.KeysVerified = n
	n, sealed, err := verifyRestoredSecrets(ctx, cfg, st, signer)
	if err != nil {
		return &backup.RestoreInconsistency{Check: backup.ConsistencySecrets, Err: err}
	}
	result.SecretsVerified, result.SealedTenantsNotOpened = n, sealed
	return nil
}

// verifyRestoredEvents re-reads the backup's event log and compares the
// restored log with it record for record.
func verifyRestoredEvents(ctx context.Context, cfg *config.Config, log *events.Log, path string, auditKey *jose.SigningKey) (int, error) {
	key, err := backupIntegrityKey(cfg)
	if err != nil {
		return 0, err
	}
	defer secret.Wipe(key)
	f, err := os.Open(path) // #nosec G304 -- the restored backup set's own event log, under the isolated target (CWE-22)
	if err != nil {
		return 0, fmt.Errorf("open the backup's event log: %w", err)
	}
	defer func() { _ = f.Close() }()
	return verifyLogMatchesBackup(ctx, cfg, log, f, key, auditKey)
}

// verifyLogMatchesBackup compares a populated log with a backup stream without
// appending anything. A log whose legacy scheduler history was sanitized on
// restore matches through its signed rewrite receipts.
func verifyLogMatchesBackup(ctx context.Context, cfg *config.Config, log *events.Log, f *os.File, key []byte, auditKey *jose.SigningKey) (int, error) {
	n, err := backup.VerifyLogMatchesWithKey(ctx, log, f, key)
	if err == nil || !cfg.Secrets.SecretRotationHistoryFleetReady {
		return n, err
	}
	if _, seekErr := f.Seek(0, 0); seekErr != nil {
		return n, fmt.Errorf("rewind backup file for scheduler sanitation verification: %w", seekErr)
	}
	return backup.VerifyLogMatchesSanitizedSchedulerHistoryWithKey(ctx, log, f, key,
		func(_ context.Context, receipt events.Event) (events.TenantDataRewriteReport, error) {
			return historycontinuity.VerifyReceipt(auditKey, receipt)
		})
}

// verifyRestoredKeys checks the issuing CA in the restored certificate file and
// every active tenant CA authority with a signer handle: the key the restored
// signer holds under the handle must be the key the certificate certifies.
// Nothing is signed.
func verifyRestoredKeys(ctx context.Context, caCertFile string, st *store.Store, publicKey func(context.Context, string) (crypto.PublicKey, error)) (int, error) {
	n := 0
	check := func(label, handle string, certPEM []byte) error {
		blk, _ := pem.Decode(certPEM)
		if blk == nil || blk.Type != "CERTIFICATE" {
			return fmt.Errorf("%s: its certificate is not PEM", label)
		}
		public, err := publicKey(ctx, handle)
		if err != nil {
			return fmt.Errorf("%s: the restored signer does not hold handle %q: %w", label, handle, err)
		}
		if err := crypto.VerifyCertificateSigner(blk.Bytes, public); err != nil {
			return fmt.Errorf("%s: the restored signer's key under %q is not the key its certificate certifies: %w", label, handle, err)
		}
		n++
		return nil
	}
	if caCertFile != "" {
		certPEM, err := os.ReadFile(caCertFile) // #nosec G304 -- the restored issuing CA certificate under the isolated target (CWE-22)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return n, fmt.Errorf("read the restored issuing CA certificate: %w", err)
		}
		if err == nil {
			if err := check("the issuing CA", issuingCAHandle, certPEM); err != nil {
				return n, err
			}
		}
	}
	tenants, err := st.ListTenants(ctx)
	if err != nil {
		return n, err
	}
	for _, t := range tenants {
		authorities, err := st.ListCAAuthorities(ctx, t.TenantID)
		if err != nil {
			return n, err
		}
		for _, a := range authorities {
			// A superseded or revoked authority's key may have been destroyed
			// on purpose; only the keys in use must be there.
			if a.Status != "active" || a.SignerHandle == "" {
				continue
			}
			if err := check(fmt.Sprintf("tenant %s CA %s", t.TenantID, a.ID), a.SignerHandle, []byte(a.CertificatePEM)); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

// verifyRestoredSecrets opens every stored application-secret value of every
// tenant, current and retained, under the restored deployment KEK and tenant
// key domains, composed as the server composes them, with the binding the
// secret store seals under. Each plaintext is wiped as soon as it opens. A
// tenant that sealed its key domain (or is sealing or unsealing it) cannot be
// opened by design; it is counted, not failed.
func verifyRestoredSecrets(ctx context.Context, cfg *config.Config, st *store.Store, signer SignerProvider) (opened, sealedTenants int, err error) {
	if _, err := os.Stat(cfg.Secrets.KEKFile); err != nil {
		return 0, 0, fmt.Errorf("the restored deployment KEK is not readable: %w", err)
	}
	kek, err := secrets.LoadOrCreateKEK(cfg.Secrets.KEKFile)
	if err != nil {
		return 0, 0, err
	}
	defer kek.Destroy()
	_, _, _, access, _, err := idempotencyResultProtectionFromConfig(cfg.Secrets, st, kek, signer)
	if err != nil {
		return 0, 0, err
	}
	tenants, err := st.ListTenants(ctx)
	if err != nil {
		return 0, 0, err
	}
	for _, t := range tenants {
		tenantID := t.TenantID
		err := access.WithTenant(ctx, tenantID, func(cipher tenantseal.Cipher) error {
			return st.EachStoredSecretValue(ctx, tenantID, func(name string, version int, sealed []byte) error {
				plain, err := cipher.Open(sealed, []byte(tenantID+"/secret-store/"+name))
				secret.Wipe(plain)
				if err != nil {
					return fmt.Errorf("tenant %s secret %q version %d does not open under the restored keys: %w", tenantID, name, version, err)
				}
				opened++
				return nil
			})
		})
		if status, ok := tenantseal.StatusOf(err); ok {
			switch status {
			case tenantseal.StatusSealed, tenantseal.StatusSealing, tenantseal.StatusUnsealing:
				sealedTenants++
				continue
			}
		}
		if err != nil {
			return opened, sealedTenants, err
		}
	}
	return opened, sealedTenants, nil
}
