// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/objectstore"
)

// UploadFullBackupSet copies the finished full backup set in dir to the
// configured object store as backups/<directory name>/, the manifest last
// (trstctl --full-backup-upload DIR). Sensitive artifacts are already
// encrypted in the set; the upload moves the set's bytes unchanged.
func UploadFullBackupSet(ctx context.Context, cfg *config.Config, dir string) (backup.ObjectSet, error) {
	store, err := backupObjectStore(cfg)
	if err != nil {
		return backup.ObjectSet{}, err
	}
	defer store.Destroy()
	return backup.UploadFullBackup(ctx, store, dir)
}

// FetchFullBackupSet downloads the set name from the configured object store
// into dir, a new or empty directory, and re-hashes every artifact against the
// set's manifest (trstctl --full-backup-download NAME). Restoring the fetched
// set is a separate --full-restore-dir step.
func FetchFullBackupSet(ctx context.Context, cfg *config.Config, name, dir string) (backup.VerifyReport, error) {
	store, err := backupObjectStore(cfg)
	if err != nil {
		return backup.VerifyReport{}, err
	}
	defer store.Destroy()
	return backup.DownloadFullBackup(ctx, store, name, dir)
}

func backupObjectStore(cfg *config.Config) (*objectstore.S3, error) {
	if !cfg.ObjectStore.Configured() {
		return nil, errors.New("no object store is configured (object_store or TRSTCTL_OBJECT_STORE_*)")
	}
	return objectstore.FromConfig(cfg.ObjectStore)
}
