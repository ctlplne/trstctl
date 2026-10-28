// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/reportarchive"
	"trstctl.com/trstctl/internal/store"
)

// A206: the signed reports completed compliance runs recorded live outside the
// replay log, under audit.archive_dir or in the archive object store, so a
// log-and-database backup could not bring them back. The full backup copies
// every completed run's report into one encrypted artifact with an index; a
// full restore puts each back where its run's reference says, and the restore
// drill restores them into its isolated target and reads each back against its
// digest.

const reportArchiveArtifactName = "report-archive"

// reportArchiveIndex lists what the artifact holds.
type reportArchiveIndex struct {
	Version int                  `json:"version"`
	Reports []reportArchiveEntry `json:"reports"`
}

type reportArchiveEntry struct {
	TenantID string `json:"tenant_id"`
	RunID    string `json:"run_id"`
	Ref      string `json:"ref"`
	Digest   string `json:"digest"`
	// Missing says why a run's report was not in the archive when the backup
	// ran; the backup records it rather than failing every later backup.
	Missing string `json:"missing,omitempty"`
}

func (e reportArchiveEntry) file(root string) string {
	return filepath.Join(root, e.TenantID, e.RunID, e.Digest+".json")
}

// reportArchiveFromConfig is the archive a backup reads from or a restore
// writes to.
func reportArchiveFromConfig(cfg *config.Config) (reportarchive.Archive, func(), error) {
	archive := reportarchive.Archive{Dir: reportarchive.Dir{Root: cfg.Audit.ArchiveDir}}
	objects, err := openArchiveObjectStore(cfg)
	if err != nil {
		return reportarchive.Archive{}, func() {}, err
	}
	if objects == nil {
		return archive, func() {}, nil
	}
	archive.Objects = objects
	return archive, objects.Destroy, nil
}

// restoreFullBackupReportsFor opens the restore target's archive: its own
// directory only for the isolated drill, which never reaches the object store.
func restoreFullBackupReportsFor(ctx context.Context, cfg *config.Config, manifest backup.FullManifest, dir string, encryptionKey []byte, isolated bool) (reportRestoreResult, error) {
	if isolated {
		archive := reportarchive.Archive{Dir: reportarchive.Dir{Root: cfg.Audit.ArchiveDir}}
		return restoreFullBackupReports(ctx, manifest, dir, archive, encryptionKey, true)
	}
	archive, closeArchive, err := reportArchiveFromConfig(cfg)
	if err != nil {
		return reportRestoreResult{}, err
	}
	defer closeArchive()
	return restoreFullBackupReports(ctx, manifest, dir, archive, encryptionKey, false)
}

// captureFullBackupReports copies every completed run's report into the
// backup. It reads each through the archive, so a report in the object store
// is captured like one on disk, and checks it against the run's digest.
func captureFullBackupReports(ctx context.Context, st *store.Store, archive reportarchive.Archive, dir string, enc *fullBackupEncryption) (backup.Artifact, error) {
	none := backup.Artifact{Name: reportArchiveArtifactName, Role: reportArchiveArtifactName, Sensitive: true}
	tenants, err := st.TenantsWithCompletedComplianceReports(ctx)
	if err != nil {
		return none, fmt.Errorf("backup: list tenants with compliance reports: %w", err)
	}
	if len(tenants) == 0 {
		return none, nil
	}
	staging, err := os.MkdirTemp("", "trstctl-report-archive-")
	if err != nil {
		return none, fmt.Errorf("backup: stage report archive: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()
	index := reportArchiveIndex{Version: 1}
	for _, tenantID := range tenants {
		runs, err := st.ListCompletedComplianceReportArtifacts(ctx, tenantID)
		if err != nil {
			return none, fmt.Errorf("backup: list compliance reports: %w", err)
		}
		for _, run := range runs {
			entry := reportArchiveEntry{TenantID: tenantID, RunID: run.RunID, Ref: run.ArtifactRef, Digest: run.ArtifactDigest}
			data, readErr := archive.Read(ctx, run.ArtifactRef, tenantID, run.RunID, run.ArtifactDigest)
			if readErr != nil {
				entry.Missing = "the report could not be read from the archive when this backup ran"
				index.Reports = append(index.Reports, entry)
				continue
			}
			path := entry.file(staging)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return none, fmt.Errorf("backup: stage report: %w", err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil { // #nosec G703 -- the staging tree is this backup's own temp directory (CWE-22)
				return none, fmt.Errorf("backup: stage report: %w", err)
			}
			index.Reports = append(index.Reports, entry)
		}
	}
	raw, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return none, err
	}
	if err := os.WriteFile(filepath.Join(staging, "index.json"), raw, 0o600); err != nil {
		return none, fmt.Errorf("backup: write report index: %w", err)
	}
	artifact, err := dirArtifact(reportArchiveArtifactName, reportArchiveArtifactName, staging,
		filepath.Join(dir, "files", reportArchiveArtifactName), true, true, true, dir, enc)
	if err != nil {
		return none, err
	}
	// The source was a staging copy; name where the reports live instead.
	artifact.SourcePath = "compliance report archive"
	return artifact, nil
}

// reportRestoreResult counts what a restore put back.
type reportRestoreResult struct {
	Restored        int
	MissingAtBackup int
}

// restoreFullBackupReports puts the backup's reports back. A full restore
// writes each where its run's reference says (audit.archive_dir or the object
// store); the isolated drill writes every one into its own target directory.
// Either way each report is read back and checked against its digest.
func restoreFullBackupReports(ctx context.Context, manifest backup.FullManifest, dir string, archive reportarchive.Archive, encryptionKey []byte, isolated bool) (reportRestoreResult, error) {
	var out reportRestoreResult
	artifact, ok := manifestArtifact(manifest, reportArchiveArtifactName)
	if !ok || !artifact.Captured {
		return out, nil
	}
	staging, err := os.MkdirTemp("", "trstctl-report-restore-")
	if err != nil {
		return out, fmt.Errorf("restore: stage report archive: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()
	tree := filepath.Join(staging, "reports")
	if err := restoreDirArtifact(manifest, reportArchiveArtifactName, dir, filepath.Join(dir, "files", reportArchiveArtifactName), tree, encryptionKey); err != nil {
		return out, fmt.Errorf("restore report archive: %w", err)
	}
	raw, err := os.ReadFile(filepath.Join(tree, "index.json")) // #nosec G304 -- the restore's own staging tree (CWE-22)
	if err != nil {
		return out, fmt.Errorf("restore: read report index: %w", err)
	}
	var index reportArchiveIndex
	if err := json.Unmarshal(raw, &index); err != nil || index.Version != 1 {
		return out, fmt.Errorf("restore: the report index is not a version 1 index: %v", err)
	}
	for _, entry := range index.Reports {
		if entry.Missing != "" {
			out.MissingAtBackup++
			continue
		}
		if !reportarchive.ValidReference(entry.Ref, entry.TenantID, entry.RunID, entry.Digest) {
			return out, fmt.Errorf("restore: report index entry for run %s has an invalid reference", entry.RunID)
		}
		data, err := os.ReadFile(entry.file(tree)) // #nosec G304 -- the restore's own staging tree; names validated above (CWE-22)
		if err != nil {
			return out, fmt.Errorf("restore: the backup lists run %s's report and does not hold it: %w", entry.RunID, err)
		}
		if crypto.SHA256Hex(data) != entry.Digest {
			return out, fmt.Errorf("restore: run %s's report does not match its digest", entry.RunID)
		}
		ref, err := putRestoredReport(ctx, archive, entry, data, isolated)
		if err != nil {
			return out, err
		}
		if _, err := archive.Read(ctx, ref, entry.TenantID, entry.RunID, entry.Digest); err != nil {
			return out, fmt.Errorf("restore: run %s's report does not read back: %w", entry.RunID, err)
		}
		out.Restored++
	}
	return out, nil
}

// putRestoredReport writes one report where it belongs and returns the
// reference it now has.
func putRestoredReport(ctx context.Context, archive reportarchive.Archive, entry reportArchiveEntry, data []byte, isolated bool) (string, error) {
	inDir := isolated || reportarchive.IsDirectoryReference(entry.Ref)
	if inDir {
		if archive.Dir.Root == "" {
			return "", fmt.Errorf("restore: the backup holds compliance reports and audit.archive_dir is not configured")
		}
		if err := os.MkdirAll(archive.Dir.Root, 0o700); err != nil {
			return "", fmt.Errorf("restore: create the report archive: %w", err)
		}
		ref, _, err := archive.Dir.Put(entry.TenantID, entry.RunID, data)
		if err != nil {
			return "", fmt.Errorf("restore: run %s's report: %w", entry.RunID, err)
		}
		return ref, nil
	}
	if archive.Objects == nil {
		return "", errors.New("restore: the backup holds compliance reports in the archive object store, which is not configured")
	}
	err := archive.Objects.Create(ctx, entry.Ref, bytes.NewReader(data), int64(len(data)), crypto.SHA256Sum(data))
	if err != nil && !errors.Is(err, objectstore.ErrExists) {
		return "", fmt.Errorf("restore: run %s's report: %w", entry.RunID, err)
	}
	return entry.Ref, nil
}
