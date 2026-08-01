// SPDX-License-Identifier: MPL-2.0

// Package supportbundle creates a bounded, offline-first diagnostic archive.
// It deliberately records posture and aggregate counts, never raw environment,
// endpoints, paths, tenant identifiers, or credential material.
package supportbundle

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

const (
	schemaVersion = 1
	maxLogBytes   = 256 << 10
	maxLogLines   = 200
	probeTimeout  = 2 * time.Second
)

var (
	uuidValue = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	pathKV    = regexp.MustCompile(`(?im)\b(?:key|cert|ca|kek|secret|token|license|store|data)_?(?:file|path|dir)\s*[:=]\s*[^\s,;]+`)
	unixPath  = regexp.MustCompile(`(?:^|[\s="'(:])/[A-Za-z0-9._~/-]+`)
	winPath   = regexp.MustCompile(`\b[A-Za-z]:\\[^\s"'<>]+`)
)

// Options are the operator-controlled inputs. Getenv is injected for tests and
// defaults to os.Getenv. Output may be empty for a timestamped current-directory
// name. LogFile is optional and is never named inside the archive.
type Options struct {
	Getenv  func(string) string
	Output  string
	LogFile string
	Now     func() time.Time
}

type manifest struct {
	SchemaVersion int      `json:"schema_version"`
	GeneratedAt   string   `json:"generated_at"`
	Privacy       []string `json:"privacy_guards"`
	Entries       []string `json:"entries"`
}

type buildPosture struct {
	Product   string `json:"product"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

type configPosture struct {
	Status              string            `json:"status"`
	PostgresMode        string            `json:"postgres_mode,omitempty"`
	NATSMode            string            `json:"nats_mode,omitempty"`
	NATSReplicas        int               `json:"nats_replicas,omitempty"`
	SignerMode          string            `json:"signer_mode,omitempty"`
	SignerTransport     string            `json:"signer_transport,omitempty"`
	TLSMode             string            `json:"tls_mode,omitempty"`
	MigrateAuto         bool              `json:"migrate_auto,omitempty"`
	AirGapEnabled       bool              `json:"air_gap_enabled,omitempty"`
	TelemetryEnabled    bool              `json:"telemetry_enabled,omitempty"`
	FIPSModuleActive    bool              `json:"fips_module_active"`
	BulkheadDefinitions []bulkheadPosture `json:"bulkhead_definitions,omitempty"`
	Protocols           map[string]bool   `json:"protocols,omitempty"`
	Warnings            []string          `json:"warnings"`
}

type bulkheadPosture struct {
	Name    string `json:"name"`
	Workers int    `json:"workers"`
	Queue   int    `json:"queue"`
}

type dependencyPosture struct {
	Config   dependencyState `json:"config"`
	Postgres dependencyState `json:"postgres"`
	NATS     dependencyState `json:"nats"`
	Signer   dependencyState `json:"signer"`
}

type dependencyState struct {
	Mode  string `json:"mode,omitempty"`
	State string `json:"state"`
}

type migrationPosture struct {
	State        string   `json:"state"`
	Auto         bool     `json:"auto"`
	PendingCount int      `json:"pending_count"`
	Pending      []string `json:"pending"`
}

type queuePosture struct {
	State      string             `json:"state"`
	Outbox     store.QueueSummary `json:"outbox"`
	Bulkheads  []bulkheadPosture  `json:"bulkheads"`
	Disclosure string             `json:"disclosure"`
}

// Create writes the support archive and returns its path. Configuration errors
// become diagnostic state instead of preventing archive creation.
func Create(ctx context.Context, opts Options) (string, error) {
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	generatedAt := now().UTC()
	output := strings.TrimSpace(opts.Output)
	if output == "" {
		output = "trstctl-support-" + generatedAt.Format("20060102T150405Z") + ".tar.gz"
	}
	if !strings.HasSuffix(strings.ToLower(output), ".tar.gz") {
		return "", errors.New("support bundle output must end in .tar.gz")
	}
	if _, err := os.Stat(output); err == nil {
		return "", fmt.Errorf("support bundle output already exists: %s", output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect support bundle output: %w", err)
	}

	cfg, cfgErr := config.Load(getenv)
	cfgPosture := collectConfigPosture(cfg, cfgErr)
	deps := dependencyPosture{
		Config:   dependencyState{State: cfgPosture.Status},
		Postgres: dependencyState{State: "not_probed"},
		NATS:     dependencyState{State: "not_probed"},
		Signer:   dependencyState{State: "not_probed"},
	}
	migrations := migrationPosture{State: "not_probed", Pending: []string{}}
	queues := queuePosture{
		State: "not_probed", Outbox: store.QueueSummary{},
		Bulkheads:  cfgPosture.BulkheadDefinitions,
		Disclosure: "aggregate counts only; tenant and destination identifiers are excluded",
	}
	if cfg != nil && cfgErr == nil {
		collectDependencyPosture(ctx, cfg, &deps, &migrations, &queues)
	}

	logs, err := sanitizedLogs(opts.LogFile)
	if err != nil {
		return "", err
	}
	entries := map[string][]byte{}
	addJSON(entries, "build.json", buildPosture{
		Product: "trstctl", Version: buildinfo.Version(), Commit: buildinfo.Commit(),
		BuildDate: buildinfo.Date(), GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH,
	})
	addJSON(entries, "config-posture.json", cfgPosture)
	addJSON(entries, "dependencies.json", deps)
	addJSON(entries, "migrations.json", migrations)
	addJSON(entries, "queues.json", queues)
	entries["logs/recent.log"] = []byte(logs)

	names := make([]string, 0, len(entries)+1)
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	manifestNames := append([]string{"manifest.json"}, names...)
	addJSON(entries, "manifest.json", manifest{
		SchemaVersion: schemaVersion,
		GeneratedAt:   generatedAt.Format(time.RFC3339),
		Privacy: []string{
			"no raw environment or configuration values",
			"no endpoint, path, tenant, subject, or destination identifiers",
			"logs secret-redacted and PII-redacted, then residual-scanned",
		},
		Entries: manifestNames,
	})
	names = append(names, "manifest.json")
	sort.Strings(names)

	for _, name := range names {
		clean := sanitize(string(entries[name]))
		if err := residualPrivacyCheck(clean); err != nil {
			return "", fmt.Errorf("support bundle refused %s: %w", name, err)
		}
		entries[name] = []byte(clean)
	}
	if err := writeArchive(output, generatedAt, names, entries); err != nil {
		return "", err
	}
	return output, nil
}

func collectConfigPosture(cfg *config.Config, cfgErr error) configPosture {
	out := configPosture{
		Status: "valid", FIPSModuleActive: crypto.FIPSEnabled(),
		Warnings: []string{}, Protocols: map[string]bool{},
	}
	if cfgErr != nil || cfg == nil {
		out.Status = "validation_failed"
		out.Warnings = append(out.Warnings, "configuration could not be validated; raw validation text is intentionally excluded")
		return out
	}
	out.PostgresMode = cfg.Postgres.Mode
	out.NATSMode = cfg.NATS.Mode
	out.NATSReplicas = cfg.NATS.Replicas
	out.SignerMode = cfg.Signer.Mode
	switch {
	case cfg.Signer.Mode == config.SignerChild:
		out.SignerTransport = "child_uds"
	case cfg.Signer.MTLSEnabled():
		out.SignerTransport = "external_mtls"
	default:
		out.SignerTransport = "external_uds"
	}
	out.TLSMode = cfg.Server.TLS.Mode
	out.MigrateAuto = cfg.Migrate.Auto
	out.AirGapEnabled = cfg.AirGap.Enabled
	out.TelemetryEnabled = cfg.Telemetry.Enabled
	for _, limit := range cfg.Bulkheads.Configs() {
		out.BulkheadDefinitions = append(out.BulkheadDefinitions, bulkheadPosture{
			Name: limit.Name, Workers: limit.Workers, Queue: limit.Queue,
		})
	}
	protocols, err := cfg.Protocols.Effective()
	if err != nil {
		out.Warnings = append(out.Warnings, "protocol profile could not be resolved")
		return out
	}
	out.Protocols = map[string]bool{
		"acme": protocols.ACME.Enabled, "est": protocols.EST.Enabled,
		"scep": protocols.SCEP.Enabled, "cmp": protocols.CMP.Enabled,
		"spiffe": protocols.SPIFFE.Enabled, "ssh": protocols.SSH.Enabled,
		"tsa": protocols.TSA.Enabled,
	}
	return out
}

func collectDependencyPosture(ctx context.Context, cfg *config.Config, deps *dependencyPosture, migrations *migrationPosture, queues *queuePosture) {
	deps.Postgres.Mode = cfg.Postgres.Mode
	deps.NATS.Mode = cfg.NATS.Mode
	deps.Signer.Mode = cfg.Signer.Mode

	if cfg.Postgres.Mode == config.PostgresExternal {
		probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
		st, err := store.Open(probeCtx, cfg.Postgres.DSN)
		cancel()
		if err != nil {
			deps.Postgres.State = "unreachable"
			migrations.State = "unavailable"
			queues.State = "unavailable"
		} else {
			defer st.Close()
			deps.Postgres.State = "reachable"
			probeCtx, cancel = context.WithTimeout(ctx, probeTimeout)
			pending, err := st.PendingMigrations(probeCtx)
			cancel()
			if err != nil {
				migrations.State = "unavailable"
			} else {
				migrations.State = "read"
				migrations.Auto = cfg.Migrate.Auto
				migrations.Pending = pending
				migrations.PendingCount = len(pending)
			}
			probeCtx, cancel = context.WithTimeout(ctx, probeTimeout)
			summary, err := st.SupportQueueSummary(probeCtx)
			cancel()
			if err != nil {
				queues.State = "unavailable"
			} else {
				queues.State = "read"
				queues.Outbox = summary
			}
		}
	} else {
		deps.Postgres.State = probeTCP(net.JoinHostPort("127.0.0.1", fmt.Sprint(cfg.Postgres.Port)))
		migrations.State = "bundled_checked_during_control_plane_start"
		migrations.Auto = cfg.Migrate.Auto
		queues.State = "requires_running_bundled_database"
	}

	if cfg.NATS.Mode == config.NATSExternal {
		deps.NATS.State = probeURLTCP(cfg.NATS.URL)
	} else if directoryReady(cfg.NATS.StoreDir) {
		deps.NATS.State = "embedded_storage_present"
	} else {
		deps.NATS.State = "embedded_storage_not_created"
	}

	switch {
	case cfg.Signer.Mode == config.SignerChild:
		if directoryReady(cfg.Signer.KeyStoreDir) {
			deps.Signer.State = "child_storage_present_process_not_started"
		} else {
			deps.Signer.State = "child_storage_not_created_process_not_started"
		}
	case cfg.Signer.MTLSEnabled():
		deps.Signer.State = probeTCP(cfg.Signer.MTLSAddress)
	default:
		deps.Signer.State = probeUnix(cfg.Signer.Socket)
	}
}

func probeURLTCP(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "invalid_endpoint"
	}
	host := parsed.Host
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "4222")
	}
	return probeTCP(host)
}

func probeTCP(address string) string {
	conn, err := net.DialTimeout("tcp", address, probeTimeout)
	if err != nil {
		return "unreachable"
	}
	_ = conn.Close()
	return "tcp_reachable"
}

func probeUnix(path string) string {
	conn, err := net.DialTimeout("unix", path, probeTimeout)
	if err != nil {
		return "unreachable"
	}
	_ = conn.Close()
	return "reachable"
}

func directoryReady(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func sanitizedLogs(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "No log file supplied. Re-run with --log-file to include a bounded sanitized tail.\n", nil
	}
	file, err := os.Open(path) // #nosec G304 -- operator-invoked support bundle collecting its configured files (CWE-22)
	if err != nil {
		return "", fmt.Errorf("read support log: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect support log: %w", err)
	}
	offset := info.Size() - maxLogBytes
	if offset < 0 {
		offset = 0
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return "", fmt.Errorf("seek support log: %w", err)
	}
	body, err := io.ReadAll(io.LimitReader(file, maxLogBytes))
	if err != nil {
		return "", fmt.Errorf("read support log tail: %w", err)
	}
	lines := strings.Split(string(body), "\n")
	if offset > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	if len(lines) > maxLogLines {
		lines = lines[len(lines)-maxLogLines:]
	}
	return sanitize(strings.Join(lines, "\n")) + "\n", nil
}

func sanitize(value string) string {
	out := aimodel.DefaultRedactor(value)
	out = aimodel.RedactPII(out)
	out = uuidValue.ReplaceAllString(out, "[REDACTED-IDENTIFIER]")
	out = pathKV.ReplaceAllString(out, "[REDACTED-PATH]")
	out = unixPath.ReplaceAllStringFunc(out, func(value string) string {
		if len(value) > 0 && value[0] != '/' {
			return value[:1] + "[REDACTED-PATH]"
		}
		return "[REDACTED-PATH]"
	})
	out = winPath.ReplaceAllString(out, "[REDACTED-PATH]")
	return out
}

func residualPrivacyCheck(value string) error {
	if aimodel.ResidualSecret(value) {
		return errors.New("residual secret-like material remains after redaction")
	}
	if aimodel.ContainsPII(value) || uuidValue.MatchString(value) {
		return errors.New("residual personal or tenant identifier remains after redaction")
	}
	return nil
}

func addJSON(entries map[string][]byte, name string, value any) {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	entries[name] = append(body, '\n')
}

func writeArchive(output string, generatedAt time.Time, names []string, entries map[string][]byte) error {
	dir := filepath.Dir(output)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create support bundle directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, ".trstctl-support-*.tar.gz")
	if err != nil {
		return fmt.Errorf("create support bundle: %w", err)
	}
	tempPath := temp.Name()
	keep := false
	defer func() {
		_ = temp.Close()
		if !keep {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	zw := gzip.NewWriter(temp)
	zw.ModTime = time.Unix(0, 0).UTC()
	zw.OS = 255
	tw := tar.NewWriter(zw)
	for _, name := range names {
		body := entries[name]
		header := &tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(body)),
			ModTime: generatedAt, AccessTime: time.Time{}, ChangeTime: time.Time{},
			Uid: 0, Gid: 0, Uname: "", Gname: "",
		}
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if _, err := tw.Write(body); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, output); err != nil {
		return fmt.Errorf("publish support bundle: %w", err)
	}
	keep = true
	return nil
}
