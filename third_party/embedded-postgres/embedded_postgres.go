// SPDX-License-Identifier: MIT

package embeddedpostgres

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

var mu sync.Mutex

// EmbeddedPostgres maintains all configuration and runtime functions for maintaining the lifecycle of one Postgres process.
type EmbeddedPostgres struct {
	config                 Config
	cacheLocator           CacheLocator
	remoteFetchStrategy    RemoteFetchStrategy
	initDatabase           initDatabase
	createDatabase         createDatabase
	started                bool
	syncedLogger           *syncedLogger
	archiveIdentity        *ArchiveIdentity
	verifiedConfig         Config
	verifiedRunPath        string
	verifiedStartUncertain bool
	fetchVerifiedArchive   func(string) error
}

// NewDatabase creates a new EmbeddedPostgres struct that can be used to start and stop a Postgres process.
// When called with no parameters it will assume a default configuration state provided by the DefaultConfig method.
// When called with parameters the first Config parameter will be used for configuration.
func NewDatabase(config ...Config) *EmbeddedPostgres {
	if len(config) < 1 {
		return newDatabaseWithConfig(DefaultConfig())
	}

	return newDatabaseWithConfig(config[0])
}

func newDatabaseWithConfig(config Config) *EmbeddedPostgres {
	versionStrategy := defaultVersionStrategy(
		config,
		runtime.GOOS,
		runtime.GOARCH,
		linuxMachineName,
		shouldUseAlpineLinuxBuild,
	)
	cacheLocator := defaultCacheLocator(config.cachePath, versionStrategy)
	client := netsec.SafeClient(30 * time.Second)
	return &EmbeddedPostgres{
		config: config, cacheLocator: cacheLocator,
		remoteFetchStrategy: defaultRemoteFetchStrategy(config.binaryRepositoryURL, versionStrategy, cacheLocator, client),
		fetchVerifiedArchive: func(destination string) error {
			return defaultRemoteFetchStrategy(config.binaryRepositoryURL, versionStrategy,
				func() (string, bool) { return destination, false }, client, expectedTXZName(versionStrategy))()
		},
		initDatabase: defaultInitDatabase, createDatabase: defaultCreateDatabase,
	}

}

// Start will try to start the configured Postgres process returning an error when there were any problems with invocation.
// If any error occurs Start will try to also Stop the Postgres process in order to not leave any sub-process running.
//
//nolint:funlen
func (ep *EmbeddedPostgres) Start() (err error) {
	if ep.started {
		return errors.New("server is already started")
	}
	if ep.archiveIdentity != nil {
		if err := ep.prepareVerifiedBinary(); err != nil {
			return err
		}
		defer func() {
			if err != nil && !ep.started && !ep.verifiedStartUncertain {
				err = errors.Join(err, ep.cleanupVerifiedBinary())
			}
		}()
	}

	if err := ensurePortAvailable(ep.config.port); err != nil {
		return err
	}

	logger, err := newSyncedLogger(ep.verifiedRunPath, ep.config.logger)
	if err != nil {
		return errors.New("unable to create logger")
	}

	ep.syncedLogger = logger

	cacheLocation, cacheExists := ep.cacheLocator()

	if ep.config.runtimePath == "" {
		ep.config.runtimePath = filepath.Join(filepath.Dir(cacheLocation), "extracted")
	}

	if ep.config.dataPath == "" {
		ep.config.dataPath = filepath.Join(ep.config.runtimePath, "data")
	}

	if err := os.RemoveAll(ep.config.runtimePath); err != nil {
		return fmt.Errorf("unable to clean up runtime directory %s with error: %s", ep.config.runtimePath, err)
	}

	if ep.config.binariesPath == "" {
		ep.config.binariesPath = ep.config.runtimePath
	}

	if err := ep.downloadAndExtractBinary(cacheExists, cacheLocation); err != nil {
		return err
	}

	if err := os.MkdirAll(ep.config.runtimePath, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create runtime directory %s with error: %s", ep.config.runtimePath, err)
	}

	var reuseData bool
	if ep.archiveIdentity != nil {
		reuseData, err = ep.verifiedDataReady()
		if err != nil {
			return err
		}
	} else {
		reuseData = dataDirIsValid(ep.config.dataPath, ep.config.version)
	}

	if !reuseData {
		if err := ep.cleanDataDirectoryAndInit(); err != nil {
			return err
		}
	}

	if err := startPostgres(ep); err != nil {
		if ep.archiveIdentity != nil {
			// A failed pg_ctl start cannot establish whether it launched a child or
			// encountered another owner's server. Do not stop that unproven process.
			// Preserve this private tree for diagnosis instead of deleting live bytes.
			ep.verifiedStartUncertain = true
			closeErr := ep.syncedLogger.file.Close()
			ep.syncedLogger = nil
			return fmt.Errorf("%w; startup ownership uncertain; private tree retained at %s", errors.Join(err, closeErr), ep.verifiedRunPath)
		}
		return err
	}

	ep.started = true
	if err := ep.syncedLogger.flush(); err != nil {
		if ep.archiveIdentity != nil {
			if stopErr := stopPostgres(ep); stopErr != nil {
				return errors.Join(err, stopErr)
			}
			ep.started = false
		}
		return err
	}

	if !reuseData {
		if err := ep.createDatabase(ep.config.port, ep.config.username, ep.config.password, ep.config.database); err != nil {
			if stopErr := stopPostgres(ep); stopErr != nil {
				return fmt.Errorf("database operation failed and shutdown failed: %w", errors.Join(err, stopErr))
			}
			ep.started = false

			return err
		}
	}

	if err := healthCheckDatabaseOrTimeout(ep.config); err != nil {
		if stopErr := stopPostgres(ep); stopErr != nil {
			return fmt.Errorf("database operation failed and shutdown failed: %w", errors.Join(err, stopErr))
		}
		ep.started = false

		return err
	}

	return nil
}

func (ep *EmbeddedPostgres) downloadAndExtractBinary(cacheExists bool, cacheLocation string) error {
	if ep.archiveIdentity != nil {
		if ep.verifiedRunPath == "" {
			return errors.New("postgres verified binary preparation is missing")
		}
		return nil
	}
	// lock to prevent collisions with duplicate downloads
	mu.Lock()
	defer mu.Unlock()

	_, binDirErr := os.Stat(filepath.Join(ep.config.binariesPath, "bin"))
	if os.IsNotExist(binDirErr) {
		if !cacheExists {
			if err := ep.remoteFetchStrategy(); err != nil {
				return err
			}
		}

		if err := decompressTarXz(defaultTarReader, cacheLocation, ep.config.binariesPath); err != nil {
			return err
		}
	}
	return nil
}

func (ep *EmbeddedPostgres) cleanDataDirectoryAndInit() error {
	if ep.archiveIdentity != nil {
		return ep.initVerifiedDataDirectory()
	}
	if err := os.RemoveAll(ep.config.dataPath); err != nil {
		return fmt.Errorf("unable to clean up data directory %s with error: %s", ep.config.dataPath, err)
	}

	if err := ep.initDatabase(ep.config.binariesPath, ep.config.runtimePath, ep.config.dataPath, ep.config.username, ep.config.password, ep.config.locale, ep.config.encoding, ep.syncedLogger.file); err != nil {
		return err
	}

	return nil
}

// Stop will try to stop the Postgres process gracefully returning an error when there were any problems.
func (ep *EmbeddedPostgres) Stop() error {
	if !ep.started {
		return errors.New("server has not been started")
	}

	if err := stopPostgres(ep); err != nil {
		return err
	}

	ep.started = false

	flushErr := ep.syncedLogger.flush()
	if ep.archiveIdentity != nil {
		return errors.Join(flushErr, ep.cleanupVerifiedBinary())
	}
	return flushErr
}

func encodeOptions(port uint32, parameters map[string]string) string {
	options := []string{fmt.Sprintf("-p %d", port)}
	for k, v := range parameters {
		// Single-quote parameter values - they may have spaces.
		options = append(options, fmt.Sprintf("-c %s='%s'", k, v))
	}
	return strings.Join(options, " ")
}

func startPostgres(ep *EmbeddedPostgres) error {
	args := postgresStartArgs(ep.config, ep.syncedLogger.file.Name())
	postgresProcess := exec.Command(args[0], args[1:]...)
	postgresProcess.Stdout = ep.syncedLogger.file
	postgresProcess.Stderr = ep.syncedLogger.file

	if err := postgresProcess.Run(); err != nil {
		flushErr := ep.syncedLogger.flush()
		logContent, readErr := readLogsOrTimeout(ep.syncedLogger.file)

		return fmt.Errorf("could not start postgres using %s: %w\n%s", postgresProcess.String(), errors.Join(err, flushErr, readErr), string(logContent))
	}

	return nil
}

func postgresStartArgs(config Config, logPath string) []string {
	return []string{
		filepath.Join(config.binariesPath, "bin/pg_ctl"), "start", "-w",
		"-D", config.dataPath,
		// pg_ctl otherwise discards the server process's stderr. Keep it in the
		// same private temporary log already read into startup errors so a failed
		// database never degrades into the unactionable "Examine the log output".
		"-l", logPath,
		"-o", encodeOptions(config.port, config.startParameters),
	}
}

func stopPostgres(ep *EmbeddedPostgres) error {
	postgresBinary := filepath.Join(ep.config.binariesPath, "bin/pg_ctl")
	postgresProcess := exec.Command(postgresBinary, "stop", "-w",
		"-D", ep.config.dataPath)
	postgresProcess.Stderr = ep.syncedLogger.file
	postgresProcess.Stdout = ep.syncedLogger.file

	if err := postgresProcess.Run(); err != nil {
		return err
	}

	return nil
}

func ensurePortAvailable(port uint32) error {
	conn, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return fmt.Errorf("process already listening on port %d", port)
	}

	if err := conn.Close(); err != nil {
		return err
	}

	return nil
}

func dataDirIsValid(dataDir string, version PostgresVersion) bool {
	pgVersion := filepath.Join(dataDir, "PG_VERSION")

	d, err := os.ReadFile(pgVersion)
	if err != nil {
		return false
	}

	v := strings.TrimSuffix(string(d), "\n")

	return strings.HasPrefix(string(version), v)
}
