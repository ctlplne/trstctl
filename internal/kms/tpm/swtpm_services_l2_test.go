// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package tpm_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/kms/tpm"
)

// startSystemResourceManager starts tpm2-abrmd on the container's D-Bus
// system bus in front of swtpm, where services running as their own users
// reach it under the package's policy (root, and the tss group), as they reach
// /dev/tpmrm0 on a host. It returns the tpm2 provider's environment.
func startSystemResourceManager(t *testing.T, sock string) []string {
	t.Helper()
	const busSocket = "/run/dbus/system_bus_socket"
	if err := os.MkdirAll("/run/dbus", 0o755); err != nil { // #nosec G301 -- the container's D-Bus runtime directory (CWE-276)
		t.Fatal(err)
	}
	_ = os.Remove(busSocket)
	if out, err := exec.Command("dbus-uuidgen", "--ensure").CombinedOutput(); err != nil { // #nosec G204 -- fixed tool and arguments (CWE-78)
		t.Fatalf("dbus-uuidgen: %v\n%s", err, out)
	}
	var labLog bytes.Buffer
	bus := exec.Command("dbus-daemon", "--system", "--nofork", "--nopidfile") // #nosec G204 -- fixed tool and arguments (CWE-78)
	bus.Stdout, bus.Stderr = &labLog, &labLog
	if err := bus.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bus.Process.Kill(); _ = bus.Wait(); _ = os.Remove(busSocket) })
	waitFor(t, "the D-Bus system bus", func() bool { _, err := os.Stat(busSocket); return err == nil }, labLog.String)
	rm := exec.Command("tpm2-abrmd", "--allow-root", "--tcti=swtpm:path="+sock) // #nosec G204,G702 -- a fixed tool; the socket path is the container harness's own swtpm (CWE-78)
	rm.Stdout, rm.Stderr = &labLog, &labLog
	if err := rm.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rm.Process.Kill(); _ = rm.Wait() })
	waitFor(t, "tpm2-abrmd on the system bus", func() bool {
		return exec.Command("tpm2_getrandom", "-T", "tabrmd", "8").Run() == nil // #nosec G204 -- fixed tool and arguments (CWE-78)
	}, labLog.String)
	return append(os.Environ(), "TPM2OPENSSL_TCTI=tabrmd")
}

// stopByPIDFile sends SIGTERM to the process a pid file names (the lab's
// own daemons).
func stopByPIDFile(path string) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the test's own temp directory (CWE-22)
	if err != nil {
		return
	}
	if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && pid > 1 {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
}

// handshakesWith runs n TLS handshakes at once, each after negotiate, and
// returns how many completed with leaf.
func handshakesWith(addr string, n int, leaf []byte, negotiate tlsprobe.PreHandshake) int {
	var mu sync.Mutex
	var wg sync.WaitGroup
	ok := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			opts := []tlsprobe.Option{tlsprobe.WithTimeout(30 * time.Second)}
			if negotiate != nil {
				opts = append(opts, tlsprobe.WithPreHandshake(negotiate))
			}
			res, err := tlsprobe.Probe(context.Background(), addr, opts...)
			if err == nil && len(res.PeerCertificates) > 0 && bytes.Equal(res.PeerCertificates[0], leaf) {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return ok
}

// runAs runs a lab command, failing the test with its output. The output goes
// to a file, not a pipe: a daemon that keeps the launcher's output open would
// hold a pipe forever.
func runAs(t *testing.T, env []string, name string, args ...string) {
	t.Helper()
	out, err := os.CreateTemp("", "tpmo1l2-run-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(out.Name()) }()
	cmd := exec.Command(name, args...) // #nosec G204,G702 -- the lab's own fixed tools and test paths (CWE-78)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = out, out
	runErr := cmd.Run()
	_ = out.Close()
	if runErr != nil {
		raw, _ := os.ReadFile(out.Name()) // #nosec G304 -- the test's own temp file (CWE-22)
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), runErr, raw)
	}
}

// TestSwtpmServicesSharingTheTPM2ProviderFailConcurrentHandshakesTPMO1L2
// (swtpm + tpm2-abrmd + Debian 12's tpm2-openssl and stock packages; run by
// the container harness): why apache, postgresql and mysql (MariaDB) do not
// take a TPM-held key, and why haproxy takes one only with nbthread 1. Each
// loads the TSS2 key through the tpm2 provider once, in one process, and then
// handshakes on threads (apache's event MPM, haproxy's default threads,
// MariaDB) or in forked processes (PostgreSQL's backends) that share that
// process's one provider context, so concurrent handshakes fail. Each check
// fails when a package changes the behavior, so the connector list in
// internal/agent/relay can be revisited.
func TestSwtpmServicesSharingTheTPM2ProviderFailConcurrentHandshakesTPMO1L2(t *testing.T) {
	sock := os.Getenv("TRSTCTL_SWTPM_PATH")
	if sock == "" || os.Getenv("TRSTCTL_TPM2_PROVIDER") != "1" || os.Getenv("TRSTCTL_SWTPM_INNER") != "1" {
		t.Skip("the swtpm container harness (TRSTCTL_SWTPM_INNER=1, TRSTCTL_SWTPM_PATH, TRSTCTL_TPM2_PROVIDER=1) is required")
	}
	dev, err := tpm.OpenDevice(tpm.DeviceConfig{Path: sock, PersistentHandleBase: 0x8101e000})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := crypto.SelfSignedCACert(ca, "TPM-O1-L2 lab CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyFile, chainPEM, leaf := labTPMServerCert(t, dev.(tpm.HostKeyDevice), ca, caDER)
	_ = dev.Close()
	// The provider config, where each service's own user can read it.
	confDir, err := os.MkdirTemp("", "tpmo1l2-provider-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(confDir) })
	if err := os.Chmod(confDir, 0o755); err != nil { // #nosec G302 -- the tpm2 provider config is not secret (CWE-276)
		t.Fatal(err)
	}
	confPath := filepath.Join(confDir, "openssl-tpm2.cnf")
	if err := os.WriteFile(confPath, []byte(tpm2ProviderConf), 0o644); err != nil { // #nosec G306 -- the services' users read the provider config (CWE-276)
		t.Fatal(err)
	}
	env := append(startSystemResourceManager(t, sock), "OPENSSL_CONF="+confPath)
	runAs(t, env, "usermod", "-aG", "tss", "postgres")
	runAs(t, env, "usermod", "-aG", "tss", "mysql")
	// A directory each service's own user can read, with the certificate and
	// the TPM's key file.
	shared := func(owner string) (string, string, string) {
		t.Helper()
		dir, err := os.MkdirTemp("", "tpmo1l2-"+owner+"-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
		for path, body := range map[string][]byte{certPath: chainPEM, keyPath: keyFile} {
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		runAs(t, env, "chown", "-R", owner+":"+owner, dir)
		return dir, certPath, keyPath
	}
	expectFailures := func(service, marker string, addr string, negotiate tlsprobe.PreHandshake, logs func() string) {
		t.Helper()
		first := handshakesWith(addr, 8, leaf, negotiate)
		second := handshakesWith(addr, 8, leaf, negotiate)
		if first == 8 && second == 8 {
			t.Fatalf("%s now serves a TPM-held key to concurrent handshakes: revisit tpmHostKeyConnectors in internal/agent/relay and the TPM-O1 limits in docs/limitations.md\n%s", service, logs())
		}
		t.Logf("%s: %d and %d of 8 concurrent handshakes completed", service, first, second)
		t.Log(marker)
	}

	// apache2 with Debian's default event MPM: handshakes on worker threads.
	apachePort := freeLoopbackPort(t)
	_, apacheCert, apacheKey := shared("root")
	runAs(t, env, "a2enmod", "-q", "ssl")
	site := fmt.Sprintf("ServerName web.lab.test\nListen 127.0.0.1:%d\n<VirtualHost 127.0.0.1:%d>\n  SSLEngine on\n  SSLCertificateFile %s\n  SSLCertificateKeyFile %s\n</VirtualHost>\n",
		apachePort, apachePort, apacheCert, apacheKey)
	if err := os.WriteFile("/etc/apache2/sites-enabled/tpm-o1-l2.conf", []byte(site), 0o644); err != nil { // #nosec G306 -- the container's stock apache2 site directory (CWE-276)
		t.Fatal(err)
	}
	runAs(t, env, "apache2ctl", "start")
	apacheLogs := func() string { raw, _ := os.ReadFile("/var/log/apache2/error.log"); return string(raw) } // #nosec G304 -- the container's apache2 log (CWE-22)
	waitFor(t, "apache2", func() bool { return handshakesWith(fmt.Sprintf("127.0.0.1:%d", apachePort), 1, leaf, nil) == 1 }, apacheLogs)
	expectFailures("apache2 (event MPM)", "TPMO1L2_APACHE_EVENT_FAILS_AS_DOCUMENTED", fmt.Sprintf("127.0.0.1:%d", apachePort), nil, apacheLogs)
	runAs(t, env, "apache2ctl", "stop")

	// haproxy with its default threads, one per CPU.
	haproxyDir, _, _ := shared("root")
	bundle := append(append([]byte(nil), chainPEM...), keyFile...)
	bundlePath := filepath.Join(haproxyDir, "web.pem")
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	haproxyPort := freeLoopbackPort(t)
	cfgPath := filepath.Join(haproxyDir, "haproxy.cfg")
	cfg := fmt.Sprintf("global\n  log stderr format raw local0\ndefaults\n  mode http\n  timeout connect 5s\n  timeout client 10s\n  timeout server 10s\nfrontend fe\n  bind 127.0.0.1:%d ssl crt %s\n  http-request return status 200 content-type text/plain string ok\n",
		haproxyPort, bundlePath)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(haproxyDir, "haproxy.pid")
	runAs(t, env, "haproxy", "-W", "-D", "-f", cfgPath, "-p", pidPath)
	t.Cleanup(func() { stopByPIDFile(pidPath) })
	noLogs := func() string { return "" }
	waitFor(t, "haproxy", func() bool { return handshakesWith(fmt.Sprintf("127.0.0.1:%d", haproxyPort), 1, leaf, nil) == 1 }, noLogs)
	expectFailures("haproxy (default threads)", "TPMO1L2_HAPROXY_THREADS_FAIL_AS_DOCUMENTED", fmt.Sprintf("127.0.0.1:%d", haproxyPort), nil, noLogs)
	stopByPIDFile(pidPath)

	// PostgreSQL 15: backends forked from the postmaster that loaded the key.
	pgDir, pgCert, pgKey := shared("postgres")
	pgData := filepath.Join(pgDir, "data")
	runAs(t, env, "su", "postgres", "-c", "/usr/lib/postgresql/15/bin/initdb -D "+pgData)
	pgPort := freeLoopbackPort(t)
	pgConf := fmt.Sprintf("ssl = on\nssl_cert_file = '%s'\nssl_key_file = '%s'\nport = %d\nlisten_addresses = '127.0.0.1'\nunix_socket_directories = '%s'\n",
		pgCert, pgKey, pgPort, pgDir)
	if err := os.WriteFile(filepath.Join(pgData, "postgresql.auto.conf"), []byte(pgConf), 0o600); err != nil {
		t.Fatal(err)
	}
	runAs(t, env, "chown", "-R", "postgres:postgres", pgDir)
	pgLog := filepath.Join(pgDir, "postgres.log")
	pgLogs := func() string { raw, _ := os.ReadFile(pgLog); return string(raw) } // #nosec G304 -- the test's own temp directory (CWE-22)
	pgStart := exec.Command("su", "postgres", "-c",                              // #nosec G204,G702 -- the lab's own PostgreSQL and test paths (CWE-78)
		fmt.Sprintf("OPENSSL_CONF=%s TPM2OPENSSL_TCTI=tabrmd /usr/lib/postgresql/15/bin/pg_ctl -D %s -l %s -w start", confPath, pgData, pgLog))
	pgStart.Env = env
	t.Cleanup(func() {
		_ = exec.Command("su", "postgres", "-c", "/usr/lib/postgresql/15/bin/pg_ctl -D "+pgData+" -m fast stop").Run() // #nosec G204 -- the lab's own PostgreSQL (CWE-78)
	})
	pgOutPath := filepath.Join(pgDir, "pg_ctl.out")
	pgOut, err := os.Create(pgOutPath) // #nosec G304 -- the test's own temp directory (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	pgStart.Stdout, pgStart.Stderr = pgOut, pgOut
	err = pgStart.Run()
	_ = pgOut.Close()
	out, _ := os.ReadFile(pgOutPath) // #nosec G304 -- the test's own temp directory (CWE-22)
	if err != nil {
		// The postmaster refusing to start with the key is the same failure:
		// its SSL context needs the provider's context it would share.
		t.Logf("PostgreSQL 15 did not start with the TPM-held key: %v\n%s\n%s", err, out, pgLogs())
		t.Log("TPMO1L2_POSTGRESQL_FAILS_AS_DOCUMENTED")
	} else {
		expectFailures("PostgreSQL 15", "TPMO1L2_POSTGRESQL_FAILS_AS_DOCUMENTED", fmt.Sprintf("127.0.0.1:%d", pgPort), tlsprobe.PostgresSSLRequest, pgLogs)
	}

	// MariaDB: a thread per connection.
	mdbDir, mdbCert, mdbKey := shared("mysql")
	mdbData := filepath.Join(mdbDir, "data")
	runAs(t, env, "mariadb-install-db", "--user=mysql", "--datadir="+mdbData)
	mdbPort := freeLoopbackPort(t)
	myCnf := filepath.Join(mdbDir, "my.cnf")
	options := []byte(fmt.Sprintf("[mysqld]\nuser=mysql\ndatadir=%s\nsocket=%s/mysqld.sock\npid-file=%s/mysqld.pid\nport=%d\nbind-address=127.0.0.1\nssl-cert=%s\nssl-key=%s\n",
		mdbData, mdbDir, mdbDir, mdbPort, mdbCert, mdbKey))
	if err := os.WriteFile(myCnf, options, 0o644); err != nil { // #nosec G306 -- MariaDB reads its option file as its own user (CWE-276)
		t.Fatal(err)
	}
	runAs(t, env, "chown", "-R", "mysql:mysql", mdbDir)
	var mdbLog bytes.Buffer
	mdb := exec.Command("mariadbd", "--defaults-file="+myCnf) // #nosec G204,G702 -- the lab's own MariaDB and test paths (CWE-78)
	mdb.Env = env
	mdb.Stdout, mdb.Stderr = &mdbLog, &mdbLog
	if err := mdb.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mdb.Process.Kill(); _ = mdb.Wait() })
	waitFor(t, "MariaDB", func() bool {
		return handshakesWith(fmt.Sprintf("127.0.0.1:%d", mdbPort), 1, leaf, tlsprobe.MySQLSSLRequest) == 1
	}, mdbLog.String)
	expectFailures("MariaDB", "TPMO1L2_MARIADB_FAILS_AS_DOCUMENTED", fmt.Sprintf("127.0.0.1:%d", mdbPort), tlsprobe.MySQLSSLRequest, mdbLog.String)
}
