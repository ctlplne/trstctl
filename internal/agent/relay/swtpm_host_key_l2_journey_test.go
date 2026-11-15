// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package relay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/kms/tpm"
)

const l2ProviderConf = `openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
alg_section = evp_properties
[provider_sect]
default = default_sect
tpm2 = tpm2_sect
[default_sect]
activate = 1
[tpm2_sect]
activate = 1
[evp_properties]
default_properties = ?provider=tpm2
`

// l2Lab is the shared TPM lab of the TPM-O1-L2 journeys: the host's
// attestation key and its operator CA, the lab CA, tpm2-abrmd on the D-Bus
// system bus in front of swtpm (services running as their own users reach it,
// as they reach /dev/tpmrm0 on a host), and the tpmrm bridge for the agent.
type l2Lab struct {
	dir, aikPath, chainPath, rmSock, sslConf string
	rootPEM, caDER                           []byte
	ca                                       *crypto.LockedSigner
}

func startL2Lab(t *testing.T, sock string) *l2Lab {
	t.Helper()
	ctx := context.Background()
	lab := &l2Lab{dir: t.TempDir()}
	dev, err := tpm.OpenDevice(tpm.DeviceConfig{Path: sock, PersistentHandleBase: 0x8101f000})
	if err != nil {
		t.Fatal(err)
	}
	backend := tpm.New(dev)
	aik, _, err := crypto.GenerateEdgeCAKeyHandleAndCSR(ctx, "tpm-o1-l2-aik", "host key attestation key", crypto.ECDSAP256, backend)
	if err != nil {
		t.Fatalf("create the attestation key: %v", err)
	}
	_ = backend.Close()
	rootPEM, chainPEM, err := deviceattesttest.IssueAIKCertificate(aik.PublicKeyDER, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	aikJSON, err := json.Marshal(aik)
	if err != nil {
		t.Fatal(err)
	}
	lab.rootPEM = rootPEM
	lab.aikPath, lab.chainPath = filepath.Join(lab.dir, "ak.json"), filepath.Join(lab.dir, "ak-chain.pem")
	for path, body := range map[string][]byte{lab.aikPath: aikJSON, lab.chainPath: chainPEM} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The provider config, where services running as their own users (dovecot's
	// login processes) can read it.
	confDir, err := os.MkdirTemp("", "tpmo1l2-provider-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(confDir) })
	if err := os.Chmod(confDir, 0o755); err != nil { // #nosec G302 -- the tpm2 provider config is not secret (CWE-276)
		t.Fatal(err)
	}
	lab.sslConf = filepath.Join(confDir, "openssl-tpm2.cnf")
	if err := os.WriteFile(lab.sslConf, []byte(l2ProviderConf), 0o644); err != nil { // #nosec G306 -- the tpm2 provider config is not secret (CWE-276)
		t.Fatal(err)
	}
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	if lab.caDER, err = crypto.SelfSignedCACert(ca, "TPM-O1-L2 journey CA", time.Hour); err != nil {
		t.Fatal(err)
	}
	lab.ca = ca

	const busSocket = "/run/dbus/system_bus_socket"
	if err := os.MkdirAll("/run/dbus", 0o755); err != nil { // #nosec G301 -- the container's D-Bus runtime directory (CWE-276)
		t.Fatal(err)
	}
	_ = os.Remove(busSocket)
	if out, err := exec.Command("dbus-uuidgen", "--ensure").CombinedOutput(); err != nil { // #nosec G204 -- fixed tool and arguments (CWE-78)
		t.Fatalf("dbus-uuidgen: %v\n%s", err, out)
	}
	labOut, err := os.Create(filepath.Join(lab.dir, "rm.out")) // #nosec G304 -- the test's own temp directory (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = labOut.Close() })
	start := func(name string, args ...string) {
		t.Helper()
		cmd := exec.Command(name, args...) // #nosec G204,G702 -- the lab's own fixed tools and test paths (CWE-78)
		cmd.Stdout, cmd.Stderr = labOut, labOut
		if err := cmd.Start(); err != nil {
			t.Fatalf("start %s: %v", name, err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	}
	wait := func(what string, ready func() bool) {
		t.Helper()
		for i := 0; i < 600; i++ {
			if ready() {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		raw, _ := os.ReadFile(filepath.Join(lab.dir, "rm.out")) // #nosec G304 -- the test's own temp directory (CWE-22)
		t.Fatalf("%s did not come up\n%s", what, raw)
	}
	start("dbus-daemon", "--system", "--nofork", "--nopidfile")
	t.Cleanup(func() { _ = os.Remove(busSocket) })
	wait("the D-Bus system bus", func() bool { _, err := os.Stat(busSocket); return err == nil })
	start("tpm2-abrmd", "--allow-root", "--tcti=swtpm:path="+sock)
	wait("tpm2-abrmd", func() bool {
		return exec.Command("tpm2_getrandom", "-T", "tabrmd", "8").Run() == nil // #nosec G204 -- fixed tool and arguments (CWE-78)
	})
	bridge := os.Getenv("TRSTCTL_TPMRM_BRIDGE")
	if bridge == "" {
		t.Fatal("TRSTCTL_TPMRM_BRIDGE names the lab's tpmrm bridge (testdata/swtpm-hostkey)")
	}
	lab.rmSock = filepath.Join(lab.dir, "tpmrm.sock")
	start(bridge, lab.rmSock, "tabrmd")
	wait("the tpmrm bridge", func() bool { fi, err := os.Stat(lab.rmSock); return err == nil && fi.Mode()&os.ModeSocket != 0 })
	return lab
}

// firstKey has the TPM make a host key and the lab CA certify it for
// web.lab.test: the key file, the chain and the leaf.
func (lab *l2Lab) firstKey(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	dev, err := tpm.OpenDevice(tpm.DeviceConfig{Path: lab.rmSock})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dev.Close() }()
	host := dev.(tpm.HostKeyDevice)
	keyFile, publicDER, err := host.CreateHostKey()
	if err != nil {
		t.Fatalf("the first TPM-held key: %v", err)
	}
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "web.lab.test", DNSNames: []string{"web.lab.test"}},
		tpm.HostKeySigner(host, keyFile, publicDER))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := crypto.SignServerCertFromCSR(lab.caDER, lab.ca, csrDER, []string{"web.lab.test"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := pem.Decode(chain)
	if leaf == nil {
		t.Fatal("the first chain has no certificate")
	}
	return keyFile, chain, leaf.Bytes
}

// renew runs one TPM-held host renewal through the relay as a host agent
// runs it, with the host's rollback ledger, and returns the served leaf.
func (lab *l2Lab) renew(t *testing.T, ch *journeyChannel, profile connector.LocalOpsConfig, rollback *relay.HostRollbackStore,
	jobID int64, connectorName string, targetConfig map[string]string, verifyAddress string, logs func() string) []byte {
	t.Helper()
	raw, err := json.Marshal(targetConfig)
	if err != nil {
		t.Fatal(err)
	}
	job := renewJob(t, relay.DeployIntent{
		Connector: connectorName, Target: "web01", TargetID: "t-tpm-o1-l2-" + connectorName,
		KeyCustody:        relay.HostKeyCustodyTPM,
		SubjectCommonName: "web.lab.test", SubjectDNSNames: []string{"web.lab.test"},
		TargetConfig: raw, VerifyAddress: verifyAddress, VerifyServerName: "web.lab.test",
	})
	job.JobID = jobID
	ch.jobs = []relay.Job{job}
	before := len(ch.reports)
	if _, err := relay.RunOnceWithSelfUpgradeAndHostRollback(context.Background(), ch, http.DefaultClient, profile, nil, nil, rollback, 4, 120); err != nil {
		t.Fatalf("job %d: %v\n%s", jobID, err, logs())
	}
	if len(ch.reports) != before+1 || ch.reports[before].outcome != transport.OutcomeVerified {
		t.Fatalf("job %d reports = %+v, want it verified\n%s", jobID, ch.reports, logs())
	}
	last := len(ch.custody) - 1
	if last < 0 || ch.custody[last].Origin != custody.OriginDevice || ch.custody[last].Storage != custody.StorageDeviceBound ||
		ch.custody[last].Exportable != custody.NonExportable {
		t.Fatalf("job %d custody = %+v, want device, device_bound, non_exportable", jobID, ch.custody)
	}
	return ch.served[len(ch.served)-1]
}

// underLoad runs fn while clients handshake continuously with every address,
// and returns how many handshakes ran and how many failed.
func underLoad(fn func(), addrs ...string) (int, int) {
	stop := make(chan struct{})
	var mu sync.Mutex
	var wg sync.WaitGroup
	handshakes, failures := 0, 0
	for _, addr := range addrs {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				res, err := tlsprobe.Probe(context.Background(), addr, tlsprobe.WithTimeout(30*time.Second))
				mu.Lock()
				handshakes++
				if err != nil || len(res.PeerCertificates) == 0 {
					failures++
				}
				mu.Unlock()
			}
		}(addr)
	}
	time.Sleep(time.Second)
	fn()
	time.Sleep(time.Second)
	close(stop)
	wg.Wait()
	return handshakes, failures
}

func freeL2Port(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func writeL2Script(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil { // #nosec G306,G703 -- the fixture IS an executable, in the test's own temp directory (CWE-276, CWE-22)
		t.Fatal(err)
	}
}

// TestSwtpmHostRenewalJourneysHAProxyAndPostfixTPMO1L2 (TPM-O1-L2 journeys;
// swtpm with Debian 12's tpm2-openssl, tpm2-abrmd, haproxy, postfix and
// dovecot; run by the internal/kms/tpm container harness): the relay renews a
// TPM-held key into haproxy and into postfix with dovecot as a host agent
// does, each from a first TPM-held key onto a new one, verified by its own
// post-deploy handshake, and then again while clients handshake
// continuously, with no handshake failing. haproxy runs as the Debian unit
// runs it, master-worker with one thread (nbthread 1, which the agent reads in
// its config before any key exists); its reload, the unit's ExecReload, makes
// the master re-execute. postfix and dovecot read the provider's config from
// their import_environment, and each of their daemons starts OpenSSL itself.
func TestSwtpmHostRenewalJourneysHAProxyAndPostfixTPMO1L2(t *testing.T) {
	sock := os.Getenv("TRSTCTL_SWTPM_PATH")
	if sock == "" || os.Getenv("TRSTCTL_TPM2_PROVIDER") != "1" || os.Getenv("TRSTCTL_SWTPM_INNER") != "1" {
		t.Skip("the swtpm container harness (TRSTCTL_SWTPM_INNER=1, TRSTCTL_SWTPM_PATH, TRSTCTL_TPM2_PROVIDER=1; the TPM-O1-L2 image) is required")
	}
	lab := startL2Lab(t, sock)
	serviceEnv := append(os.Environ(), "OPENSSL_CONF="+lab.sslConf, "TPM2OPENSSL_TCTI=tabrmd")

	t.Run("haproxy", func(t *testing.T) {
		dir := t.TempDir()
		keyFile, chain, firstLeaf := lab.firstKey(t)
		crtPath, cfgPath, pidPath := filepath.Join(dir, "web.pem"), filepath.Join(dir, "haproxy.cfg"), filepath.Join(dir, "haproxy.pid")
		if err := os.WriteFile(crtPath, append(append([]byte(nil), chain...), keyFile...), 0o600); err != nil {
			t.Fatal(err)
		}
		port := freeL2Port(t)
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		cfg := fmt.Sprintf(`global
  nbthread 1
defaults
  mode http
  timeout connect 5s
  timeout client 10s
  timeout server 10s
frontend fe
  bind %s ssl crt %s
  http-request return status 200 content-type text/plain string ok
`, addr, crtPath)
		if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		// As Debian's haproxy.service starts it (-Ws there), with the
		// provider's config from a drop-in's Environment=.
		startOut, err := os.Create(filepath.Join(dir, "haproxy.out")) // #nosec G304 -- the test's own temp directory (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		start := exec.Command("haproxy", "-W", "-D", "-f", cfgPath, "-p", pidPath) // #nosec G204,G702 -- the lab's haproxy and test paths (CWE-78)
		start.Env = serviceEnv
		start.Stdout, start.Stderr = startOut, startOut
		startErr := start.Run()
		_ = startOut.Close()
		if startErr != nil {
			raw, _ := os.ReadFile(filepath.Join(dir, "haproxy.out")) // #nosec G304 -- the test's own temp directory (CWE-22)
			t.Fatalf("start haproxy: %v\n%s", startErr, raw)
		}
		t.Cleanup(func() {
			raw, err := os.ReadFile(pidPath) // #nosec G304 -- the test's own temp directory (CWE-22)
			if err != nil {
				return
			}
			if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && pid > 1 {
				_ = syscall.Kill(pid, syscall.SIGTERM)
			}
		})
		if journeyHandshakes(addr, 1, firstLeaf) != 1 {
			time.Sleep(2 * time.Second)
			if journeyHandshakes(addr, 1, firstLeaf) != 1 {
				t.Fatal("haproxy does not serve its first TPM-held key")
			}
		}
		// The operator's haproxy action gives `haproxy -c` the provider's
		// config; the systemctl action stands in for the unit's ExecReload
		// (a check, then USR2 to the master, which re-executes).
		wrapper, reload := filepath.Join(dir, "haproxy-action"), filepath.Join(dir, "systemctl-action")
		writeL2Script(t, wrapper, fmt.Sprintf("#!/bin/sh\nexport OPENSSL_CONF=%s TPM2OPENSSL_TCTI=tabrmd\nexec /usr/sbin/haproxy \"$@\"\n", lab.sslConf))
		writeL2Script(t, reload, fmt.Sprintf("#!/bin/sh\n[ \"$*\" = \"reload haproxy\" ] || exit 2\nexport OPENSSL_CONF=%s TPM2OPENSSL_TCTI=tabrmd\n/usr/sbin/haproxy -c -q -f %s || exit 1\nexec /bin/kill -USR2 \"$(cat %s)\"\n",
			lab.sslConf, cfgPath, pidPath))
		profile := connector.LocalOpsConfig{
			AllowedRoots: []string{dir},
			Actions: []connector.LocalAction{
				{LogicalName: "haproxy", Command: wrapper, PassArgs: true, Timeout: time.Minute},
				{LogicalName: "systemctl", Command: reload, PassArgs: true, Timeout: time.Minute},
			},
			HostKeyTPM: &connector.HostKeyTPMConfig{Path: lab.rmSock, AttestationKey: lab.aikPath, AttestationCertChain: lab.chainPath},
		}
		rollback, err := relay.NewHostRollbackStore(filepath.Join(t.TempDir(), "ledger"), "tenant-tpm-o1-l2")
		if err != nil {
			t.Fatal(err)
		}
		ch := &journeyChannel{rootPEM: lab.rootPEM, ca: lab.ca, caDER: lab.caDER}
		target := map[string]string{"crt_path": crtPath, "config_path": cfgPath}
		logs := func() string { return "" }
		first := lab.renew(t, ch, profile, rollback, 77, "haproxy", target, addr, logs)
		if bytes.Equal(first, firstLeaf) || journeyHandshakes(addr, 1, first) != 1 {
			t.Fatal("haproxy does not serve the renewed certificate")
		}
		var second []byte
		handshakes, failures := underLoad(func() { second = lab.renew(t, ch, profile, rollback, 79, "haproxy", target, addr, logs) }, addr)
		if handshakes == 0 || failures != 0 {
			t.Fatalf("%d of %d handshakes failed across haproxy's reload", failures, handshakes)
		}
		if ok := journeyHandshakes(addr, 8, second); ok != 8 {
			t.Fatalf("%d of 8 concurrent handshakes saw the renewed certificate", ok)
		}
		t.Logf("TPMO1L2_HAPROXY_OK handshakes=%d failures=0 fingerprint=%s", handshakes, crypto.SHA256Hex(second))
	})

	t.Run("postfix with dovecot", func(t *testing.T) {
		dir := t.TempDir()
		keyFile, chain, firstLeaf := lab.firstKey(t)
		paths := map[string]string{
			"postfix_cert_path": filepath.Join(dir, "postfix.crt"), "postfix_key_path": filepath.Join(dir, "postfix.key"),
			"dovecot_cert_path": filepath.Join(dir, "dovecot.crt"), "dovecot_key_path": filepath.Join(dir, "dovecot.key"),
		}
		for field, path := range paths {
			body := chain
			if strings.HasSuffix(field, "_key_path") {
				body = keyFile
			}
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		smtps, imaps := freeL2Port(t), freeL2Port(t)
		smtpsAddr, imapsAddr := fmt.Sprintf("127.0.0.1:%d", smtps), fmt.Sprintf("127.0.0.1:%d", imaps)
		// Each command's output goes to a file, not a pipe: a daemon that keeps
		// the launcher's output open (dovecot does) would hold a pipe forever.
		run := func(name string, args ...string) {
			t.Helper()
			outPath := filepath.Join(dir, "run.out")
			out, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- the test's own temp directory (CWE-22)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(name, args...) // #nosec G204,G702 -- the lab's own fixed tools and test paths (CWE-78)
			cmd.Stdout, cmd.Stderr = out, out
			runErr := cmd.Run()
			_ = out.Close()
			if runErr != nil {
				raw, _ := os.ReadFile(outPath) // #nosec G304 -- the test's own temp directory (CWE-22)
				t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), runErr, raw)
			}
		}
		// dovecot's login processes run as dovenull: on a host, a member of
		// the tss group that may open /dev/tpmrm0.
		run("usermod", "-aG", "tss", "dovenull")
		imports := "OPENSSL_CONF=" + lab.sslConf + " TPM2OPENSSL_TCTI=tabrmd"
		run("postconf", "-e", "smtpd_tls_cert_file="+paths["postfix_cert_path"], "smtpd_tls_key_file="+paths["postfix_key_path"],
			"smtpd_tls_security_level=may", "inet_interfaces=loopback-only", "maillog_file=/var/log/postfix.log",
			"import_environment=MAIL_CONFIG MAIL_DEBUG MAIL_LOGTAG TZ LANG=C POSTLOG_SERVICE POSTLOG_HOSTNAME "+imports)
		master, err := os.OpenFile("/etc/postfix/master.cf", os.O_APPEND|os.O_WRONLY, 0o644) // #nosec G302,G304 -- the container's stock postfix master.cf (CWE-276, CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		_, err = fmt.Fprintf(master, "%s inet n - y - - smtpd\n  -o smtpd_tls_wrappermode=yes\n", smtpsAddr)
		_ = master.Close()
		if err != nil {
			t.Fatal(err)
		}
		dovecotConf := fmt.Sprintf(`protocols = imap
listen = 127.0.0.1
ssl = required
ssl_cert = <%s
ssl_key = <%s
import_environment = TZ CORE_OUTOFMEM CORE_ERROR LISTEN_PID LISTEN_FDS %s
log_path = /var/log/dovecot.log
mail_location = mbox:/tmp/tpm-o1-l2-mail:INBOX=/tmp/tpm-o1-l2-mail/inbox
service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    address = 127.0.0.1
    port = %d
  }
}
passdb {
  driver = static
  args = nopassword
}
userdb {
  driver = static
  args = uid=nobody gid=nogroup home=/tmp
}
`, paths["dovecot_cert_path"], paths["dovecot_key_path"], imports, imaps)
		if err := os.WriteFile("/etc/dovecot/dovecot.conf", []byte(dovecotConf), 0o644); err != nil { // #nosec G306 -- the container's stock dovecot config path (CWE-276)
			t.Fatal(err)
		}
		run("postfix", "start")
		t.Cleanup(func() { _ = exec.Command("postfix", "stop").Run() }) // #nosec G204 -- the lab's own postfix (CWE-78)
		run("dovecot")
		t.Cleanup(func() { _ = exec.Command("doveadm", "stop").Run() }) // #nosec G204 -- the lab's own dovecot (CWE-78)
		logs := func() string {
			var b strings.Builder
			for _, name := range []string{"/var/log/postfix.log", "/var/log/dovecot.log"} {
				raw, _ := os.ReadFile(name) // #nosec G304 -- the container's service logs (CWE-22)
				fmt.Fprintf(&b, "== %s\n%s\n", name, raw)
			}
			return b.String()
		}
		for _, addr := range []string{smtpsAddr, imapsAddr} {
			ok := false
			for i := 0; i < 100 && !ok; i++ {
				ok = journeyHandshakes(addr, 1, firstLeaf) == 1
				if !ok {
					time.Sleep(200 * time.Millisecond)
				}
			}
			if !ok {
				t.Fatalf("%s does not serve the first TPM-held key\n%s", addr, logs())
			}
		}
		// postfix check, doveconf -n, postfix reload and doveadm reload run as
		// the package installs them: the services take the provider's config
		// from import_environment, not from the agent.
		profile := connector.LocalOpsConfig{
			AllowedRoots: []string{dir},
			Actions: []connector.LocalAction{
				{LogicalName: "postfix", Command: "/usr/sbin/postfix", PassArgs: true, Timeout: time.Minute},
				{LogicalName: "doveconf", Command: "/usr/bin/doveconf", PassArgs: true, Timeout: time.Minute},
				{LogicalName: "doveadm", Command: "/usr/bin/doveadm", PassArgs: true, Timeout: time.Minute},
			},
			HostKeyTPM: &connector.HostKeyTPMConfig{Path: lab.rmSock, AttestationKey: lab.aikPath, AttestationCertChain: lab.chainPath},
		}
		rollback, err := relay.NewHostRollbackStore(filepath.Join(t.TempDir(), "ledger"), "tenant-tpm-o1-l2")
		if err != nil {
			t.Fatal(err)
		}
		ch := &journeyChannel{rootPEM: lab.rootPEM, ca: lab.ca, caDER: lab.caDER}
		first := lab.renew(t, ch, profile, rollback, 77, "postfix", paths, smtpsAddr, logs)
		for _, addr := range []string{smtpsAddr, imapsAddr} {
			ok := false
			for i := 0; i < 50 && !ok; i++ {
				ok = journeyHandshakes(addr, 1, first) == 1
				if !ok {
					time.Sleep(200 * time.Millisecond)
				}
			}
			if !ok {
				t.Fatalf("%s does not serve the renewed certificate\n%s", addr, logs())
			}
		}
		var second []byte
		handshakes, failures := underLoad(func() { second = lab.renew(t, ch, profile, rollback, 79, "postfix", paths, smtpsAddr, logs) }, smtpsAddr, imapsAddr)
		if handshakes == 0 || failures != 0 {
			t.Fatalf("%d of %d handshakes failed across postfix's and dovecot's reloads\n%s", failures, handshakes, logs())
		}
		for _, addr := range []string{smtpsAddr, imapsAddr} {
			ok := 0
			for i := 0; i < 25 && ok != 8; i++ {
				if ok = journeyHandshakes(addr, 8, second); ok != 8 {
					time.Sleep(200 * time.Millisecond)
				}
			}
			if ok != 8 {
				t.Fatalf("%s: %d of 8 concurrent handshakes saw the renewed certificate\n%s", addr, ok, logs())
			}
		}
		t.Logf("TPMO1L2_POSTFIX_DOVECOT_OK handshakes=%d failures=0 fingerprint=%s", handshakes, crypto.SHA256Hex(second))
	})
}
