// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package relay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/kms/tpm"
)

// journeyChannel stands in for the control plane in the swtpm journey: it
// verifies the TPM's attestation of the CSR's key for the job exactly as
// SignJobCSR does (deviceattest under the operator's root) and signs the CSR
// with a lab CA.
type journeyChannel struct {
	renewChannel
	rootPEM []byte
	ca      *crypto.LockedSigner
	caDER   []byte
	served  [][]byte
}

func (j *journeyChannel) SignJobCSRWithKeyAttestation(_ context.Context, jobID int64, _ int, csrDER, attestation []byte) ([]byte, []byte, string, error) {
	j.signCalls++
	j.signed = append(j.signed, append([]byte(nil), csrDER...))
	binding, err := deviceattest.HostKeyBinding(jobID, csrDER)
	if err != nil {
		return nil, nil, "", err
	}
	if _, err := deviceattest.VerifyHostKeyAttestation(attestation, binding, csrDER, [][]byte{j.rootPEM}, time.Now().UTC()); err != nil {
		return nil, nil, "", fmt.Errorf("the control plane refused the attestation: %w", err)
	}
	chain, err := crypto.SignServerCertFromCSR(j.caDER, j.ca, csrDER, []string{"web.lab.test"}, time.Hour)
	if err != nil {
		return nil, nil, "", err
	}
	leaf, rest := pem.Decode(chain)
	if leaf == nil {
		return nil, nil, "", errors.New("no issued leaf")
	}
	j.served = append(j.served, leaf.Bytes)
	return pem.EncodeToMemory(leaf), rest, crypto.SHA256Hex(leaf.Bytes), nil
}

// journeyHandshakes runs n TLS handshakes at once and returns how many
// completed with leaf.
func journeyHandshakes(addr string, n int, leaf []byte) int {
	var mu sync.Mutex
	var wg sync.WaitGroup
	ok := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := tlsprobe.Probe(context.Background(), addr, tlsprobe.WithTimeout(30*time.Second))
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

// TestSwtpmHostRenewalJourneyTPMO1 (TPM-O1 journey; swtpm with Debian 12's
// tpm2-openssl, tpm2-abrmd and nginx; run by the internal/kms/tpm container
// harness): a host renewal whose profile requires a TPM-held key, executed by
// the relay against a real TPM, has the TPM create the key and sign the CSR,
// proves it with TPM2_Certify by a TPM attestation key the operator's CA
// certified, and the control plane's check accepts it; the agent installs the
// TPM's key file for nginx, which serves the new certificate through the tpm2
// provider (the relay's own post-deploy handshake verifies it, and a separate
// client sees it too), and the receipt claims a device-origin, device-bound,
// non-exportable key. No software private key is written anywhere.
//
// TPM-O1-L3: nginx runs as the Debian package runs it, a master and one worker
// started by /etc/init.d/nginx from /etc/nginx/nginx.conf, with the provider's
// OpenSSL config in its environment as a systemd drop-in would give it. The
// host profile's nginx action is the operator's wrapper that gives `nginx -t`
// that config too (the agent runs actions with a scrubbed environment), and
// its nginx-upgrade action is the init script's upgrade, which re-executes
// nginx so a fresh master loads the key; the agent never reloads nginx in
// place. A second renewal onto a new TPM key runs while a client handshakes
// continuously, and no handshake fails. TPM-O1-L1: a CA re-protection of the
// TPM-held key runs through the TPM the same way.
func TestSwtpmHostRenewalJourneyTPMO1(t *testing.T) {
	sock := os.Getenv("TRSTCTL_SWTPM_PATH")
	if sock == "" || os.Getenv("TRSTCTL_TPM2_PROVIDER") != "1" || os.Getenv("TRSTCTL_SWTPM_INNER") != "1" {
		t.Skip("the swtpm container harness (TRSTCTL_SWTPM_INNER=1, TRSTCTL_SWTPM_PATH, TRSTCTL_TPM2_PROVIDER=1; an image with tpm2-openssl, tpm2-abrmd and nginx) is required")
	}
	ctx := context.Background()
	now := time.Now().UTC()
	dir := t.TempDir()

	// The host's attestation key: a TPM key, certified by the operator's
	// attestation CA, whose handle file and chain the host profile names.
	dev, err := tpm.OpenDevice(tpm.DeviceConfig{Path: sock, PersistentHandleBase: 0x8101c000})
	if err != nil {
		t.Fatal(err)
	}
	backend := tpm.New(dev)
	aik, _, err := crypto.GenerateEdgeCAKeyHandleAndCSR(ctx, "tpm-o1-journey-aik", "host key attestation key", crypto.ECDSAP256, backend)
	if err != nil {
		t.Fatalf("create the attestation key: %v", err)
	}
	_ = backend.Close()
	rootPEM, chainPEM, err := deviceattesttest.IssueAIKCertificate(aik.PublicKeyDER, now)
	if err != nil {
		t.Fatal(err)
	}
	aikJSON, err := json.Marshal(aik)
	if err != nil {
		t.Fatal(err)
	}
	aikPath, chainPath := filepath.Join(dir, "ak.json"), filepath.Join(dir, "ak-chain.pem")
	for path, body := range map[string][]byte{aikPath: aikJSON, chainPath: chainPEM} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := crypto.SelfSignedCACert(ca, "TPM-O1 journey CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// The lab's stand-in for the host kernel's TPM resource manager:
	// tpm2-abrmd on a private D-Bus session bus in front of swtpm (it takes
	// swtpm's one connection, now that the attestation key exists), and the
	// tpmrm bridge, which gives the agent its own tpm2-abrmd connection while
	// nginx's tpm2 provider holds another, as two clients of /dev/tpmrm0 have.
	bus := filepath.Join(dir, "bus")
	busEnv := "DBUS_SESSION_BUS_ADDRESS=unix:path=" + bus
	labOut, err := os.Create(filepath.Join(dir, "rm.out")) // #nosec G304 -- the test's own temp directory (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = labOut.Close() }()
	startLab := func(name string, args ...string) {
		t.Helper()
		cmd := exec.Command(name, args...) // #nosec G204,G702 -- the lab's own fixed tools and test paths (CWE-78)
		cmd.Env = append(os.Environ(), busEnv)
		cmd.Stdout, cmd.Stderr = labOut, labOut
		if err := cmd.Start(); err != nil {
			t.Fatalf("start %s: %v", name, err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	}
	waitLab := func(what string, ready func() bool) {
		t.Helper()
		for i := 0; i < 600; i++ {
			if ready() {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		raw, _ := os.ReadFile(filepath.Join(dir, "rm.out")) // #nosec G304 -- the test's own temp directory (CWE-22)
		t.Fatalf("%s did not come up\n%s", what, raw)
	}
	isSocket := func(path string) func() bool {
		return func() bool { fi, err := os.Stat(path); return err == nil && fi.Mode()&os.ModeSocket != 0 }
	}
	startLab("dbus-daemon", "--session", "--nofork", "--nopidfile", "--address=unix:path="+bus)
	waitLab("the D-Bus session bus", isSocket(bus))
	startLab("tpm2-abrmd", "--session", "--allow-root", "--tcti=swtpm:path="+sock)
	waitLab("tpm2-abrmd", func() bool {
		probe := exec.Command("tpm2_getrandom", "-T", "tabrmd:bus_type=session", "8") // #nosec G204 -- fixed tool and arguments (CWE-78)
		probe.Env = append(os.Environ(), busEnv)
		return probe.Run() == nil
	})
	bridge := os.Getenv("TRSTCTL_TPMRM_BRIDGE")
	if bridge == "" {
		t.Fatal("TRSTCTL_TPMRM_BRIDGE names the lab's tpmrm bridge (testdata/swtpm-hostkey)")
	}
	rmSock := filepath.Join(dir, "tpmrm.sock")
	startLab(bridge, rmSock, "tabrmd:bus_type=session")
	waitLab("the tpmrm bridge", isSocket(rmSock))

	// nginx as the Debian package runs it: the stock config path, pid file
	// and init script, one worker, serving a first TPM-held key the lab CA
	// certified.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	certPath, keyPath, sslConf := filepath.Join(dir, "web.crt"), filepath.Join(dir, "web.key"), filepath.Join(dir, "openssl.cnf")
	if err := os.WriteFile(sslConf, []byte(`openssl_conf = openssl_init
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
`), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := tpm.OpenDevice(tpm.DeviceConfig{Path: rmSock})
	if err != nil {
		t.Fatal(err)
	}
	firstHost := first.(tpm.HostKeyDevice)
	firstKey, firstPublic, err := firstHost.CreateHostKey()
	if err != nil {
		t.Fatalf("the first TPM-held key: %v", err)
	}
	firstCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "web.lab.test", DNSNames: []string{"web.lab.test"}},
		tpm.HostKeySigner(firstHost, firstKey, firstPublic))
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	firstChain, err := crypto.SignServerCertFromCSR(caDER, ca, firstCSR, []string{"web.lab.test"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	firstLeaf, _ := pem.Decode(firstChain)
	if firstLeaf == nil {
		t.Fatal("the first chain has no certificate")
	}
	for path, body := range map[string][]byte{certPath: firstChain, keyPath: firstKey} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	nginxConf := fmt.Sprintf(`user www-data;
worker_processes 1;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log info;
env OPENSSL_CONF;
env TPM2OPENSSL_TCTI;
env DBUS_SESSION_BUS_ADDRESS;
events { worker_connections 64; }
http {
  access_log off;
  server {
    listen %[1]s ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate %[2]s;
    ssl_certificate_key %[3]s;
    location / { return 200 "ok"; }
  }
}
`, addr, certPath, keyPath)
	if err := os.WriteFile("/etc/nginx/nginx.conf", []byte(nginxConf), 0o644); err != nil { // #nosec G306 -- the container's stock nginx config path, as the package installs it (CWE-276)
		t.Fatal(err)
	}
	service := func(action string) {
		t.Helper()
		cmd := exec.Command("/etc/init.d/nginx", action) // #nosec G204 -- the stock init script with a fixed action (CWE-78)
		// What a systemd drop-in's Environment= lines give nginx on a host.
		cmd.Env = append(os.Environ(), "OPENSSL_CONF="+sslConf, "TPM2OPENSSL_TCTI=tabrmd:bus_type=session", busEnv)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("/etc/init.d/nginx %s: %v\n%s", action, err, out)
		}
	}
	logs := func() string {
		var b strings.Builder
		for _, name := range []string{"/var/log/nginx/error.log", filepath.Join(dir, "rm.out")} {
			raw, _ := os.ReadFile(name) // #nosec G304 -- the container's nginx log and the test's own temp directory (CWE-22)
			fmt.Fprintf(&b, "== %s\n%s\n", name, raw)
		}
		return b.String()
	}
	service("start")
	t.Cleanup(func() {
		stop := exec.Command("/etc/init.d/nginx", "stop") // #nosec G204 -- the stock init script with a fixed action (CWE-78)
		_ = stop.Run()
	})
	if ok := journeyHandshakes(addr, 1, firstLeaf.Bytes); ok != 1 {
		time.Sleep(2 * time.Second)
		if journeyHandshakes(addr, 1, firstLeaf.Bytes) != 1 {
			t.Fatalf("nginx does not serve its first TPM-held key\n%s", logs())
		}
	}

	wrapper := filepath.Join(dir, "nginx-action")
	wrapperScript := []byte(fmt.Sprintf(`#!/bin/sh
# The operator's nginx action: nginx -t loads the TPM's key file through the
# tpm2 provider, which the agent's scrubbed environment does not name.
export OPENSSL_CONF=%s TPM2OPENSSL_TCTI=tabrmd:bus_type=session DBUS_SESSION_BUS_ADDRESS=unix:path=%s
exec /usr/sbin/nginx "$@"
`, sslConf, bus))
	if err := os.WriteFile(wrapper, wrapperScript, 0o755); err != nil { // #nosec G306,G703 -- the fixture IS an executable, in the test's own temp directory (CWE-276, CWE-22)
		t.Fatal(err)
	}
	profile := connector.LocalOpsConfig{
		AllowedRoots: []string{dir},
		Actions: []connector.LocalAction{
			{LogicalName: "nginx", Command: wrapper, PassArgs: true, Timeout: time.Minute},
			{LogicalName: "nginx-upgrade", Command: "/etc/init.d/nginx", Args: []string{"upgrade"}, Timeout: time.Minute},
		},
		HostKeyTPM: &connector.HostKeyTPMConfig{Path: rmSock, AttestationKey: aikPath, AttestationCertChain: chainPath},
	}
	targetConfig, err := json.Marshal(map[string]string{"cert_path": certPath, "key_path": keyPath})
	if err != nil {
		t.Fatal(err)
	}
	// The host's encrypted predecessor ledger, which the CA re-protection
	// below (TPM-O1-L1) pins its predecessor in, in its own directory.
	rollback, err := relay.NewHostRollbackStore(filepath.Join(t.TempDir(), "ledger"), "tenant-tpm-o1")
	if err != nil {
		t.Fatal(err)
	}
	renewal := func(jobID int64) relay.Job {
		job := renewJob(t, relay.DeployIntent{
			Connector: "nginx", Target: "web01", TargetID: "t-tpm-o1-journey",
			KeyCustody:        relay.HostKeyCustodyTPM,
			SubjectCommonName: "web.lab.test", SubjectDNSNames: []string{"web.lab.test"},
			TargetConfig: targetConfig, VerifyAddress: addr, VerifyServerName: "web.lab.test",
		})
		job.JobID = jobID
		return job
	}
	ch := &journeyChannel{rootPEM: rootPEM, ca: ca, caDER: caDER}
	ch.jobs = []relay.Job{renewal(77)}
	if _, err := relay.RunOnceWithSelfUpgradeAndHostRollback(ctx, ch, http.DefaultClient, profile, nil, nil, rollback, 4, 120); err != nil {
		t.Fatalf("RunOnceWithSelfUpgradeAndHostRollback: %v\n%s", err, logs())
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != transport.OutcomeVerified {
		t.Fatalf("reports = %+v, want one verified renewal\n%s", ch.reports, logs())
	}
	if ch.signCalls != 1 || len(ch.served) != 1 {
		t.Fatalf("signed %d CSRs", ch.signCalls)
	}
	if len(ch.custody) != 1 || ch.custody[0].Origin != custody.OriginDevice ||
		ch.custody[0].Storage != custody.StorageDeviceBound || ch.custody[0].Exportable != custody.NonExportable {
		t.Fatalf("custody = %+v, want device, device_bound, non_exportable", ch.custody)
	}
	key, err := os.ReadFile(keyPath) // #nosec G304 -- the test's own temp directory (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(key, []byte("-----BEGIN TSS2 PRIVATE KEY-----")) || bytes.Contains(key, []byte("BEGIN PRIVATE KEY")) || bytes.Contains(key, []byte("BEGIN EC PRIVATE KEY")) ||
		bytes.Equal(key, firstKey) {
		t.Fatalf("the installed key is not a new TPM key file:\n%s", key)
	}
	res, err := tlsprobe.Probe(ctx, addr, tlsprobe.WithTimeout(30*time.Second))
	if err != nil || len(res.PeerCertificates) == 0 || !bytes.Equal(res.PeerCertificates[0], ch.served[0]) {
		t.Fatalf("a separate client sees another certificate: %v\n%s", err, logs())
	}
	t.Logf("TPMO1_JOURNEY_OK fingerprint=%s tls_version=%#x", crypto.SHA256Hex(ch.served[0]), res.TLSVersion)

	// TPM-O1-L3: a renewal onto a new TPM key while a client handshakes
	// continuously. The upgrade's new master loads the key while the old one
	// finishes its connections, so no handshake fails.
	stopLoad := make(chan struct{})
	var handshakes, failures int
	var loadDone sync.WaitGroup
	loadDone.Add(1)
	go func() {
		defer loadDone.Done()
		for {
			select {
			case <-stopLoad:
				return
			default:
			}
			r, probeErr := tlsprobe.Probe(context.Background(), addr, tlsprobe.WithTimeout(30*time.Second))
			handshakes++
			if probeErr != nil || len(r.PeerCertificates) == 0 {
				failures++
			}
		}
	}()
	time.Sleep(time.Second)
	ch.jobs = []relay.Job{renewal(79)}
	_, renewErr := relay.RunOnceWithSelfUpgradeAndHostRollback(ctx, ch, http.DefaultClient, profile, nil, nil, rollback, 4, 120)
	time.Sleep(time.Second)
	close(stopLoad)
	loadDone.Wait()
	if renewErr != nil {
		t.Fatalf("the renewal under load: %v\n%s", renewErr, logs())
	}
	if len(ch.reports) != 2 || ch.reports[1].outcome != transport.OutcomeVerified || len(ch.served) != 2 {
		t.Fatalf("reports = %+v, want the renewal under load verified\n%s", ch.reports, logs())
	}
	if handshakes == 0 || failures != 0 {
		t.Fatalf("%d of %d handshakes failed across the renewal's re-execution of nginx\n%s", failures, handshakes, logs())
	}
	if ok := journeyHandshakes(addr, 8, ch.served[1]); ok != 8 {
		t.Fatalf("%d of 8 concurrent handshakes saw the renewed certificate\n%s", ok, logs())
	}
	t.Logf("TPMO1L3_RENEWAL_UNDER_LOAD_OK handshakes=%d failures=0 fingerprint=%s", handshakes, crypto.SHA256Hex(ch.served[1]))

	// TPM-O1-L1: a CA re-protection of that TPM-held key. The agent pins the
	// served predecessor (its key file's public key, read through the TPM,
	// is the certificate's), the TPM signs the re-protected CSR with the
	// retained key file and certifies the key again over the new job, the
	// control plane's check accepts that attestation and a successor CA
	// signs, and nginx, re-executed, serves the successor through the tpm2
	// provider with the same key file. No software key is made or read.
	predecessorKey, err := os.ReadFile(keyPath) // #nosec G304 -- the test's own temp directory (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	predecessor, err := certinfo.Inspect(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ch.served[1]}))
	if err != nil {
		t.Fatal(err)
	}
	successorCA, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer successorCA.Destroy()
	successorDER, err := crypto.SelfSignedCACert(successorCA, "TPM-O1-L1 successor CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ch.ca, ch.caDER = successorCA, successorDER
	reprotect := renewJob(t, relay.DeployIntent{
		Connector: "nginx", Target: "web01", TargetID: "t-tpm-o1-journey",
		KeyCustody:        relay.HostKeyCustodyTPM,
		SubjectCommonName: "web.lab.test", SubjectDNSNames: []string{"web.lab.test"},
		TargetConfig: targetConfig, VerifyAddress: addr, VerifyServerName: "web.lab.test",
		IdentityID: "identity-tpm-o1-l1", PredecessorCertificateID: "certificate-tpm-o1",
		IssuingAuthoritySource: "private", IssuingAuthorityID: "ca-tpm-o1-l1-successor",
		ReprotectJobID: "vdec-tpm-o1-l1", ReprotectPredecessorFingerprint: predecessor.SHA256Fingerprint,
		ReprotectPredecessorSPKISHA256: predecessor.SPKISHA256, ReprotectTTLSeconds: 3600,
	})
	reprotect.JobID = 78
	ch.jobs = []relay.Job{reprotect}
	if _, err := relay.RunOnceWithSelfUpgradeAndHostRollback(ctx, ch, http.DefaultClient, profile, nil, nil, rollback, 4, 120); err != nil {
		t.Fatalf("re-protection: %v\n%s", err, logs())
	}
	if len(ch.reports) != 3 || ch.reports[2].outcome != transport.OutcomeVerified {
		t.Fatalf("reports = %+v, want the re-protection verified\n%s", ch.reports, logs())
	}
	if ch.signCalls != 3 || len(ch.served) != 3 {
		t.Fatalf("signed %d CSRs, served %d certificates", ch.signCalls, len(ch.served))
	}
	successor, err := certinfo.Inspect(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ch.served[2]}))
	if err != nil {
		t.Fatal(err)
	}
	if successor.SPKISHA256 != predecessor.SPKISHA256 || successor.SHA256Fingerprint == predecessor.SHA256Fingerprint ||
		!strings.Contains(successor.Issuer, "TPM-O1-L1 successor CA") {
		t.Fatalf("successor %+v; want the predecessor's key under the successor CA", successor)
	}
	if len(ch.custody) != 3 || ch.custody[2].Origin != custody.OriginDevice ||
		ch.custody[2].Storage != custody.StorageDeviceBound || ch.custody[2].Exportable != custody.NonExportable {
		t.Fatalf("re-protection custody = %+v, want device, device_bound, non_exportable", ch.custody)
	}
	key, err = os.ReadFile(keyPath) // #nosec G304 -- the test's own temp directory (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, predecessorKey) {
		t.Fatal("the re-protection installed another key file than the TPM's retained one")
	}
	res, err = tlsprobe.Probe(ctx, addr, tlsprobe.WithTimeout(30*time.Second))
	if err != nil || len(res.PeerCertificates) == 0 || !bytes.Equal(res.PeerCertificates[0], ch.served[2]) {
		t.Fatalf("a separate client sees another certificate after the re-protection: %v\n%s", err, logs())
	}
	t.Logf("TPMO1L1_REPROTECT_OK fingerprint=%s spki=%s", successor.SHA256Fingerprint, successor.SPKISHA256)

	// TPM-O1-L3-L1: a containment stopped nginx, and the replacement deploy's
	// nginx-upgrade finds it stopped. Debian's init-script upgrade does not
	// start a stopped nginx, so the profile maps nginx-upgrade to the
	// documented script that starts a stopped nginx and re-executes a running
	// one; the init script reads the provider's config from /etc/default/nginx.
	defaults := fmt.Sprintf("export OPENSSL_CONF=%s TPM2OPENSSL_TCTI=tabrmd:bus_type=session %s\n", sslConf, busEnv)
	if err := os.WriteFile("/etc/default/nginx", []byte(defaults), 0o644); err != nil { // #nosec G306 -- the container's stock nginx defaults file (CWE-276)
		t.Fatal(err)
	}
	reexec := filepath.Join(dir, "nginx-upgrade")
	reexecScript := []byte(`#!/bin/sh
# nginx-upgrade: re-execute a running nginx, start a stopped one.
if [ -s /run/nginx.pid ] && kill -0 "$(cat /run/nginx.pid)" 2>/dev/null; then
  exec /etc/init.d/nginx upgrade
fi
exec /etc/init.d/nginx start
`)
	if err := os.WriteFile(reexec, reexecScript, 0o755); err != nil { // #nosec G306,G703 -- the fixture IS an executable, in the test's own temp directory (CWE-276, CWE-22)
		t.Fatal(err)
	}
	service("stop")
	for i := 0; i < 50 && journeyHandshakes(addr, 1, ch.served[2]) == 1; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if journeyHandshakes(addr, 1, ch.served[2]) == 1 {
		t.Fatal("nginx still serves after the stop")
	}
	profile.Actions[1] = connector.LocalAction{LogicalName: "nginx-upgrade", Command: reexec, Timeout: time.Minute}
	ch.jobs = []relay.Job{renewal(80)}
	if _, err := relay.RunOnceWithSelfUpgradeAndHostRollback(ctx, ch, http.DefaultClient, profile, nil, nil, rollback, 4, 120); err != nil {
		t.Fatalf("the renewal of a stopped nginx: %v\n%s", err, logs())
	}
	if len(ch.reports) != 4 || ch.reports[3].outcome != transport.OutcomeVerified || len(ch.served) != 4 {
		t.Fatalf("reports = %+v, want the renewal of the stopped nginx verified\n%s", ch.reports, logs())
	}
	if ok := journeyHandshakes(addr, 8, ch.served[3]); ok != 8 {
		t.Fatalf("%d of 8 concurrent handshakes saw the certificate the started nginx serves\n%s", ok, logs())
	}
	t.Logf("TPMO1L3L1_STOPPED_NGINX_STARTED_OK fingerprint=%s", crypto.SHA256Hex(ch.served[3]))
}
