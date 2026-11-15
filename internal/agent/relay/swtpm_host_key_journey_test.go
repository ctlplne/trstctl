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
	"strconv"
	"strings"
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
func TestSwtpmHostRenewalJourneyTPMO1(t *testing.T) {
	sock := os.Getenv("TRSTCTL_SWTPM_PATH")
	if sock == "" || os.Getenv("TRSTCTL_TPM2_PROVIDER") != "1" {
		t.Skip("TRSTCTL_SWTPM_PATH and TRSTCTL_TPM2_PROVIDER=1 (an image with tpm2-openssl, tpm2-abrmd and nginx) are required")
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

	// nginx as the host runs it, behind the lab's stand-in for a host
	// kernel's /dev/tpmrm0: the "nginx" action starts tpm2-abrmd in front of
	// swtpm on first use (trstctl's own TPM work is done by then: the
	// resource manager takes swtpm's one connection), checks the config and,
	// for a reload, restarts the lab's single-process nginx on the new files.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	certPath, keyPath := filepath.Join(dir, "web.crt"), filepath.Join(dir, "web.key")
	confPath, sslConf := filepath.Join(dir, "nginx.conf"), filepath.Join(dir, "openssl.cnf")
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
	nginxConf := fmt.Sprintf(`daemon off;
master_process off;
worker_processes 1;
error_log %[1]s/error.log info;
pid %[1]s/nginx.pid;
env OPENSSL_CONF;
env TPM2OPENSSL_TCTI;
env DBUS_SESSION_BUS_ADDRESS;
events { worker_connections 16; }
http {
  access_log off;
  client_body_temp_path %[1]s;
  server {
    listen 127.0.0.1:%[2]d ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate %[3]s;
    ssl_certificate_key %[4]s;
    location / { return 200 "ok"; }
  }
}
`, dir, port, certPath, keyPath)
	if err := os.WriteFile(confPath, []byte(nginxConf), 0o600); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(dir, "nginx-action")
	script := fmt.Sprintf(`#!/bin/sh
set -eu
D=%[1]s
export OPENSSL_CONF=$D/openssl.cnf TPM2OPENSSL_TCTI=tabrmd:bus_type=session DBUS_SESSION_BUS_ADDRESS=unix:path=$D/bus
if ! /usr/bin/tpm2_getrandom -T tabrmd:bus_type=session 8 >/dev/null 2>&1; then
  /usr/bin/dbus-daemon --session --nofork --nopidfile --address=unix:path=$D/bus </dev/null >>$D/rm.out 2>&1 &
  echo $! >$D/dbus.pid
  i=0; until [ -S $D/bus ]; do i=$((i+1)); [ $i -lt 600 ] || exit 3; sleep 0.1; done
  /usr/sbin/tpm2-abrmd --session --allow-root --tcti=swtpm:path=%[2]s </dev/null >>$D/rm.out 2>&1 &
  echo $! >$D/abrmd.pid
  i=0; until /usr/bin/tpm2_getrandom -T tabrmd:bus_type=session 8 >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 600 ] || exit 4; sleep 0.1; done
fi
case "$1" in
-t) exec /usr/sbin/nginx -t -c %[3]s -p $D ;;
-s)
  if [ -f $D/nginx.pid ]; then kill "$(cat $D/nginx.pid)" 2>/dev/null || true; sleep 0.5; fi
  /usr/sbin/nginx -c %[3]s -p $D </dev/null >>$D/nginx.out 2>&1 &
  exit 0 ;;
esac
exit 2
`, dir, sock, confPath)
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil { // #nosec G306,G703 -- the fixture IS an executable, in the test's own temp directory (CWE-276, CWE-22)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, name := range []string{"nginx.pid", "abrmd.pid", "dbus.pid"} {
			if raw, err := os.ReadFile(filepath.Join(dir, name)); err == nil { // #nosec G304 -- the test's own temp directory (CWE-22)
				if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil {
					if p, err := os.FindProcess(pid); err == nil {
						_ = p.Kill()
					}
				}
			}
		}
	})
	logs := func() string {
		var b strings.Builder
		for _, name := range []string{"error.log", "nginx.out", "rm.out"} {
			raw, _ := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- the test's own temp directory (CWE-22)
			fmt.Fprintf(&b, "== %s\n%s\n", name, raw)
		}
		return b.String()
	}

	profile := connector.LocalOpsConfig{
		AllowedRoots: []string{dir},
		Actions:      []connector.LocalAction{{LogicalName: "nginx", Command: wrapper, PassArgs: true, Timeout: time.Minute}},
		HostKeyTPM:   &connector.HostKeyTPMConfig{Path: sock, AttestationKey: aikPath, AttestationCertChain: chainPath},
	}
	targetConfig, err := json.Marshal(map[string]string{"cert_path": certPath, "key_path": keyPath})
	if err != nil {
		t.Fatal(err)
	}
	// The host's encrypted predecessor ledger, which the CA re-protection
	// below (TPM-O1-L1) pins its predecessor in. Its own directory: nginx
	// gives its temp path (dir) to its worker user, and the ledger refuses a
	// parent directory another user owns.
	rollback, err := relay.NewHostRollbackStore(filepath.Join(t.TempDir(), "ledger"), "tenant-tpm-o1")
	if err != nil {
		t.Fatal(err)
	}
	ch := &journeyChannel{rootPEM: rootPEM, ca: ca, caDER: caDER}
	ch.jobs = []relay.Job{renewJob(t, relay.DeployIntent{
		Connector: "nginx", Target: "web01", TargetID: "t-tpm-o1-journey",
		KeyCustody:        relay.HostKeyCustodyTPM,
		SubjectCommonName: "web.lab.test", SubjectDNSNames: []string{"web.lab.test"},
		TargetConfig:  targetConfig,
		VerifyAddress: fmt.Sprintf("127.0.0.1:%d", port), VerifyServerName: "web.lab.test",
	})}
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
	if !bytes.Contains(key, []byte("-----BEGIN TSS2 PRIVATE KEY-----")) || bytes.Contains(key, []byte("BEGIN PRIVATE KEY")) || bytes.Contains(key, []byte("BEGIN EC PRIVATE KEY")) {
		t.Fatalf("the installed key is not the TPM's key file:\n%s", key)
	}
	res, err := tlsprobe.Probe(ctx, fmt.Sprintf("127.0.0.1:%d", port), tlsprobe.WithTimeout(30*time.Second))
	if err != nil || len(res.PeerCertificates) == 0 || !bytes.Equal(res.PeerCertificates[0], ch.served[0]) {
		t.Fatalf("a separate client sees another certificate: %v\n%s", err, logs())
	}
	t.Logf("TPMO1_JOURNEY_OK fingerprint=%s tls_version=%#x", crypto.SHA256Hex(ch.served[0]), res.TLSVersion)

	// TPM-O1-L1: a CA re-protection of that TPM-held key. nginx now holds
	// tpm2-abrmd's connection to swtpm, as it would hold the kernel's
	// /dev/tpmrm0, so the agent reaches the same TPM through the lab's
	// tpmrm bridge, its own tpm2-abrmd connection. The agent pins the
	// served predecessor (its key file's public key, read through the TPM,
	// is the certificate's), the TPM signs the re-protected CSR with the
	// retained key file and certifies the key again over the new job, the
	// control plane's check accepts that attestation and a successor CA
	// signs, and nginx serves the successor through the tpm2 provider with
	// the same key file. No software key is made or read.
	bridge := os.Getenv("TRSTCTL_TPMRM_BRIDGE")
	if bridge == "" {
		t.Fatal("TRSTCTL_TPMRM_BRIDGE names the lab's tpmrm bridge (testdata/swtpm-hostkey)")
	}
	rmSock := filepath.Join(dir, "tpmrm.sock")
	rm := exec.Command(bridge, rmSock, "tabrmd:bus_type=session") // #nosec G204,G702 -- the harness names the lab's own bridge binary (CWE-78)
	rm.Env = append(os.Environ(), "DBUS_SESSION_BUS_ADDRESS=unix:path="+filepath.Join(dir, "bus"))
	rm.Stdout, rm.Stderr = os.Stderr, os.Stderr
	if err := rm.Start(); err != nil {
		t.Fatalf("start the tpmrm bridge: %v", err)
	}
	t.Cleanup(func() { _ = rm.Process.Kill(); _, _ = rm.Process.Wait() })
	for i := 0; i < 100; i++ {
		if fi, err := os.Stat(rmSock); err == nil && fi.Mode()&os.ModeSocket != 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	predecessorKey, err := os.ReadFile(keyPath) // #nosec G304 -- the test's own temp directory (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	predecessor, err := certinfo.Inspect(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ch.served[0]}))
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
		TargetConfig:  targetConfig,
		VerifyAddress: fmt.Sprintf("127.0.0.1:%d", port), VerifyServerName: "web.lab.test",
		IdentityID: "identity-tpm-o1-l1", PredecessorCertificateID: "certificate-tpm-o1",
		IssuingAuthoritySource: "private", IssuingAuthorityID: "ca-tpm-o1-l1-successor",
		ReprotectJobID: "vdec-tpm-o1-l1", ReprotectPredecessorFingerprint: predecessor.SHA256Fingerprint,
		ReprotectPredecessorSPKISHA256: predecessor.SPKISHA256, ReprotectTTLSeconds: 3600,
	})
	reprotect.JobID = 78
	ch.jobs = []relay.Job{reprotect}
	profile.HostKeyTPM.Path = rmSock
	if _, err := relay.RunOnceWithSelfUpgradeAndHostRollback(ctx, ch, http.DefaultClient, profile, nil, nil, rollback, 4, 120); err != nil {
		t.Fatalf("re-protection: %v\n%s", err, logs())
	}
	if len(ch.reports) != 2 || ch.reports[1].outcome != transport.OutcomeVerified {
		t.Fatalf("reports = %+v, want the re-protection verified\n%s", ch.reports, logs())
	}
	if ch.signCalls != 2 || len(ch.served) != 2 {
		t.Fatalf("signed %d CSRs, served %d certificates", ch.signCalls, len(ch.served))
	}
	successor, err := certinfo.Inspect(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ch.served[1]}))
	if err != nil {
		t.Fatal(err)
	}
	if successor.SPKISHA256 != predecessor.SPKISHA256 || successor.SHA256Fingerprint == predecessor.SHA256Fingerprint ||
		!strings.Contains(successor.Issuer, "TPM-O1-L1 successor CA") {
		t.Fatalf("successor %+v; want the predecessor's key under the successor CA", successor)
	}
	if len(ch.custody) != 2 || ch.custody[1].Origin != custody.OriginDevice ||
		ch.custody[1].Storage != custody.StorageDeviceBound || ch.custody[1].Exportable != custody.NonExportable {
		t.Fatalf("re-protection custody = %+v, want device, device_bound, non_exportable", ch.custody)
	}
	key, err = os.ReadFile(keyPath) // #nosec G304 -- the test's own temp directory (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, predecessorKey) {
		t.Fatal("the re-protection installed another key file than the TPM's retained one")
	}
	res, err = tlsprobe.Probe(ctx, fmt.Sprintf("127.0.0.1:%d", port), tlsprobe.WithTimeout(30*time.Second))
	if err != nil || len(res.PeerCertificates) == 0 || !bytes.Equal(res.PeerCertificates[0], ch.served[1]) {
		t.Fatalf("a separate client sees another certificate after the re-protection: %v\n%s", err, logs())
	}
	t.Logf("TPMO1L1_REPROTECT_OK fingerprint=%s spki=%s", successor.SHA256Fingerprint, successor.SPKISHA256)
}
