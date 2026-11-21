// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/kms/tpm"
)

// softwareHostKeyTPM stands in for the host's TPM in a unit test: it makes a
// software P-256 key per host key file and signs with it. It never certifies;
// the test injects the attestation, and the swtpm journey runs the real one.
type softwareHostKeyTPM struct {
	mu      sync.Mutex
	keys    map[string]*crypto.LockedSigner
	created int
}

func (d *softwareHostKeyTPM) CreateHostKey() ([]byte, []byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return nil, nil, err
	}
	d.created++
	file, err := tpm.EncodeTSS2PrivateKey(tpm.HostSRKHandle, []byte("public-area-"+strconv.Itoa(d.created)), []byte("wrapped-private"))
	if err != nil {
		return nil, nil, err
	}
	if d.keys == nil {
		d.keys = map[string]*crypto.LockedSigner{}
	}
	d.keys[string(file)] = signer
	return file, append([]byte(nil), signer.Public().DER...), nil
}

func (d *softwareHostKeyTPM) key(file []byte) (*crypto.LockedSigner, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	signer, ok := d.keys[string(file)]
	if !ok {
		return nil, errors.New("software TPM: no such host key file")
	}
	return signer, nil
}

func (d *softwareHostKeyTPM) SignWithHostKey(file, digest []byte) ([]byte, error) {
	signer, err := d.key(file)
	if err != nil {
		return nil, err
	}
	return signer.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256})
}

func (d *softwareHostKeyTPM) CertifyHostKey([]byte, string, []byte, []byte) (crypto.EdgeTPMCertification, error) {
	return crypto.EdgeTPMCertification{}, errors.New("software TPM: certification is injected by the test")
}

func (d *softwareHostKeyTPM) HostKeyPublicDER(file []byte) ([]byte, error) {
	signer, err := d.key(file)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), signer.Public().DER...), nil
}

// attestedRenewChannel is a renewChannel that also takes the TPM's
// attestation with the CSR.
type attestedRenewChannel struct {
	renewChannel
	attestations [][]byte
}

func (r *attestedRenewChannel) SignJobCSRWithKeyAttestation(ctx context.Context, jobID int64, attempt int, csrDER, attestation []byte) ([]byte, []byte, string, error) {
	r.attestations = append(r.attestations, append([]byte(nil), attestation...))
	return r.SignJobCSR(ctx, jobID, attempt, csrDER)
}

// tpmRenewProfile is a host profile whose nginx and nginx-upgrade actions
// record their arguments in dir/actions.log; withTPM names the host's TPM.
func tpmActionFixture(t *testing.T, dir, name string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		// The host-action boundary accepts native .exe files on Windows. Build
		// one owned test program instead of presenting a Unix shell script as
		// an executable; it records exactly the same action name and argv.
		source := filepath.Join(dir, "action.go")
		program := `package main
import ("fmt"; "os"; "path/filepath"; "strings")
func main() {
 f, err := os.OpenFile(filepath.Join(filepath.Dir(os.Args[0]), "actions.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
 if err != nil { os.Exit(1) }
 defer f.Close()
 name := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
 if _, err := fmt.Fprintf(f, "%s %s\n", name, strings.Join(os.Args[1:], " ")); err != nil { os.Exit(1) }
}`
		if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name+".exe")
		if out, err := exec.Command("go", "build", "-trimpath", "-o", path, source).CombinedOutput(); err != nil { // #nosec G204 -- fixed Go tool compiles this test's owned source and output (CWE-78)
			t.Fatalf("build native action fixture: %v: %s", err, out)
		}
		return path
	}
	path := filepath.Join(dir, name)
	script := []byte("#!/bin/sh\necho \"$(basename \"$0\") $*\" >> " + filepath.Join(dir, "actions.log") + "\nexit 0\n")
	if err := os.WriteFile(path, script, 0o755); err != nil { // #nosec G306,G703 -- owned executable fixture (CWE-276, CWE-22)
		t.Fatal(err)
	}
	return path
}

func tpmRenewProfile(t *testing.T, dir string, withTPM bool) connector.LocalOpsConfig {
	t.Helper()
	nginx := tpmActionFixture(t, dir, "nginx")
	upgrade := tpmActionFixture(t, dir, "nginx-upgrade")
	profile := connector.LocalOpsConfig{AllowedRoots: []string{dir},
		Actions: []connector.LocalAction{{LogicalName: "nginx", Command: nginx, PassArgs: true},
			{LogicalName: "nginx-upgrade", Command: upgrade}}}
	if withTPM {
		profile.HostKeyTPM = &connector.HostKeyTPMConfig{AttestationKey: filepath.Join(dir, "ak.json"), AttestationCertChain: filepath.Join(dir, "ak.pem")}
	}
	return profile
}

func tpmRenewIntent(t *testing.T, dir, connectorName string) relay.DeployIntent {
	t.Helper()
	return relay.DeployIntent{
		Connector: connectorName, Target: "web01", TargetID: "t-web01",
		KeyCustody:        relay.HostKeyCustodyTPM,
		SubjectCommonName: "web.example.test", SubjectDNSNames: []string{"web.example.test"},
		TargetConfig: renewTargetConfig(t, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")),
	}
}

// TestTPMHostRenewalMakesTheKeyInTheTPMAndSendsItsAttestationTPMO1: a renewal
// whose profile requires a TPM-held key has the TPM make the key and sign the
// CSR, sends the TPM's attestation of that key for this job with the CSR, and
// installs the TPM's key file: no software private key exists on the host or
// in the request, and the receipt claims a device-origin, device-bound,
// non-exportable key.
func TestTPMHostRenewalMakesTheKeyInTheTPMAndSendsItsAttestationTPMO1(t *testing.T) {
	dev := &softwareHostKeyTPM{}
	var attested []string
	restore := relay.SetHostKeyTPMForTest(dev, func(jobID int64, file, csrDER []byte) ([]byte, error) {
		attested = append(attested, strconv.FormatInt(jobID, 10))
		if !bytes.Contains(file, []byte("BEGIN TSS2 PRIVATE KEY")) {
			t.Errorf("the attestation was asked for a key that is not a TPM key file:\n%s", file)
		}
		return []byte("tpm-attestation-for-job-" + strconv.FormatInt(jobID, 10)), nil
	})
	defer restore()
	dir := t.TempDir()
	ch := &attestedRenewChannel{renewChannel: renewChannel{certPEM: []byte("ISSUED-LEAF\n"), chainPEM: []byte("ISSUER\n"), fpr: "sha256:issued"}}
	ch.jobs = []relay.Job{renewJob(t, tpmRenewIntent(t, dir, "nginx"))}

	if _, err := relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient, tpmRenewProfile(t, dir, true), 4, 60); err != nil {
		t.Fatalf("RunOnceWithHost: %v", err)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome == relay.OutcomeFailed {
		t.Fatalf("reports = %+v", ch.reports)
	}
	if dev.created != 1 || len(ch.signed) != 1 || len(ch.attestations) != 1 ||
		string(ch.attestations[0]) != "tpm-attestation-for-job-77" || strings.Join(attested, ",") != "77" {
		t.Fatalf("created %d keys, signed %d CSRs with attestations %q (asked for jobs %v)", dev.created, len(ch.signed), ch.attestations, attested)
	}
	csr, err := crypto.InspectCSR(ch.signed[0])
	if err != nil || csr.KeyAlgorithm != "ECDSA" || csr.KeyBits != 256 {
		t.Fatalf("CSR %+v: %v", csr, err)
	}
	var tpmPublic []byte
	for _, signer := range dev.keys {
		tpmPublic = signer.Public().DER
	}
	if !bytes.Contains(ch.signed[0], tpmPublic) {
		t.Fatal("the CSR does not carry the TPM's key")
	}
	installed, err := os.ReadFile(filepath.Join(dir, "key.pem")) // #nosec G304 -- the test's own temp directory (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(installed, []byte("-----BEGIN TSS2 PRIVATE KEY-----")) ||
		bytes.Contains(installed, []byte("BEGIN PRIVATE KEY")) || bytes.Contains(installed, []byte("BEGIN EC PRIVATE KEY")) {
		t.Fatalf("the installed key is not the TPM's key file:\n%s", installed)
	}
	if len(ch.custody) != 1 || ch.custody[0].Origin != custody.OriginDevice ||
		ch.custody[0].Storage != custody.StorageDeviceBound || ch.custody[0].Exportable != custody.NonExportable {
		t.Fatalf("custody = %+v, want device, device_bound, non_exportable", ch.custody)
	}
}

// TestTPMHostRenewalIsRefusedBeforeAnyKeyWhenTheHostCannotHoldItTPMO1: a
// renewal that requires a TPM-held key, on a host whose profile names no TPM,
// for a connector that cannot install one, for a key the TPM cannot hold, or
// through a channel that cannot send an attestation, or that names a custody
// no agent provides, is refused with its reason before the TPM makes a key
// and before anything is signed or written.
func TestTPMHostRenewalIsRefusedBeforeAnyKeyWhenTheHostCannotHoldItTPMO1(t *testing.T) {
	dev := &softwareHostKeyTPM{}
	restore := relay.SetHostKeyTPMForTest(dev, func(int64, []byte, []byte) ([]byte, error) {
		t.Error("an attestation was asked for")
		return nil, errors.New("unexpected")
	})
	defer restore()
	for _, tc := range []struct {
		name      string
		withTPM   bool
		plain     bool
		mutate    func(*relay.DeployIntent)
		wantText  string
		noUpgrade bool
	}{
		{"no TPM in the host profile", false, false, nil, "names no host_key_tpm", false},
		// TPM-O1-L3: nginx must be re-executed to serve a TPM-held key.
		{"an nginx host profile with no nginx-upgrade action", true, false, nil, "needs the host profile's nginx-upgrade action", true},
		{"a connector that converts the key", true, false, func(i *relay.DeployIntent) { i.Connector = "apache" }, "installed only for nginx", false},
		{"a key the TPM cannot hold", true, false, func(i *relay.DeployIntent) { i.SubjectKeyAlgorithm = "RSA-2048" }, "ECDSA P-256", false},
		{"a channel that cannot send an attestation", true, true, nil, "cannot send a TPM key attestation", false},
		{"a custody no agent provides", true, false, func(i *relay.DeployIntent) { i.KeyCustody = "hsm" }, "which this agent does not provide", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			intent := tpmRenewIntent(t, dir, "nginx")
			if tc.mutate != nil {
				tc.mutate(&intent)
			}
			var ch relay.Channel
			var signCalls func() int
			var reports func() []report
			if tc.plain {
				plain := &renewChannel{certPEM: []byte("ISSUED-LEAF\n"), fpr: "sha256:issued"}
				plain.jobs = []relay.Job{renewJob(t, intent)}
				ch, signCalls, reports = plain, func() int { return plain.signCalls }, func() []report { return plain.reports }
			} else {
				attested := &attestedRenewChannel{renewChannel: renewChannel{certPEM: []byte("ISSUED-LEAF\n"), fpr: "sha256:issued"}}
				attested.jobs = []relay.Job{renewJob(t, intent)}
				ch, signCalls, reports = attested, func() int { return attested.signCalls }, func() []report { return attested.reports }
			}
			before := dev.created
			profile := tpmRenewProfile(t, dir, tc.withTPM)
			if tc.noUpgrade {
				profile.Actions = profile.Actions[:1]
			}
			if _, err := relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient, profile, 4, 60); err != nil {
				t.Fatalf("RunOnceWithHost: %v", err)
			}
			got := reports()
			if len(got) != 1 || got[0].outcome != relay.OutcomeFailed || !strings.Contains(got[0].detail, tc.wantText) {
				t.Fatalf("reports = %+v, want a failure naming %q", got, tc.wantText)
			}
			if dev.created != before || signCalls() != 0 {
				t.Fatalf("the TPM made %d keys and %d CSRs were signed before the refusal", dev.created-before, signCalls())
			}
			if _, err := os.Stat(filepath.Join(dir, "key.pem")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a key file was written: %v", err)
			}
		})
	}
}

// TestTPMHostKeyCustodyIsDeviceBoundTPMO1: the receipt a TPM-held key's
// renewal sends, and the control plane expects, names a key generated on a
// device that will not export it (device origin, device-bound,
// non-exportable); a custody the agent does not know is an error.
func TestTPMHostKeyCustodyIsDeviceBoundTPMO1(t *testing.T) {
	record, err := relay.HostRenewCustody("nginx", relay.HostKeyCustodyTPM, "host-agent-7")
	if err != nil || !record.Complete() || record.Origin != custody.OriginDevice || record.Storage != custody.StorageDeviceBound ||
		record.Exportable != custody.NonExportable || record.GeneratedBy != "host-agent-7" {
		t.Fatalf("TPM custody = %+v: %v", record, err)
	}
	if _, err := relay.HostRenewCustody("nginx", "hsm", "host-agent-7"); err == nil {
		t.Fatal("an unknown host key custody was classified")
	}
}

// TestHostKeyTPMProfileNeedsItsAttestationFilesTPMO1: the host profile's
// host_key_tpm names the attestation key's handle and chain by absolute path,
// beside the roots its key files are written in.
func TestHostKeyTPMProfileNeedsItsAttestationFilesTPMO1(t *testing.T) {
	dir := t.TempDir()
	write := func(profile map[string]any) string {
		raw, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "profile.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	device, attestationKey, attestationChain := filepath.Join(dir, "tpmrm0"), filepath.Join(dir, "ak.json"), filepath.Join(dir, "ak.pem")
	good := map[string]any{"tpm_path": device, "attestation_key": attestationKey, "attestation_cert_chain": attestationChain}
	loaded, err := relay.LoadHostProfile(write(map[string]any{"allowed_roots": []string{dir}, "host_key_tpm": good}))
	if err != nil || loaded.HostKeyTPM == nil || loaded.HostKeyTPM.AttestationKey != attestationKey || loaded.HostKeyTPM.Path != device {
		t.Fatalf("loaded %+v: %v", loaded.HostKeyTPM, err)
	}
	for _, tc := range []struct {
		name    string
		profile map[string]any
		want    string
	}{
		{"no attestation chain", map[string]any{"allowed_roots": []string{dir}, "host_key_tpm": map[string]any{"attestation_key": attestationKey}}, "needs attestation_key and attestation_cert_chain"},
		{"a relative path", map[string]any{"allowed_roots": []string{dir}, "host_key_tpm": map[string]any{"attestation_key": "ak.json", "attestation_cert_chain": attestationChain}}, "is not absolute"},
		{"no roots", map[string]any{"kubernetes_secrets": map[string]any{"namespaces": []string{"web"}}, "host_key_tpm": good}, "must name the allowed roots"},
	} {
		if _, err := relay.LoadHostProfile(write(tc.profile)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}

// TestTPMHostRenewalReexecutesNginxInsteadOfReloadingItTPMO1L3: a renewal
// with a TPM-held key checks nginx's configuration and then runs the host
// profile's nginx-upgrade action, which re-executes nginx so a fresh master
// loads the key; it never reloads nginx in place, which with OpenSSL's tpm2
// provider leaves nginx failing its handshakes or serving the previous
// certificate. A renewal of a software key on the same profile reloads as
// before.
func TestTPMHostRenewalReexecutesNginxInsteadOfReloadingItTPMO1L3(t *testing.T) {
	dev := &softwareHostKeyTPM{}
	restore := relay.SetHostKeyTPMForTest(dev, func(jobID int64, _, _ []byte) ([]byte, error) {
		return []byte("tpm-attestation-for-job-" + strconv.FormatInt(jobID, 10)), nil
	})
	defer restore()
	for _, tc := range []struct {
		name    string
		custody string
		want    string
	}{
		{"a TPM-held key", relay.HostKeyCustodyTPM, "nginx -t\nnginx-upgrade \n"},
		{"a software key", "", "nginx -t\nnginx -s reload\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			intent := tpmRenewIntent(t, dir, "nginx")
			intent.KeyCustody = tc.custody
			ch := &attestedRenewChannel{renewChannel: renewChannel{certPEM: []byte("ISSUED-LEAF\n"), chainPEM: []byte("ISSUER\n"), fpr: "sha256:issued"}}
			ch.jobs = []relay.Job{renewJob(t, intent)}
			if _, err := relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient, tpmRenewProfile(t, dir, true), 4, 60); err != nil {
				t.Fatalf("RunOnceWithHost: %v", err)
			}
			if len(ch.reports) != 1 || ch.reports[0].outcome == relay.OutcomeFailed {
				t.Fatalf("reports = %+v", ch.reports)
			}
			ran, err := os.ReadFile(filepath.Join(dir, "actions.log")) // #nosec G304 -- the test's own temp directory (CWE-22)
			if err != nil {
				t.Fatal(err)
			}
			if string(ran) != tc.want {
				t.Fatalf("the deploy ran:\n%s\nwant:\n%s", ran, tc.want)
			}
		})
	}
}

// TestHostDryRunPlansTheNginxReexecForATPMHeldKeyTPMO1L3: a connector test of
// an nginx target whose key is TPM-held plans nginx -t and the host profile's
// nginx-upgrade action, not an in-place reload, and is not ready on a profile
// that does not map nginx-upgrade; a software key's plan still reloads.
func TestHostDryRunPlansTheNginxReexecForATPMHeldKeyTPMO1L3(t *testing.T) {
	root := t.TempDir()
	certPath, keyPath := filepath.Join(root, "site.crt"), filepath.Join(root, "site.key")
	for _, path := range []string{certPath, keyPath} {
		if err := os.WriteFile(path, []byte("bootstrap"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plan := func(custody string, actions ...connector.LocalAction) relay.Plan {
		t.Helper()
		p, err := relay.DryRunOnHost(context.Background(), http.DefaultClient,
			connector.LocalOpsConfig{AllowedRoots: []string{root}, Actions: actions},
			relay.DeployIntent{Connector: "nginx", Target: "web", KeyCustody: custody,
				TargetConfig: mustJSON(t, map[string]string{"cert_path": certPath, "key_path": keyPath})}, nil)
		if err != nil {
			t.Fatalf("host dry-run: %v", err)
		}
		return p
	}
	mutates := func(p relay.Plan) string { return strings.Join(p.WouldMutate, "\n") }
	tpmPlan := plan(relay.HostKeyCustodyTPM, trueAction("nginx", true), trueAction("nginx-upgrade", false))
	if !tpmPlan.Ready || !strings.Contains(mutates(tpmPlan), "run operator-approved nginx-upgrade") || strings.Contains(mutates(tpmPlan), "-s reload") {
		t.Fatalf("TPM-held plan = %+v", tpmPlan)
	}
	if missing := plan(relay.HostKeyCustodyTPM, trueAction("nginx", true)); missing.Ready {
		t.Fatalf("a TPM-held plan without nginx-upgrade in the profile is ready: %+v", missing)
	}
	softwarePlan := plan("", trueAction("nginx", true))
	if !softwarePlan.Ready || !strings.Contains(mutates(softwarePlan), "run operator-approved nginx -s reload") {
		t.Fatalf("software plan = %+v", softwarePlan)
	}
}

// tpmServiceProfile is a host profile whose actions, one per logical name,
// record their arguments in dir/actions.log, with the host's TPM named.
func tpmServiceProfile(t *testing.T, dir string, names ...string) connector.LocalOpsConfig {
	t.Helper()
	profile := connector.LocalOpsConfig{AllowedRoots: []string{dir},
		HostKeyTPM: &connector.HostKeyTPMConfig{AttestationKey: filepath.Join(dir, "ak.json"), AttestationCertChain: filepath.Join(dir, "ak.pem")}}
	for _, name := range names {
		profile.Actions = append(profile.Actions, connector.LocalAction{LogicalName: name, Command: tpmActionFixture(t, dir, name), PassArgs: true})
	}
	return profile
}

// TestTPMHeldKeysAreInstalledForHAProxyWithOneThreadAndForPostfixTPMO1L2:
// haproxy and postfix with dovecot take a TPM-held key, each proven against
// its stock package with the tpm2 provider. haproxy's threads share the
// provider's one TPM context, so the agent reads its config_path inside the
// profile's allowed roots and refuses, before any key exists, a configuration
// whose global section does not set nbthread 1 (or that it cannot read); with
// it, the renewal makes the key in the TPM and runs haproxy's check and
// reload. A postfix renewal installs the key for both services and reloads
// both. apache is still refused.
func TestTPMHeldKeysAreInstalledForHAProxyWithOneThreadAndForPostfixTPMO1L2(t *testing.T) {
	dev := &softwareHostKeyTPM{}
	restore := relay.SetHostKeyTPMForTest(dev, func(jobID int64, _, _ []byte) ([]byte, error) {
		return []byte("tpm-attestation-for-job-" + strconv.FormatInt(jobID, 10)), nil
	})
	defer restore()
	run := func(t *testing.T, dir string, intent relay.DeployIntent, profile connector.LocalOpsConfig) ([]report, int) {
		t.Helper()
		ch := &attestedRenewChannel{renewChannel: renewChannel{certPEM: []byte("ISSUED-LEAF\n"), chainPEM: []byte("ISSUER\n"), fpr: "sha256:issued"}}
		ch.jobs = []relay.Job{renewJob(t, intent)}
		if _, err := relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient, profile, 4, 60); err != nil {
			t.Fatalf("RunOnceWithHost: %v", err)
		}
		return ch.reports, ch.signCalls
	}
	haproxyIntent := func(t *testing.T, dir, config string) relay.DeployIntent {
		t.Helper()
		configPath := filepath.Join(dir, "haproxy.cfg")
		if config != "" {
			if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		intent := tpmRenewIntent(t, dir, "haproxy")
		intent.TargetConfig = mustJSON(t, map[string]string{"crt_path": filepath.Join(dir, "web.pem"), "config_path": configPath})
		return intent
	}
	for _, tc := range []struct {
		name, config, want string
	}{
		{"no nbthread", "global\n  log stderr local0\nfrontend fe\n  bind :443 ssl crt /x\n", "needs nbthread 1 in its global section"},
		{"four threads", "global\n  nbthread 4\n", "needs nbthread 1 in its global section"},
		{"nbthread 1 outside global", "global\n  maxconn 10\ndefaults\n  nbthread 1\n", "needs nbthread 1 in its global section"},
		{"an unreadable config_path", "", "needs its config_path readable inside the host profile's allowed roots"},
	} {
		t.Run("haproxy refused: "+tc.name, func(t *testing.T) {
			dir := t.TempDir()
			before := dev.created
			reports, signed := run(t, dir, haproxyIntent(t, dir, tc.config), tpmServiceProfile(t, dir, "haproxy", "systemctl"))
			if len(reports) != 1 || reports[0].outcome != relay.OutcomeFailed || !strings.Contains(reports[0].detail, tc.want) {
				t.Fatalf("reports = %+v, want a failure naming %q", reports, tc.want)
			}
			if dev.created != before || signed != 0 {
				t.Fatal("the TPM made a key or a CSR was signed before the refusal")
			}
		})
	}
	t.Run("haproxy with nbthread 1", func(t *testing.T) {
		dir := t.TempDir()
		config := "# trstctl-managed\nglobal\n  nbthread 2\n  nbthread 1 # one thread for the TPM-held key\ndefaults\n  mode http\n"
		reports, signed := run(t, dir, haproxyIntent(t, dir, config), tpmServiceProfile(t, dir, "haproxy", "systemctl"))
		if len(reports) != 1 || reports[0].outcome == relay.OutcomeFailed || signed != 1 {
			t.Fatalf("reports = %+v, signed %d", reports, signed)
		}
		ran, _ := os.ReadFile(filepath.Join(dir, "actions.log")) // #nosec G304 -- the test's own temp directory (CWE-22)
		bundle, _ := os.ReadFile(filepath.Join(dir, "web.pem"))  // #nosec G304 -- the test's own temp directory (CWE-22)
		if string(ran) != "haproxy -c -f "+filepath.Join(dir, "haproxy.cfg")+"\nsystemctl reload haproxy\n" ||
			!bytes.Contains(bundle, []byte("BEGIN TSS2 PRIVATE KEY")) {
			t.Fatalf("haproxy ran:\n%s\nbundle:\n%s", ran, bundle)
		}
	})
	t.Run("postfix with dovecot", func(t *testing.T) {
		dir := t.TempDir()
		intent := tpmRenewIntent(t, dir, "postfix")
		intent.TargetConfig = mustJSON(t, map[string]string{
			"postfix_cert_path": filepath.Join(dir, "postfix.crt"), "postfix_key_path": filepath.Join(dir, "postfix.key"),
			"dovecot_cert_path": filepath.Join(dir, "dovecot.crt"), "dovecot_key_path": filepath.Join(dir, "dovecot.key")})
		reports, signed := run(t, dir, intent, tpmServiceProfile(t, dir, "postfix", "doveconf", "doveadm"))
		if len(reports) != 1 || reports[0].outcome == relay.OutcomeFailed || signed != 1 {
			t.Fatalf("reports = %+v, signed %d", reports, signed)
		}
		for _, name := range []string{"postfix.key", "dovecot.key"} {
			key, _ := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- the test's own temp directory (CWE-22)
			if !bytes.Contains(key, []byte("BEGIN TSS2 PRIVATE KEY")) {
				t.Fatalf("%s is not the TPM's key file:\n%s", name, key)
			}
		}
		ran, _ := os.ReadFile(filepath.Join(dir, "actions.log")) // #nosec G304 -- the test's own temp directory (CWE-22)
		if string(ran) != "postfix check\ndoveconf -n\npostfix reload\ndoveadm reload\n" {
			t.Fatalf("postfix ran:\n%s", ran)
		}
	})
	t.Run("apache refused", func(t *testing.T) {
		dir := t.TempDir()
		reports, signed := run(t, dir, tpmRenewIntent(t, dir, "apache"), tpmServiceProfile(t, dir, "apachectl"))
		if len(reports) != 1 || reports[0].outcome != relay.OutcomeFailed ||
			!strings.Contains(reports[0].detail, "installed only for nginx, haproxy, postfix, not apache") || signed != 0 {
			t.Fatalf("reports = %+v, signed %d", reports, signed)
		}
	})
}
