// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestHostProfileRejectsUnpinnedHAProxyConfigAction(t *testing.T) {
	command, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	profilePath := filepath.Join(root, "profile.json")
	for _, name := range []string{"haproxy", " haproxy "} {
		profile := map[string]any{
			"allowed_roots": []string{root},
			"actions": []map[string]any{{
				"logical_name": name, "command": command, "pass_args": true,
			}},
		}
		data, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(profilePath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := relay.LoadHostProfile(profilePath); err == nil || !strings.Contains(err.Error(), "pinned") {
			t.Fatalf("unbounded HAProxy action %q accepted: %v", name, err)
		}
	}
}

func TestHostExecutorRefusesUnpinnedHAProxyBeforeAnyWrite(t *testing.T) {
	command, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	crtPath := filepath.Join(root, "server.pem")
	target, err := json.Marshal(map[string]string{"crt_path": crtPath, "config_path": crtPath})
	if err != nil {
		t.Fatal(err)
	}
	profile := connector.LocalOpsConfig{AllowedRoots: []string{root}, Actions: []connector.LocalAction{
		{LogicalName: "haproxy", Command: command, PassArgs: true},
		{LogicalName: "systemctl", Command: command, PassArgs: true},
	}}
	_, err = relay.ExecuteOnHost(context.Background(), profile, relay.DeployIntent{
		Connector: "haproxy", Target: "host", TargetConfig: target,
	}, relay.Material{
		"credential.cert_pem": []byte("not a certificate"),
		"credential.key_pem":  []byte("not a key"),
	})
	if err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("job-selected HAProxy config was accepted: %v", err)
	}
	if _, err := os.Stat(crtPath); !os.IsNotExist(err) {
		t.Fatalf("rejected HAProxy job wrote a file: %v", err)
	}
}

func TestHostExecutorRejectsHAProxyNonCertificateBytesBeforeWrite(t *testing.T) {
	command, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	crtPath := filepath.Join(root, "server.pem")
	configPath := filepath.Join(root, "haproxy.cfg")
	target, err := json.Marshal(map[string]string{"crt_path": crtPath, "config_path": configPath})
	if err != nil {
		t.Fatal(err)
	}
	profile := connector.LocalOpsConfig{AllowedRoots: []string{root}, Actions: []connector.LocalAction{
		{LogicalName: "haproxy", LogicalArgs: []string{"-c", "-f", configPath}, Command: command, PassArgs: true},
		{LogicalName: "systemctl", Command: command, PassArgs: true},
	}}
	_, err = relay.ExecuteOnHost(context.Background(), profile, relay.DeployIntent{
		Connector: "haproxy", Target: "host", TargetConfig: target, Fingerprint: strings.Repeat("a", 64),
	}, relay.Material{
		"credential.cert_pem": []byte("not a certificate"),
		"credential.key_pem":  []byte("not a key"),
	})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("non-certificate bytes accepted for HAProxy bundle: %v", err)
	}
	if _, err := os.Stat(crtPath); !os.IsNotExist(err) {
		t.Fatalf("malformed credential wrote a file: %v", err)
	}
}

func TestHostExecutorRefusesHAProxyConfigThatDiffersFromOperatorPin(t *testing.T) {
	command, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	crtPath := filepath.Join(root, "server.pem")
	approved := filepath.Join(root, "approved.cfg")
	selected := filepath.Join(root, "selected.cfg")
	target, err := json.Marshal(map[string]string{"crt_path": crtPath, "config_path": selected})
	if err != nil {
		t.Fatal(err)
	}
	profile := connector.LocalOpsConfig{AllowedRoots: []string{root}, Actions: []connector.LocalAction{
		{LogicalName: "haproxy", LogicalArgs: []string{"-c", "-f", approved}, Command: command, PassArgs: true},
	}}
	cert, key, fingerprint := hostTestCredential(t)
	intent := relay.DeployIntent{Connector: "haproxy", Target: "host", TargetConfig: target, Fingerprint: fingerprint}
	_, err = relay.ExecuteOnHost(context.Background(), profile, intent, relay.Material{
		"credential.cert_pem": cert, "credential.key_pem": key,
	})
	if err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("job-selected config path was accepted: %v", err)
	}
	if _, err := os.Stat(crtPath); !os.IsNotExist(err) {
		t.Fatalf("rejected job wrote a bundle: %v", err)
	}
	plan, err := relay.DryRunOnHost(context.Background(), nil, profile, intent, nil)
	if err != nil || plan.Ready {
		t.Fatalf("preview accepted an unpinned config path: plan=%+v err=%v", plan, err)
	}
}

func TestHostExecutorBindsHAProxyMaterialToCertificateAndKey(t *testing.T) {
	command, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	crtPath, configPath := filepath.Join(root, "server.pem"), filepath.Join(root, "haproxy.cfg")
	target, err := json.Marshal(map[string]string{"crt_path": crtPath, "config_path": configPath})
	if err != nil {
		t.Fatal(err)
	}
	profile := connector.LocalOpsConfig{AllowedRoots: []string{root}, Actions: []connector.LocalAction{
		{LogicalName: "haproxy", LogicalArgs: []string{"-c", "-f", configPath}, Command: command, PassArgs: true},
		{LogicalName: "systemctl", Command: command, PassArgs: true},
	}}
	key, cert, err := crypto.GenerateUploadableRSAKeypair(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(key)
	otherKey, _, err := crypto.GenerateUploadableRSAKeypair(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(otherKey)
	info, err := certinfo.Inspect(cert)
	if err != nil {
		t.Fatal(err)
	}
	base := relay.DeployIntent{Connector: "haproxy", Target: "host", TargetConfig: target, Fingerprint: info.SHA256Fingerprint}
	for _, tc := range []struct {
		name, fingerprint, want string
		key                     []byte
	}{
		{"wrong fingerprint", strings.Repeat("0", 64), "fingerprint", key},
		{"wrong key", info.SHA256Fingerprint, "does not match", otherKey},
		{"trailing key data", info.SHA256Fingerprint, "private key", append(append([]byte(nil), key...), []byte("extra data\n")...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intent := base
			intent.Fingerprint = tc.fingerprint
			_, err := relay.ExecuteOnHost(context.Background(), profile, intent, relay.Material{
				"credential.cert_pem": cert, "credential.key_pem": tc.key,
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("bad material accepted or wrong error: %v", err)
			}
			if _, err := os.Stat(crtPath); !os.IsNotExist(err) {
				t.Fatalf("rejected material wrote a file: %v", err)
			}
		})
	}
	_, err = relay.ExecuteOnHost(context.Background(), profile, base, relay.Material{
		"credential.cert_pem": append([]byte("  \n"), cert...), "credential.key_pem": append([]byte(" \n"), key...),
	})
	if err != nil {
		t.Fatalf("matching material refused: %v", err)
	}
	installed, err := os.ReadFile(crtPath) // #nosec G304 -- private test directory and fixed path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(installed), "  \n-----BEGIN") || !strings.Contains(string(installed), "-----BEGIN CERTIFICATE-----") || !strings.Contains(string(installed), "-----BEGIN PRIVATE KEY-----") {
		t.Fatal("host bundle did not use canonical certificate and key PEM")
	}
}
