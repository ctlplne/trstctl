// SPDX-License-Identifier: BUSL-1.1

package helm

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var updateSignerHSMGolden = flag.Bool("update-signer-hsm-golden", false, "rewrite testdata/signer-hsm.golden.yaml from the rendered chart")

// signerHSMValues is an operator's HSM signer configuration: the image by
// digest, the vendor's PKCS#11 client from a host path, and the key store
// wrapped by the shipped adapter's pkcs11 provider.
const signerHSMValues = `signer:
  hsm:
    enabled: true
    image:
      digest: sha256:5a1f0c7e3b9d2a4c6e8f0a1b3c5d7e9f1a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d
    volumes:
      - name: hsm-client
        hostPath:
          path: /opt/vendor/pkcs11
          type: Directory
    volumeMounts:
      - name: hsm-client
        mountPath: /opt/vendor/pkcs11
        readOnly: true
externalKMS:
  enabled: true
  provider: pkcs11
  keyRef: trstctl-signer-keystore
  adapterConfigSecret: trstctl-kms-wrap
`

const signerHSMImage = "ghcr.io/ctlplne/trstctl-signer-hsm@sha256:5a1f0c7e3b9d2a4c6e8f0a1b3c5d7e9f1a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d"

func helmTemplateA200L3(t *testing.T, extra ...string) ([]map[string]any, string, error) {
	t.Helper()
	args := append([]string{
		"template", "trstctl", "trstctl",
		"--set", "postgres.existingSecret=trstctl-postgres",
		"--set", "nats.url=nats://nats.internal:4222",
		"--set", "kek.existingSecret=trstctl-kek",
		"--set", "signer.auth.tokenCommand=/opt/trstctl-auth/bin/signer-token-provider",
	}, extra...)
	out, err := exec.Command("helm", args...).CombinedOutput() // #nosec G204 -- the chart test's own helm template invocation (CWE-78)
	if err != nil {
		return nil, string(out), err
	}
	return decodeAllYAML(t, string(out)), string(out), nil
}

// signerPodA200L3 returns the pod spec of a rendered Deployment and its
// container named signer.
func signerPodA200L3(t *testing.T, objs []map[string]any, deployment string) (map[string]any, map[string]any) {
	t.Helper()
	for _, o := range objs {
		meta, _ := o["metadata"].(map[string]any)
		if o["kind"] != "Deployment" || meta["name"] != deployment {
			continue
		}
		spec, _ := o["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		pod, _ := tmpl["spec"].(map[string]any)
		return pod, containerNamed(asMaps(pod["containers"]), "signer")
	}
	t.Fatalf("no Deployment %s rendered", deployment)
	return nil, nil
}

func volumeA200L3(pod map[string]any, name string) map[string]any {
	for _, v := range asMaps(pod["volumes"]) {
		if v["name"] == name {
			return v
		}
	}
	return nil
}

// A200-L3 Done when: helm template with signer-hsm values renders the signer
// from the HSM signer image and its trstctl-signer-hsm binary, with the
// vendor module mounted, in both topologies, while the control plane keeps
// the main image; the rendered signer containers match the golden; the
// shipped adapter's pkcs11 provider without the HSM image fails at template
// time; and without signer.hsm nothing changes.
func TestSignerHSMImageRendersInBothTopologiesA200L3(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skipf("helm is required: %v", err)
	}
	valuesFile := filepath.Join(t.TempDir(), "signer-hsm.yaml")
	if err := os.WriteFile(valuesFile, []byte(signerHSMValues), 0o600); err != nil {
		t.Fatal(err)
	}
	golden := map[string]any{}
	for _, topology := range []struct {
		name       string
		deployment string
		extra      []string
	}{
		{"sidecar", "trstctl", nil},
		{"isolated", "trstctl-signer", []string{"--set", "signer.mode=isolated", "--set", "signer.mtls.serverName=trstctl-signer.trstctl.svc"}},
	} {
		objs, out, err := helmTemplateA200L3(t, append([]string{"-f", valuesFile}, topology.extra...)...)
		if err != nil {
			t.Fatalf("%s: helm template with signer-hsm values: %v\n%s", topology.name, err, out)
		}
		pod, signer := signerPodA200L3(t, objs, topology.deployment)
		if signer == nil {
			t.Fatalf("%s: no signer container", topology.name)
		}
		if signer["image"] != signerHSMImage {
			t.Fatalf("%s: signer image = %v, want %s", topology.name, signer["image"], signerHSMImage)
		}
		if command := asStrings(signer["command"]); len(command) != 1 || command[0] != "/usr/local/bin/trstctl-signer-hsm" {
			t.Fatalf("%s: signer command = %v, want trstctl-signer-hsm", topology.name, command)
		}
		if !hasMountPath(signer, "/opt/vendor/pkcs11") || volumeA200L3(pod, "hsm-client") == nil {
			t.Fatalf("%s: the vendor module is not mounted into the signer", topology.name)
		}
		if !hasMountPath(signer, "/etc/trstctl/kms-wrap") || hasMountPath(signer, "/etc/trstctl/kek") {
			t.Fatalf("%s: the HSM signer must mount the adapter configuration and no local KEK", topology.name)
		}
		cpPod, _ := signerPodA200L3(t, objs, "trstctl")
		if cp := containerNamed(asMaps(cpPod["containers"]), "trstctl"); cp == nil || strings.Contains(asString(cp["image"]), "signer-hsm") {
			t.Fatalf("%s: the control plane does not keep the main image", topology.name)
		}
		golden[topology.name] = map[string]any{
			"signer":    signer,
			"hsmVolume": volumeA200L3(pod, "hsm-client"),
		}
	}
	rendered, err := yaml.Marshal(golden)
	if err != nil {
		t.Fatal(err)
	}
	goldenPath := filepath.Join("testdata", "signer-hsm.golden.yaml")
	if *updateSignerHSMGolden {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, rendered, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath) // #nosec G304 -- the test's own golden file (CWE-22)
	if err != nil {
		t.Fatalf("read the golden (run with -update-signer-hsm-golden): %v", err)
	}
	if string(want) != string(rendered) {
		t.Fatalf("the rendered HSM signer differs from %s (rerun with -update-signer-hsm-golden after review):\n%s", goldenPath, rendered)
	}

	_, out, err := helmTemplateA200L3(t, "--set", "externalKMS.enabled=true", "--set", "externalKMS.provider=pkcs11",
		"--set", "externalKMS.keyRef=trstctl-signer-keystore", "--set", "externalKMS.adapterConfigSecret=trstctl-kms-wrap")
	if err == nil || !strings.Contains(out, "CRYPTO-002: externalKMS.provider=pkcs11 with the shipped adapter needs the HSM signer image") {
		t.Fatalf("pkcs11 without the HSM signer image = %v\n%s", err, out)
	}

	objs, out, err := helmTemplateA200L3(t)
	if err != nil {
		t.Fatalf("default render: %v\n%s", err, out)
	}
	_, signer := signerPodA200L3(t, objs, "trstctl")
	if command := asStrings(signer["command"]); strings.Contains(asString(signer["image"]), "signer-hsm") || len(command) != 1 || command[0] != "/usr/local/bin/trstctl-signer" {
		t.Fatalf("default signer = image %v command %v, want the main image's trstctl-signer", signer["image"], command)
	}
}
