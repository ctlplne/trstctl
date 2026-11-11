// SPDX-License-Identifier: BUSL-1.1

package helm

import (
	"os/exec"
	"testing"
)

// A200-L1: in isolated mode the chart can give the signer pod its own
// service account carrying a cloud identity (IRSA's role annotation for the
// externalKMS adapter's web_identity source) that the control plane's account
// does not get; an existing account can be named instead; by default the
// signer pod names none, as before.
func TestIsolatedSignerServiceAccountCarriesItsCloudIdentityA200L1(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skipf("helm is required: %v", err)
	}
	render := func(extra ...string) []map[string]any {
		t.Helper()
		args := append([]string{
			"template", "trstctl", "trstctl",
			"--set", "signer.mode=isolated",
			"--set", "signer.mtls.serverName=trstctl-signer.trstctl.svc",
			"--set", "postgres.existingSecret=trstctl-postgres",
			"--set", "nats.url=nats://nats.internal:4222",
			"--set", "kek.existingSecret=trstctl-kek",
			"--set", "signer.auth.tokenCommand=/opt/trstctl-auth/bin/signer-token-provider",
		}, extra...)
		out, err := exec.Command("helm", args...).CombinedOutput() // #nosec G204 -- the chart test's own helm template invocation (CWE-78)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		return decodeAllYAML(t, string(out))
	}
	object := func(objs []map[string]any, kind, name string) map[string]any {
		for _, o := range objs {
			meta, _ := o["metadata"].(map[string]any)
			if o["kind"] == kind && meta["name"] == name {
				return o
			}
		}
		return nil
	}
	podSpec := func(t *testing.T, objs []map[string]any, name string) map[string]any {
		t.Helper()
		deployment := object(objs, "Deployment", name)
		if deployment == nil {
			t.Fatalf("no Deployment %s rendered", name)
		}
		spec, _ := deployment["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		pod, _ := tmpl["spec"].(map[string]any)
		return pod
	}
	const role = "arn:aws:iam::111122223333:role/trstctl-signer-kms"

	objs := render("--set", "signer.serviceAccount.create=true", "--set", `signer.serviceAccount.annotations.eks\.amazonaws\.com/role-arn=`+role)
	account := object(objs, "ServiceAccount", "trstctl-signer")
	if account == nil {
		t.Fatal("signer.serviceAccount.create=true rendered no trstctl-signer ServiceAccount")
	}
	meta, _ := account["metadata"].(map[string]any)
	annotations, _ := meta["annotations"].(map[string]any)
	if annotations["eks.amazonaws.com/role-arn"] != role || account["automountServiceAccountToken"] != false {
		t.Fatalf("signer ServiceAccount = annotations %v, automount %v; want the role annotation and no token mount", annotations, account["automountServiceAccountToken"])
	}
	controlPlane := object(objs, "ServiceAccount", "trstctl")
	if controlPlane != nil {
		cpMeta, _ := controlPlane["metadata"].(map[string]any)
		if cpAnnotations, _ := cpMeta["annotations"].(map[string]any); cpAnnotations["eks.amazonaws.com/role-arn"] != nil {
			t.Fatal("the control plane's ServiceAccount carries the signer's cloud identity")
		}
	}
	if signer := podSpec(t, objs, "trstctl-signer"); signer["serviceAccountName"] != "trstctl-signer" || signer["automountServiceAccountToken"] != false {
		t.Fatalf("signer pod serviceAccountName = %v, automount %v", signer["serviceAccountName"], signer["automountServiceAccountToken"])
	}
	if cp := podSpec(t, objs, "trstctl"); cp["serviceAccountName"] != "trstctl" {
		t.Fatalf("control-plane pod serviceAccountName = %v, want its own account", cp["serviceAccountName"])
	}

	objs = render("--set", "signer.serviceAccount.name=signer-kms")
	if object(objs, "ServiceAccount", "signer-kms") != nil || object(objs, "ServiceAccount", "trstctl-signer") != nil {
		t.Fatal("naming an existing account must not create one")
	}
	if signer := podSpec(t, objs, "trstctl-signer"); signer["serviceAccountName"] != "signer-kms" {
		t.Fatalf("signer pod serviceAccountName = %v, want the named signer-kms", signer["serviceAccountName"])
	}

	objs = render()
	if object(objs, "ServiceAccount", "trstctl-signer") != nil {
		t.Fatal("the default render created a signer ServiceAccount")
	}
	if signer := podSpec(t, objs, "trstctl-signer"); signer["serviceAccountName"] != nil {
		t.Fatalf("the default signer pod names account %v, want none", signer["serviceAccountName"])
	}
}
