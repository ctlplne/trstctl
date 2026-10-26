// SPDX-License-Identifier: BUSL-1.1

package operator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

// dig walks decoded JSON by map keys and slice indexes.
func dig(t *testing.T, value any, path ...any) any {
	t.Helper()
	for _, step := range path {
		switch key := step.(type) {
		case string:
			m, ok := value.(map[string]any)
			if !ok {
				t.Fatalf("dig %v: %T is not an object at %q", path, value, key)
			}
			value = m[key]
		case int:
			s, ok := value.([]any)
			if !ok || key >= len(s) {
				t.Fatalf("dig %v: no index %d in %T", path, key, value)
			}
			value = s[key]
		}
	}
	return value
}

// normalize round-trips an object through JSON so rendered maps and decoded
// fakes compare alike.
func normalize(t *testing.T, value any) any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func networkedControlPlane(name string) map[string]any {
	obj := tcpObject(name, 2, "ghcr.io/ctlplne/trstctl:v9")
	spec := obj["spec"].(map[string]any)
	spec["service"] = map[string]any{
		"type": "LoadBalancer", "port": 443,
		"annotations": map[string]any{"service.beta.kubernetes.io/aws-load-balancer-internal": "true"},
	}
	spec["ingress"] = map[string]any{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		"enabled": true, "className": "nginx", "host": "trstctl.example.test", "tlsSecret": "trstctl-ingress-tls",
		"annotations": map[string]any{"nginx.ingress.kubernetes.io/backend-protocol": "HTTPS"},
	}
	spec["networkPolicy"] = map[string]any{
		"allowSameNamespace": true, "allowedNamespaces": []any{"monitoring"},
		"egressCIDRs": []any{"10.20.0.0/16"},
	}
	return obj
}

// A133/A140–A142: the operator converges the control plane's Service, a
// default-deny NetworkPolicy and an Ingress like the Helm chart, reports each
// surface, touches nothing once converged, removes what the spec drops (and the
// annotations it no longer lists), and refuses an object it does not own.
func TestReconcileManagesTheControlPlaneNetworkSurface(t *testing.T) {
	f := newFakeCluster()
	f.tcps = []map[string]any{networkedControlPlane("prod")}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	r := reconcilerForCluster(srv)
	ctx := context.Background()

	if _, err := r.ReconcileNamespace(ctx, "trstctl-system"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	service := normalize(t, f.objects["services/prod-control-plane"])
	if dig(t, service, "spec", "type") != "LoadBalancer" || dig(t, service, "spec", "ports", 0, "port") != float64(443) ||
		dig(t, service, "spec", "ports", 0, "targetPort") != "https" ||
		dig(t, service, "spec", "selector", controlPlaneLabel) != "prod" ||
		dig(t, service, "metadata", "annotations", "service.beta.kubernetes.io/aws-load-balancer-internal") != "true" ||
		dig(t, service, "metadata", "ownerReferences", 0, "name") != "prod" {
		t.Fatalf("service = %v", service)
	}
	policy := normalize(t, f.objects["networkpolicies/prod-control-plane"])
	if dig(t, policy, "spec", "podSelector", "matchLabels", controlPlaneLabel) != "prod" ||
		len(dig(t, policy, "spec", "policyTypes").([]any)) != 2 {
		t.Fatalf("network policy selector/types = %v", policy)
	}
	peers := dig(t, policy, "spec", "ingress", 0, "from").([]any)
	if len(peers) != 3 ||
		dig(t, peers[0], "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "ingress-nginx" ||
		dig(t, peers[2], "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "monitoring" ||
		dig(t, policy, "spec", "ingress", 0, "ports", 0, "port") != float64(controlPlanePort) {
		t.Fatalf("network policy ingress = %v", dig(t, policy, "spec", "ingress"))
	}
	if dig(t, policy, "spec", "egress", 1, "to", 0, "ipBlock", "cidr") != "10.20.0.0/16" ||
		len(dig(t, policy, "spec", "egress").([]any)) != 2 {
		t.Fatalf("network policy egress = %v", dig(t, policy, "spec", "egress"))
	}
	ingress := normalize(t, f.objects["ingresses/prod-control-plane"])
	if dig(t, ingress, "spec", "ingressClassName") != "nginx" ||
		dig(t, ingress, "spec", "rules", 0, "host") != "trstctl.example.test" ||
		dig(t, ingress, "spec", "rules", 0, "http", "paths", 0, "backend", "service", "name") != "prod-control-plane" ||
		dig(t, ingress, "spec", "tls", 0, "secretName") != "trstctl-ingress-tls" ||
		dig(t, ingress, "metadata", "annotations", "nginx.ingress.kubernetes.io/backend-protocol") != "HTTPS" {
		t.Fatalf("ingress = %v", ingress)
	}
	status := f.statusSet["prod"]
	surfaces, _ := status["surfaces"].(map[string]any)
	if status["phase"] != "Reconciling" || surfaces["service"] != "create" || surfaces["networkPolicy"] != "create" ||
		surfaces["ingress"] != "create" || surfaces["signer"] != "absent" {
		t.Fatalf("status after the first pass = %v", status)
	}

	actions, err := r.ReconcileNamespace(ctx, "trstctl-system")
	if err != nil || actions["prod"] != ActionNone || len(f.objectPatches) != 0 {
		t.Fatalf("second pass = %v, %v; patches %v", actions, err, f.objectPatches)
	}
	if status := f.statusSet["prod"]; status["phase"] != "Ready" || status["readySurfaces"] != float64(4) {
		t.Fatalf("converged status = %v", status)
	}

	spec := f.tcps[0]["spec"].(map[string]any)
	spec["ingress"].(map[string]any)["enabled"] = false
	spec["service"].(map[string]any)["annotations"] = map[string]any{}
	spec["networkPolicy"].(map[string]any)["enabled"] = false
	if _, err := r.ReconcileNamespace(ctx, "trstctl-system"); err != nil {
		t.Fatalf("reconcile after dropping ingress and policy: %v", err)
	}
	if _, kept := f.objects["ingresses/prod-control-plane"]; kept {
		t.Fatal("a disabled ingress was kept")
	}
	if _, kept := f.objects["networkpolicies/prod-control-plane"]; kept {
		t.Fatal("a disabled network policy was kept")
	}
	if _, still := dig(t, normalize(t, f.objects["services/prod-control-plane"]), "metadata", "annotations").(map[string]any)["service.beta.kubernetes.io/aws-load-balancer-internal"]; still {
		t.Fatal("an annotation the spec dropped stayed on the service")
	}
	if surfaces := f.statusSet["prod"]["surfaces"].(map[string]any); surfaces["ingress"] != "delete" || surfaces["networkPolicy"] != "delete" {
		t.Fatalf("status after removal = %v", surfaces)
	}

	foreign := newFakeCluster()
	foreign.tcps = []map[string]any{networkedControlPlane("prod")}
	foreign.objects["services/prod-control-plane"] = map[string]any{
		"metadata": map[string]any{"name": "prod-control-plane", "labels": map[string]any{"app": "someone-else"}},
	}
	foreignSrv := httptest.NewServer(foreign.handler())
	defer foreignSrv.Close()
	if _, err := reconcilerForCluster(foreignSrv).ReconcileNamespace(ctx, "trstctl-system"); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("reconcile over a foreign service = %v, want a refusal", err)
	}
	if status := foreign.statusSet["prod"]; status["phase"] != "Blocked" || !strings.Contains(status["message"].(string), "not owned") {
		t.Fatalf("status over a foreign service = %v", status)
	}
}

// providedMTLSSecret is a signer mTLS Secret someone provisioned themselves.
func providedMTLSSecret(name, peerPin string) map[string]any {
	data := map[string]any{}
	for _, key := range signerMTLSKeys {
		data[key] = base64.StdEncoding.EncodeToString([]byte(key + "-material"))
	}
	data["peer-pin"] = base64.StdEncoding.EncodeToString([]byte(peerPin))
	return map[string]any{"metadata": map[string]any{"name": name}, "data": data}
}

// A143: in the isolated topology the operator runs the signer as its own pod
// behind its own Service, admits only this control plane to its mTLS port, and
// gives the control plane its side of the mutually pinned channel from the
// Secrets the spec names; switching back to the sidecar removes the signer's
// objects and leaves the provided Secrets alone.
func TestReconcileRendersTheIsolatedSignerLayout(t *testing.T) {
	f := newFakeCluster()
	cr := tcpObject("prod", 2, "ghcr.io/ctlplne/trstctl:v9")
	spec := cr["spec"].(map[string]any)
	spec["signerMode"] = "isolated"
	spec["signer"] = map[string]any{"mtls": map[string]any{"signerSecret": "prod-signer-pins", "controlPlaneSecret": "prod-cp-pins"}} // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
	f.tcps = []map[string]any{cr}
	f.secrets["prod-signer-pins"] = providedMTLSSecret("prod-signer-pins", "aa")
	f.secrets["prod-cp-pins"] = providedMTLSSecret("prod-cp-pins", "bb")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	r := reconcilerForCluster(srv)
	ctx := context.Background()
	if _, err := r.ReconcileNamespace(ctx, "trstctl-system"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	controlPlane := normalize(t, f.deployments["prod-control-plane"])
	env := map[string]any{}
	for _, item := range dig(t, controlPlane, "spec", "template", "spec", "containers", 0, "env").([]any) {
		entry := item.(map[string]any)
		if value, ok := entry["value"]; ok {
			env[entry["name"].(string)] = value
		} else {
			env[entry["name"].(string)] = dig(t, entry, "valueFrom", "secretKeyRef", "name")
		}
	}
	if env["TRSTCTL_SIGNER_MTLS_ADDRESS"] != "prod-signer:9443" ||
		env["TRSTCTL_SIGNER_MTLS_SERVER_NAME"] != "prod-signer.trstctl-system.svc" ||
		env["TRSTCTL_SIGNER_MTLS_PEER_PIN"] != "prod-cp-pins" || env["TRSTCTL_SIGNER_MODE"] != "external" {
		t.Fatalf("control-plane signer env = %v", env)
	}
	if containers := dig(t, controlPlane, "spec", "template", "spec", "containers").([]any); len(containers) != 1 {
		t.Fatalf("an isolated control plane runs %d containers, want only itself", len(containers))
	}

	signer := normalize(t, f.deployments["prod-signer"])
	if signer == nil {
		t.Fatal("no signer deployment")
	}
	args := strings.Join(func() []string {
		var out []string
		for _, arg := range dig(t, signer, "spec", "template", "spec", "containers", 0, "args").([]any) {
			out = append(out, arg.(string))
		}
		return out
	}(), " ")
	if !strings.Contains(args, "--mtls-listen=:9443") || !strings.Contains(args, "--mtls-peer-pin=$(SIGNER_MTLS_PEER_PIN)") ||
		dig(t, signer, "spec", "template", "spec", "containers", 0, "env", 0, "valueFrom", "secretKeyRef", "name") != "prod-signer-pins" {
		t.Fatalf("signer container = %v", dig(t, signer, "spec", "template", "spec", "containers", 0))
	}
	podLabels := dig(t, signer, "spec", "template", "metadata", "labels").(map[string]any)
	if podLabels[signerPodLabel] != "prod" || podLabels[controlPlaneLabel] != nil {
		t.Fatalf("signer pod labels = %v: the control plane's selector must not match the signer", podLabels)
	}
	if dig(t, signer, "spec", "template", "spec", "automountServiceAccountToken") != false {
		t.Fatal("the signer pod mounts a service account token")
	}
	fingerprint := dig(t, signer, "spec", "template", "metadata", "annotations", signerMTLSFingerprintAnnotation)
	if fingerprint != signerMTLSFingerprint("aa", "bb") ||
		dig(t, controlPlane, "spec", "template", "metadata", "annotations", signerMTLSFingerprintAnnotation) != fingerprint {
		t.Fatalf("pod templates carry mTLS fingerprints %v and %v, want both %s", fingerprint,
			dig(t, controlPlane, "spec", "template", "metadata", "annotations", signerMTLSFingerprintAnnotation), signerMTLSFingerprint("aa", "bb"))
	}
	if env["TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER"] != "false" {
		t.Fatalf("an isolated control plane may mint signer tokens itself: %v", env)
	}
	signerService := normalize(t, f.objects["services/prod-signer"])
	if dig(t, signerService, "spec", "selector", signerPodLabel) != "prod" || dig(t, signerService, "spec", "ports", 0, "port") != float64(9443) {
		t.Fatalf("signer service = %v", signerService)
	}
	signerPolicy := normalize(t, f.objects["networkpolicies/prod-signer"])
	if dig(t, signerPolicy, "spec", "ingress", 0, "from", 0, "podSelector", "matchLabels", controlPlaneLabel) != "prod" ||
		dig(t, signerPolicy, "spec", "ingress", 0, "ports", 0, "port") != float64(9443) {
		t.Fatalf("signer network policy = %v", signerPolicy)
	}
	controlPolicy := normalize(t, f.objects["networkpolicies/prod-control-plane"])
	egress := dig(t, controlPolicy, "spec", "egress").([]any)
	if dig(t, egress[len(egress)-1], "to", 0, "podSelector", "matchLabels", signerPodLabel) != "prod" ||
		dig(t, egress[len(egress)-1], "ports", 0, "port") != float64(9443) {
		t.Fatalf("control-plane egress to the signer = %v", egress)
	}

	spec["signerMode"] = "sidecar"
	if _, err := r.ReconcileNamespace(ctx, "trstctl-system"); err != nil {
		t.Fatalf("reconcile back to sidecar: %v", err)
	}
	if _, still := f.deployments["prod-signer"]; still {
		t.Fatal("the isolated signer deployment survived the switch to sidecar")
	}
	for _, key := range []string{"services/prod-signer", "networkpolicies/prod-signer"} {
		if _, still := f.objects[key]; still {
			t.Fatalf("%s survived the switch to sidecar", key)
		}
	}
	for _, name := range []string{"prod-signer-pins", "prod-cp-pins"} {
		if _, kept := f.secrets[name]; !kept {
			t.Fatalf("the operator deleted the provided Secret %s", name)
		}
	}

	delete(f.secrets, "prod-cp-pins")
	spec["signerMode"] = "isolated"
	if _, err := r.ReconcileNamespace(ctx, "trstctl-system"); err == nil || !strings.Contains(err.Error(), "prod-cp-pins does not exist") {
		t.Fatalf("reconcile without the provided control-plane Secret = %v, want it named", err)
	}
	if status := f.statusSet["prod"]; status["phase"] != "Blocked" || !strings.Contains(status["message"].(string), "prod-cp-pins") {
		t.Fatalf("status without the provided Secret = %v", status)
	}
}

// generatedMTLSEnd decodes one end of a pair the operator generated.
func generatedMTLSEnd(t *testing.T, f *fakeCluster, name string) (cert []byte, peerPin string, labels map[string]any) {
	t.Helper()
	obj := normalize(t, f.secrets[name])
	if obj == nil {
		t.Fatalf("no Secret %s", name)
	}
	for _, key := range signerMTLSKeys {
		raw, _ := dig(t, obj, "data", key).(string)
		value, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(value) == 0 {
			t.Fatalf("Secret %s key %s = %q, %v", name, key, raw, err)
		}
		switch key {
		case "tls.crt":
			cert = value
		case "peer-pin":
			peerPin = string(value)
		}
	}
	labels, _ = dig(t, obj, "metadata", "labels").(map[string]any)
	return cert, peerPin, labels
}

// A143: with no Secrets named, the operator mints a cross-pinned pair for the
// signer Service's name, owns it, leaves it alone while it is good, mints a new
// one for a new server name or before expiry (rolling both pods through the pin
// fingerprint), and removes it when the signer goes back to the sidecar.
func TestReconcileGeneratesAndRenewsTheSignerMTLSPair(t *testing.T) {
	f := newFakeCluster()
	cr := tcpObject("prod", 1, "ghcr.io/ctlplne/trstctl:v9")
	spec := cr["spec"].(map[string]any)
	spec["signerMode"] = "isolated"
	f.tcps = []map[string]any{cr}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	r := reconcilerForCluster(srv)
	ctx := context.Background()
	if _, err := r.ReconcileNamespace(ctx, "trstctl-system"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	signerCert, signerPeerPin, labels := generatedMTLSEnd(t, f, "prod-signer-mtls")
	cpCert, cpPeerPin, _ := generatedMTLSEnd(t, f, "prod-cp-signer-mtls")
	if labels[managedByLabel] != managedByOperator || labels[ownerLabel] != "prod" {
		t.Fatalf("generated Secret labels = %v", labels)
	}
	if pin, err := mtls.PinPEM(cpCert); err != nil || signerPeerPin != pin {
		t.Fatalf("the signer pins %q, want the control plane's key %q (%v)", signerPeerPin, pin, err)
	}
	if pin, err := mtls.PinPEM(signerCert); err != nil || cpPeerPin != pin {
		t.Fatalf("the control plane pins %q, want the signer's key %q (%v)", cpPeerPin, pin, err)
	}
	if got := dig(t, normalize(t, f.secrets["prod-signer-mtls"]), "metadata", "annotations", signerMTLSServerNameAnnotation); got != "prod-signer.trstctl-system.svc" {
		t.Fatalf("pair minted for %v", got)
	}
	if notAfter, err := mtls.CertNotAfterUnix(signerCert); err != nil || time.Until(time.Unix(notAfter, 0)) < 364*24*time.Hour {
		t.Fatalf("signer certificate expires at %d (%v), want a year out", notAfter, err)
	}
	fingerprint := signerMTLSFingerprint(signerPeerPin, cpPeerPin)
	for _, name := range []string{"prod-control-plane", "prod-signer"} {
		if got := dig(t, normalize(t, f.deployments[name]), "spec", "template", "metadata", "annotations", signerMTLSFingerprintAnnotation); got != fingerprint {
			t.Fatalf("%s pod template fingerprint = %v, want %s", name, got, fingerprint)
		}
	}
	if surfaces := f.statusSet["prod"]["surfaces"].(map[string]any); surfaces["signerMTLS"] != "create" {
		t.Fatalf("status = %v", surfaces)
	}

	if actions, err := r.ReconcileNamespace(ctx, "trstctl-system"); err != nil || actions["prod"] != ActionNone || len(f.patchedSecrets) != 0 {
		t.Fatalf("second pass = %v, %v; secret patches %v", actions, err, f.patchedSecrets)
	}

	spec["signer"] = map[string]any{"mtls": map[string]any{"serverName": "signer.prod.internal"}}
	if _, err := r.ReconcileNamespace(ctx, "trstctl-system"); err != nil {
		t.Fatalf("reconcile with a new server name: %v", err)
	}
	if got := dig(t, normalize(t, f.secrets["prod-signer-mtls"]), "metadata", "annotations", signerMTLSServerNameAnnotation); got != "signer.prod.internal" {
		t.Fatalf("pair after the server name changed was minted for %v", got)
	}
	renamedCert, renamedPin, _ := generatedMTLSEnd(t, f, "prod-signer-mtls")
	_, renamedCPPin, _ := generatedMTLSEnd(t, f, "prod-cp-signer-mtls")
	if string(renamedCert) == string(signerCert) {
		t.Fatal("a new server name kept the old signer certificate")
	}
	if _, rolled := f.patched["prod-control-plane"]; !rolled {
		t.Fatal("a new pair did not roll the control plane")
	}
	if got := dig(t, normalize(t, f.deployments["prod-signer"]), "spec", "template", "metadata", "annotations", signerMTLSFingerprintAnnotation); got != signerMTLSFingerprint(renamedPin, renamedCPPin) {
		t.Fatalf("a new pair did not roll the signer: fingerprint %v", got)
	}

	// A consistent pair that expires within the renewal window is replaced.
	expiring, err := mtls.GenerateSignerPeerPEM("signer.prod.internal", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for name, end := range map[string][3][]byte{
		"prod-signer-mtls":    {expiring.SignerCert, expiring.SignerKey, []byte(expiring.ControlPlanePinHex)},
		"prod-cp-signer-mtls": {expiring.ControlPlaneCert, expiring.ControlPlaneKey, []byte(expiring.SignerPinHex)},
	} {
		data := f.secrets[name]["data"].(map[string]any)
		data["tls.crt"] = base64.StdEncoding.EncodeToString(end[0])
		data["tls.key"] = base64.StdEncoding.EncodeToString(end[1])
		data["peer-pin"] = base64.StdEncoding.EncodeToString(end[2])
		data["peer-ca.pem"] = base64.StdEncoding.EncodeToString(expiring.CA)
	}
	if _, err := r.ReconcileNamespace(ctx, "trstctl-system"); err != nil {
		t.Fatalf("reconcile near expiry: %v", err)
	}
	renewedCert, _, _ := generatedMTLSEnd(t, f, "prod-signer-mtls")
	if notAfter, err := mtls.CertNotAfterUnix(renewedCert); err != nil || time.Until(time.Unix(notAfter, 0)) < 364*24*time.Hour {
		t.Fatalf("a pair a day from expiry was not renewed: %d, %v", notAfter, err)
	}
	if surfaces := f.statusSet["prod"]["surfaces"].(map[string]any); surfaces["signerMTLS"] != "update" {
		t.Fatalf("status after renewal = %v", surfaces)
	}

	spec["signerMode"] = "sidecar"
	if _, err := r.ReconcileNamespace(ctx, "trstctl-system"); err != nil {
		t.Fatalf("reconcile back to sidecar: %v", err)
	}
	for _, name := range []string{"prod-signer-mtls", "prod-cp-signer-mtls"} {
		if _, kept := f.secrets[name]; kept {
			t.Fatalf("the generated Secret %s outlived the isolated signer", name)
		}
	}
}

// The control plane refuses these signer-authorization combinations at
// startup, so the operator reports them on the resource and renders nothing;
// the sidecar evaluation authorizer mounts the signer's verifier into the
// control plane.
func TestReconcileReportsSignerAuthorizationTheControlPlaneWouldRefuse(t *testing.T) {
	for name, tc := range map[string]struct {
		spec map[string]any
		want string
	}{
		"production NATS without a token command": {
			spec: map[string]any{"signerMode": "sidecar", "nats": map[string]any{"url": "nats://nats:4222"}},
			want: "signer.authTokenCommand is required",
		},
		"co-resident authorizer beside an isolated signer": {
			spec: map[string]any{"signerMode": "isolated", "signer": map[string]any{"allowCoResidentAuthorizer": true}},
			want: "isolated signer exists to prevent",
		},
		"both authorizers": {
			spec: map[string]any{"signerMode": "sidecar", "signer": map[string]any{"allowCoResidentAuthorizer": true, "authTokenCommand": "/bin/approve"}},
			want: "mutually exclusive",
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeCluster()
			cr := tcpObject("prod", 1, "ghcr.io/ctlplne/trstctl:v9")
			for key, value := range tc.spec {
				cr["spec"].(map[string]any)[key] = value
			}
			f.tcps = []map[string]any{cr}
			srv := httptest.NewServer(f.handler())
			defer srv.Close()
			if _, err := reconcilerForCluster(srv).ReconcileNamespace(context.Background(), "trstctl-system"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("reconcile = %v, want %q", err, tc.want)
			}
			if status := f.statusSet["prod"]; status["phase"] != "Blocked" || !strings.Contains(status["message"].(string), tc.want) {
				t.Fatalf("status = %v", status)
			}
			if len(f.created) != 0 || len(f.objects) != 0 || len(f.createdSecrets) != 0 {
				t.Fatalf("rendered %d deployments, %d objects and %d secrets for a refused combination", len(f.created), len(f.objects), len(f.createdSecrets))
			}
		})
	}

	f := newFakeCluster()
	cr := tcpObject("eval", 1, "ghcr.io/ctlplne/trstctl:v9")
	cr["spec"].(map[string]any)["signerMode"] = "sidecar"
	cr["spec"].(map[string]any)["nats"] = map[string]any{"url": "nats://nats:4222", "allowSingleReplica": true}
	cr["spec"].(map[string]any)["signer"] = map[string]any{"allowCoResidentAuthorizer": true}
	f.tcps = []map[string]any{cr}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	if _, err := reconcilerForCluster(srv).ReconcileNamespace(context.Background(), "trstctl-system"); err != nil {
		t.Fatalf("evaluation sidecar reconcile: %v", err)
	}
	env := controlPlaneEnv(t, f.created[0])
	if envLiteral(env, "TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER") != "true" ||
		envLiteral(env, "TRSTCTL_SIGNER_AUTH_SECRET_FILE") != "/etc/trstctl/signer-auth/sign-auth.bin" ||
		!containerHasMount(containerByName(t, f.created[0], "control-plane"), "signer-auth", "/etc/trstctl/signer-auth") {
		t.Fatalf("evaluation co-resident authorizer env = %v", env)
	}
}
