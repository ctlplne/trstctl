// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

// Q6-O2: of a cluster's audit events, a finished get of the decoy's token
// Secret or a list of its namespace's Secrets is a read naming the principal,
// and any finished request made as the decoy's service account is a use naming
// the client. Other Secrets, other namespaces, cluster-wide informer lists,
// unfinished stages, the token controller filling the Secret (its read and its
// write) and a get that found no Secret (kubectl apply looking before it
// creates) are not.
func TestKubernetesAuditEventsMatchDecoyReadsAndUsesQ6O2(t *testing.T) {
	decoys := []store.HoneyToken{{ID: "d1", K8sCluster: "prod-eu", K8sNamespace: "ci", K8sServiceAccount: "deployer", K8sSecret: "deployer-token"}}
	raw := `{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[
	 {"auditID":"1","stage":"ResponseComplete","verb":"get","requestURI":"/api/v1/namespaces/ci/secrets/deployer-token","user":{"username":"alice@example.com"},"sourceIPs":["10.0.0.7"],"userAgent":"kubectl/v1.35.0","objectRef":{"resource":"secrets","namespace":"ci","name":"deployer-token","apiVersion":"v1"},"responseStatus":{"code":200}},
	 {"auditID":"1","stage":"RequestReceived","verb":"get","requestURI":"/api/v1/namespaces/ci/secrets/deployer-token","user":{"username":"alice@example.com"},"objectRef":{"resource":"secrets","namespace":"ci","name":"deployer-token"}},
	 {"auditID":"2","stage":"ResponseComplete","verb":"list","requestURI":"/api/v1/namespaces/ci/secrets","user":{"username":"system:serviceaccount:ci:builder"},"sourceIPs":["10.0.0.8"],"objectRef":{"resource":"secrets","namespace":"ci"},"responseStatus":{"code":403}},
	 {"auditID":"3","stage":"ResponseComplete","verb":"get","requestURI":"/api/v1/namespaces/ci/pods","user":{"username":"system:serviceaccount:ci:deployer"},"sourceIPs":["203.0.113.9"],"userAgent":"curl/8.9.1\u001b[2J","objectRef":{"resource":"pods","namespace":"ci"},"responseStatus":{"code":403}},
	 {"auditID":"4","stage":"ResponseComplete","verb":"get","user":{"username":"alice@example.com"},"objectRef":{"resource":"secrets","namespace":"ci","name":"registry-creds"},"responseStatus":{"code":200}},
	 {"auditID":"5","stage":"ResponseComplete","verb":"get","user":{"username":"alice@example.com"},"objectRef":{"resource":"secrets","namespace":"prod","name":"deployer-token"},"responseStatus":{"code":200}},
	 {"auditID":"6","stage":"ResponseComplete","verb":"watch","user":{"username":"system:kube-controller-manager"},"objectRef":{"resource":"secrets"},"responseStatus":{"code":200}},
	 {"auditID":"7","stage":"ResponseComplete","verb":"update","user":{"username":"system:kube-controller-manager"},"objectRef":{"resource":"secrets","namespace":"ci","name":"deployer-token"},"responseStatus":{"code":200}},
	 {"auditID":"8","stage":"ResponseComplete","verb":"get","user":{"username":"alice@example.com"},"objectRef":{"resource":"secrets","namespace":"ci","name":"deployer-token","apiGroup":"example.dev"},"responseStatus":{"code":200}},
	 {"auditID":"9","stage":"ResponseComplete","verb":"get","user":{"username":"kubernetes-admin"},"objectRef":{"resource":"secrets","namespace":"ci","name":"deployer-token"},"responseStatus":{"code":404}},
	 {"auditID":"10","stage":"ResponseComplete","verb":"get","user":{"username":"system:kube-controller-manager"},"userAgent":"kube-controller-manager/v1.35.0 (linux/arm64) kubernetes/6645204/tokens-controller","objectRef":{"resource":"secrets","namespace":"ci","name":"deployer-token"},"responseStatus":{"code":200}}
	]}`
	var batch kubernetesAuditEventList
	if err := json.Unmarshal([]byte(raw), &batch); err != nil {
		t.Fatal(err)
	}
	hits := matchKubernetesDecoyEvents(decoys, batch.Items)
	if len(hits) != 3 {
		t.Fatalf("hits = %+v; want the Secret get, the namespace list and the token use", hits)
	}
	want := []kubernetesDecoyHit{
		{decoyID: "d1", reader: "alice@example.com from 10.0.0.7", method: "token Secret read: get secrets (200)", requestURI: "/api/v1/namespaces/ci/secrets/deployer-token"},
		{decoyID: "d1", reader: "system:serviceaccount:ci:builder from 10.0.0.8", method: "token Secret read: list secrets (403)", requestURI: "/api/v1/namespaces/ci/secrets"},
		{decoyID: "d1", reader: "curl/8.9.1?[2J from 203.0.113.9", method: "token used: get pods (403)", requestURI: "/api/v1/namespaces/ci/pods"},
	}
	for i := range want {
		if hits[i] != want[i] {
			t.Fatalf("hit %d = %+v, want %+v", i, hits[i], want[i])
		}
	}
	manifest := kubernetesDecoyManifest(decoys[0])
	for _, line := range []string{"kind: ServiceAccount", "name: deployer", "namespace: ci", "automountServiceAccountToken: false",
		"kubernetes.io/service-account.name: deployer", "name: deployer-token", "type: kubernetes.io/service-account-token"} {
		if !strings.Contains(manifest, line) {
			t.Fatalf("manifest lacks %q:\n%s", line, manifest)
		}
	}
	if strings.Contains(strings.ToLower(manifest), "decoy") || strings.Contains(manifest, "RoleBinding") {
		t.Fatalf("the manifest gives the decoy away or binds it:\n%s", manifest)
	}
	if rules := kubernetesDecoyAuditRules(decoys[0]); !strings.Contains(rules, `users: ["system:serviceaccount:ci:deployer"]`) || !strings.Contains(rules, `namespaces: ["ci"]`) {
		t.Fatalf("audit rules:\n%s", rules)
	}
}
