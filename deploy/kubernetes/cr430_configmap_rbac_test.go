// SPDX-License-Identifier: BUSL-1.1

package kubernetes_test

import (
	"testing"
)

func TestCR430AgentCannotWriteConfigMapsClusterWide(t *testing.T) {
	cluster := clusterRole(t)
	for _, verb := range []string{"create", "update", "patch"} {
		if hasClusterRoleRule(cluster, "", "configmaps", verb) {
			t.Errorf("default agent ClusterRole grants cluster-wide %s on every ConfigMap", verb)
		}
	}
	local := namedDoc(t, "Role", "trstctl-agent")
	if !hasClusterRoleRule(local, "", "configmaps", "get", "create", "update", "patch") {
		t.Error("the agent's own namespace lacks bounded ConfigMap distribution access")
	}
}

func TestCR430OtherConfigMapTargetsRequireOptInNamespaceRole(t *testing.T) {
	grant := namedDoc(t, "Role", "trstctl-agent-trust-configmaps")
	meta, _ := grant["metadata"].(map[string]any)
	if meta["namespace"] == "" || meta["namespace"] == "kube-system" {
		t.Fatalf("opt-in ConfigMap Role has unsafe namespace %v", meta["namespace"])
	}
	if !hasClusterRoleRule(grant, "", "configmaps", "get", "create", "update", "patch") {
		t.Fatalf("opt-in ConfigMap Role lacks namespaced distribution verbs: %v", grant["rules"])
	}
	binding := namedDoc(t, "RoleBinding", "trstctl-agent-trust-configmaps")
	boundMeta, _ := binding["metadata"].(map[string]any)
	if boundMeta["namespace"] != meta["namespace"] {
		t.Fatalf("RoleBinding namespace %v differs from Role %v", boundMeta["namespace"], meta["namespace"])
	}
}
