// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"slices"
	"testing"
)

// A Kubernetes TLS run reports each resource as queued for delivery to its
// source's in-cluster agent, delivered, or not delivered with the reason. The
// served contract lists every one, so generated clients and the console can
// read a run the server actually returns.
func TestOpenAPIDiscoveryRunListsEveryKubernetesDeliveryStatus(t *testing.T) {
	doc := fetchSpec(t)
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	run := schemas["DiscoveryRun"].(map[string]any)["properties"].(map[string]any)
	item := run["target_results"].(map[string]any)["items"].(map[string]any)
	raw := item["properties"].(map[string]any)["status"].(map[string]any)["enum"].([]any)
	statuses := make([]string, 0, len(raw))
	for _, value := range raw {
		statuses = append(statuses, value.(string))
	}
	for _, want := range []string{"not_delivered", "delivery_queued", "delivered"} {
		if !slices.Contains(statuses, want) {
			t.Errorf("DiscoveryRun.target_results[].status enum %v does not list %q", statuses, want)
		}
	}
}
