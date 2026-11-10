// SPDX-License-Identifier: BUSL-1.1

package api_test

import "testing"

// A261-L4: the access deletes take the revision the caller read as a query
// parameter, and refuse without one (400). The served contract marked it
// optional, so a generated client could omit it and be refused.
func TestAccessDeletesRequireTheRevisionTheyReadA261L4(t *testing.T) {
	doc := fetchSpec(t)
	paths := asMap(doc["paths"])
	for _, path := range []string{
		"/api/v1/access/folders/{name}",
		"/api/v1/access/auto-approval-rules/{id}",
		"/api/v1/access/gateway-pools/{name}",
	} {
		del := asMap(asMap(paths[path])["delete"])
		if del == nil {
			t.Fatalf("%s has no DELETE operation", path)
		}
		found := false
		for _, raw := range del["parameters"].([]any) {
			p := asMap(raw)
			if p["name"] != "revision" || p["in"] != "query" {
				continue
			}
			found = true
			if p["required"] != true {
				t.Errorf("DELETE %s: revision is not required, but the handler refuses a delete without it", path)
			}
		}
		if !found {
			t.Errorf("DELETE %s declares no revision query parameter", path)
		}
	}
}
