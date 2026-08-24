// SPDX-License-Identifier: MPL-2.0

package api_test

import "testing"

func TestOwnershipAssignmentOpenAPIContractNamesDurableDecisionInputs(t *testing.T) {
	doc := fetchSpec(t)
	op := doc["paths"].(map[string]any)["/api/v1/ownership/assignments"].(map[string]any)["post"].(map[string]any)
	requestRef := op["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)["$ref"]
	if requestRef != "#/components/schemas/OwnershipAssignmentRequest" {
		t.Fatalf("ownership assignment request schema = %v", requestRef)
	}
	responseRef := op["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)["$ref"]
	if responseRef != "#/components/schemas/OwnershipAssignmentResult" {
		t.Fatalf("ownership assignment response schema = %v", responseRef)
	}
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	assertRequiredSchemaFields(t, schemas, "OwnershipAssignmentRequest", "owner_id", "inventory_ids", "reason")
	assertRequiredSchemaFields(t, schemas, "OwnershipAssignmentResult", "owner_id", "assigned", "assigned_by", "assigned_at")
	request := schemas["OwnershipAssignmentRequest"].(map[string]any)["properties"].(map[string]any)
	inventory := request["inventory_ids"].(map[string]any)
	if inventory["minItems"] != float64(1) || inventory["maxItems"] != float64(100) {
		t.Fatalf("ownership assignment inventory bounds = min:%v max:%v", inventory["minItems"], inventory["maxItems"])
	}
	items := inventory["items"].(map[string]any)
	if items["maxLength"] != float64(1024) {
		t.Fatalf("ownership assignment inventory id maxLength = %v", items["maxLength"])
	}
	reason := request["reason"].(map[string]any)
	if reason["minLength"] != float64(1) || reason["maxLength"] != float64(2000) {
		t.Fatalf("ownership assignment reason bounds = min:%v max:%v", reason["minLength"], reason["maxLength"])
	}
}
