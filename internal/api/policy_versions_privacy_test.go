// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/events"
)

func TestPolicyVersionPrivacyPreservesExecutableAuthority(t *testing.T) {
	const subject = "policy-author@example.test"
	const module = "package trstctl.policy\n\ndefault allow := false\n"
	cases := []struct {
		eventType, actorField, moduleField string
		payload                            any
	}{
		{policyVersionAuthoredEventType, "author", "module", policyVersionAuthoredEvent{
			ID: "version-a", Kind: "lifecycle", Module: module, ModuleSHA256: "sha256:reviewed-module", Package: "trstctl.policy", Query: "data.trstctl.policy",
			Description: "Reviewed by " + subject, ChangeRef: "change:" + subject, EvidenceRefs: []string{"review:" + subject, "qa:stable-evidence"}, Author: subject,
		}},
		{policyVersionActivatedEventType, "activated_by", "previous_module", policyVersionActivatedEvent{
			ID: "version-a", Kind: "lifecycle", Reason: "Reviewed by " + subject, EvidenceRefs: []string{"review:" + subject}, ActivatedBy: subject,
			PreviousID: "boot-lifecycle", PreviousModule: module, PreviousModuleSHA256: "sha256:reviewed-module", PreviousPackage: "trstctl.policy", PreviousQuery: "data.trstctl.policy",
		}},
		{policyVersionRolledBackEventType, "rolled_back_by", "rollback_to_module", policyVersionRolledBackEvent{
			ID: "version-a", Kind: "lifecycle", Reason: "Reviewed by " + subject, EvidenceRefs: []string{"review:" + subject}, RolledBackBy: subject,
			RollbackToID: "boot-lifecycle", RollbackToModule: module, RollbackToModuleSHA256: "sha256:reviewed-module", RollbackToPackage: "trstctl.policy", RollbackToQuery: "data.trstctl.policy",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.eventType, func(t *testing.T) {
			raw, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			clean, changed, err := events.PseudonymizeEventDataForSubject(raw, "tenant-a", subject, tc.eventType, 1)
			if err != nil {
				t.Fatal(err)
			}
			if !changed || bytes.Contains(clean, []byte(subject)) {
				t.Fatalf("subject remained in rewritten evidence: %s", clean)
			}
			var got map[string]any
			if err := json.Unmarshal(clean, &got); err != nil {
				t.Fatal(err)
			}
			if got[tc.moduleField] != module || got[tc.actorField] == subject || got[tc.actorField] == "" {
				t.Fatalf("module or actor was corrupted: %s", clean)
			}
			var original map[string]any
			if err := json.Unmarshal(raw, &original); err != nil {
				t.Fatal(err)
			}
			for key, value := range original {
				if strings.HasSuffix(key, "sha256") || key == "id" || strings.HasSuffix(key, "_id") || key == "kind" || strings.HasSuffix(key, "package") || strings.HasSuffix(key, "query") {
					if got[key] != value {
						t.Errorf("authority %s changed: got %v want %v", key, got[key], value)
					}
				}
			}
			original[tc.moduleField] = module + "\n# " + subject
			unsafe, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := events.PseudonymizeEventDataForSubject(unsafe, "tenant-a", subject, tc.eventType, 1); err == nil || !strings.Contains(err.Error(), "/"+tc.moduleField) {
				t.Fatalf("subject-bearing executable module did not fail closed: %v", err)
			}
			original[tc.moduleField] = module
			original["new_same_version_field"] = subject
			drifted, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := events.PseudonymizeEventDataForSubject(drifted, "tenant-a", subject, tc.eventType, 1); err == nil {
				t.Fatal("unregistered same-version field accepted")
			}
			delete(original, "new_same_version_field")
			original[tc.moduleField] = map[string]string{"new": "container"}
			drifted, err = json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := events.PseudonymizeEventDataForSubject(drifted, "tenant-a", subject, tc.eventType, 1); err == nil {
				t.Fatal("same-version module shape drift accepted")
			}
		})
	}
}
