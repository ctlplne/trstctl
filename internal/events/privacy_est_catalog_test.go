// SPDX-License-Identifier: BUSL-1.1

package events

import "testing"

func TestESTAuditOperationsHaveClosedPrivacySchemas(t *testing.T) {
	for _, op := range []string{"est-enroll", "est-reenroll", "est-serverkeygen"} {
		t.Run(op, func(t *testing.T) {
			eventType := "protocol.est." + op
			for _, payload := range []string{
				`{"op":"` + op + `","decision":"allow"}`,
				`{"op":"` + op + `","decision":"deny","reason":"profile refused","profile":"fleet"}`,
			} {
				if err := validateRegisteredPrivacyEventPayload([]byte(payload), eventType, 1); err != nil {
					t.Errorf("producer payload refused: %v", err)
				}
			}
			if err := validateRegisteredPrivacyEventPayload([]byte(`{"op":"`+op+`","decision":"allow","unexpected":"x"}`), eventType, 1); err == nil {
				t.Error("unknown audit field accepted")
			}
		})
	}
}
