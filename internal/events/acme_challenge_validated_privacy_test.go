// SPDX-License-Identifier: BUSL-1.1

package events

import "testing"

// A131 and P12-L2: a validated ACME challenge can carry a device-bound key's
// attestation evidence (A131) or the factory birth grant that answered it
// (P12-L2), and both pass the event's closed privacy shape; an undeclared
// field is still refused.
func TestACMEChallengeValidatedCarriesDeviceEvidenceAndBirthGrantP12L2(t *testing.T) {
	const base = `{"challenge_id":"c","authz_id":"a","order_id":"o","challenge_status":"valid","authz_status":"valid","order_status":"ready","attested_key_sha256":"k"`
	for name, payload := range map[string]string{
		"plain": base + `}`,
		"device-bound evidence": base + `,"device_attestation":{"format":"tpm-webauthn","credential":"Y3JlZA","binding":"Yg","public_key_sha256":"cA",` +
			`"attestation_certificate_sha256":"YQ","trusted_roots_sha256":"cg","verified_at":"2026-11-14T00:00:00Z"}}`,
		"factory birth grant": base + `,"factory_birth":{"batch_id":"b","serial":"0a","public_key_der":"cGs"}}`,
	} {
		if err := validateRegisteredPrivacyEventPayload([]byte(payload), "acme.challenge.validated", 1); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := validateRegisteredPrivacyEventPayload([]byte(base+`,"factory_birth":{"batch_id":"b","serial":"0a","public_key_der":"cGs","birth_key":"x"}}`),
		"acme.challenge.validated", 1); err == nil {
		t.Fatal("an undeclared field passed the closed shape")
	}
}
