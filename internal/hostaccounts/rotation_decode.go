// SPDX-License-Identifier: BUSL-1.1
package hostaccounts

import (
	"encoding/json"
	"errors"
)

func rotationNativeFields(raw []byte) error {
	native, e := requiredNativeFields(raw, "machine", "account")
	if e != nil {
		return e
	}
	if _, e = requiredNativeFields(native["machine"], "name", "sid", "role"); e != nil {
		return e
	}
	_, e = requiredNativeFields(native["account"], "name", "sid", "enabled", "locked", "password_required")
	return e
}
func DecodeRotationIntent(raw []byte) (RotationIntent, error) {
	var i RotationIntent
	if e := decodeInventoryJSON(raw, MaxRotationIntentBytes, &i); e != nil {
		return i, e
	}
	fields, e := requiredNativeFields(raw, "rotation_id", "account_id", "tenant_id", "agent_id", "inventory_run_id", "predecessor_generation_id", "native", "binding_digest")
	if e != nil {
		return i, e
	}
	if e = rotationNativeFields(fields["native"]); e != nil {
		return i, e
	}
	return i, i.Validate()
}
func DecodeRotationReport(raw []byte) (RotationReport, error) {
	var r RotationReport
	if e := decodeInventoryJSON(raw, MaxRotationReportBytes, &r); e != nil {
		return r, e
	}
	fields, e := requiredNativeFields(raw, "rotation_id", "binding_digest", "observed_at", "status")
	if e != nil {
		return r, e
	}
	if r.Proof != nil {
		proof, e := requiredNativeFields(fields["proof"], "binding", "generation_id", "new_authenticated", "old_refused", "observed_at")
		if e != nil {
			return r, e
		}
		if e = rotationNativeFields(proof["binding"]); e != nil {
			return r, e
		}
	}
	if !r.validShape() {
		return r, errors.New("host accounts: explicit native rotation evidence required")
	}
	return r, nil
}

// MarshalRotationReport encodes only a validated public result.
func MarshalRotationReport(i RotationIntent, r RotationReport) ([]byte, error) {
	if e := r.Validate(i); e != nil {
		return nil, e
	}
	return json.Marshal(r)
}
