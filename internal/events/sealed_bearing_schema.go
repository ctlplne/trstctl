// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// ErrFixtureSealedAdmissionRequired means a standalone log cannot authenticate
// an event that can carry ciphertext. Tests for those events need a validating
// AppendAdmission backed by their own tenant custody fixture.
var ErrFixtureSealedAdmissionRequired = errors.New("events: sealed-bearing fixture event requires validating append admission")

// SealedBearingEvent uses the same conservative classification as Append's
// fixture guard. A served test may install a real custody validator for these
// events while keeping ordinary fixture events on their existing path.
func SealedBearingEvent(event Event) bool {
	return sealedBearingEventType(event.Type) || hasSealedBearingField(event.Data)
}

// This list mirrors the sealed-bearing cases in the production ingress
// validator. A newly introduced schema with a sealed field is also refused by
// the field walk below until it is classified by that validator.
func sealedBearingEventType(eventType string) bool {
	switch eventType {
	case "licensed_crypto.migration.started",
		"kmip.state.object.created", "kmip.state.object.registered", "kmip.state.object.rekeyed",
		"secret.batch_versioned", "secret.static_rotation.advanced",
		"slack.app.installed", "codesign.commanded",
		"dynsecret.lease.pending", "dynsecret.lease.prepared", "dynsecret.lease.issued",
		"secret.version.written", "secret.sync.queued",
		"secret.created", "secret.rotated", "secret.recovered", "secret.deleted", "secret.undeleted",
		"secret.batch_imported":
		return true
	default:
		return false
	}
}

func hasSealedBearingField(data []byte) bool {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return bytes.Contains(bytes.ToLower(data), []byte("sealed")) ||
			bytes.Contains(bytes.ToLower(data), []byte("ciphertext"))
	}
	var walk func(any) bool
	walk = func(current any) bool {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				if sealedFieldName(key) || walk(child) {
					return true
				}
			}
		case []any:
			for _, child := range typed {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	return walk(value)
}

func sealedFieldName(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "sealed_at", "sealed_sha256", "sealed_only_floor", "sealed_results",
		"sealed_tenants_not_opened", "sealed_copies", "ciphertext_sha256":
		return false
	}
	return lower == "sealed" || strings.HasPrefix(lower, "sealed_") ||
		lower == "requester_sealed" || lower == "ciphertext" ||
		strings.HasPrefix(lower, "ciphertext_")
}
