// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"errors"
	"strings"
	"testing"
)

type classifiedOutboxTestError struct{ class string }

func (e classifiedOutboxTestError) Error() string             { return "attacker-controlled detail" }
func (e classifiedOutboxTestError) SafeDeliveryClass() string { return e.class }

func TestPersistedDeliveryErrorAcceptsOnlyClosedSafeClasses(t *testing.T) {
	if got := persistedDeliveryError(classifiedOutboxTestError{class: "notification_receipt_binding_conflict"}); got != "notification_receipt_binding_conflict" {
		t.Fatalf("retained receipt conflict class = %q", got)
	}

	if got := persistedDeliveryError(classifiedOutboxTestError{class: "notification_receiver_not_configured"}); got != "notification_receiver_not_configured" {
		t.Fatalf("missing receiver class = %q", got)
	}
	if got := persistedDeliveryError(classifiedOutboxTestError{class: "external_ca_finalize_failed"}); got != "external_ca_finalize_failed" {
		t.Fatalf("known safe class = %q", got)
	}
	if got := persistedDeliveryError(classifiedOutboxTestError{class: "attacker-controlled detail"}); got != "external_delivery_failed" {
		t.Fatalf("untrusted class was persisted as %q", got)
	}
}

func TestClassifiedEffectIndeterminateRetainsOnlyClosedSafeClass(t *testing.T) {
	const unsafe = "upstream response containing private material"
	err := classifiedEffectIndeterminate(classifiedOutboxTestError{class: "external_ca_finalize_failed"})
	if !errors.Is(err, ErrEffectIndeterminate) {
		t.Fatalf("classified error = %v, want ErrEffectIndeterminate", err)
	}
	if strings.Contains(err.Error(), unsafe) || strings.Contains(err.Error(), "attacker-controlled") {
		t.Fatalf("classified error rendered upstream detail: %q", err)
	}
	if got := persistedDeliveryError(err); got != "external_ca_finalize_failed" {
		t.Fatalf("persisted class = %q, want external_ca_finalize_failed", got)
	}

	untrusted := classifiedEffectIndeterminate(classifiedOutboxTestError{class: unsafe})
	if got := persistedDeliveryError(untrusted); got != "external_delivery_failed" {
		t.Fatalf("untrusted class persisted as %q", got)
	}
}
