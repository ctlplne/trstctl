// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/eventledger"

// This file re-exports the served-mutation event-name ledger (COVER-008) so callers
// already depending on internal/projections (the orchestrator, projection tests)
// reach it without importing the leaf internal/eventledger package directly. The
// ledger itself lives in internal/eventledger because internal/audit — a downstream
// of internal/store, which imports internal/audit — cannot import internal/projections
// without an import cycle, yet both layers need the same catalog.
//
// The catalog's event strings are cross-checked against this package's Event*
// constants in eventledger_consistency_test.go, so the two representations can never
// drift: a renamed event constant here that is not mirrored in the ledger fails that
// test, and an emitted lifecycle/orchestrator event type missing from the ledger
// fails the completeness test.

// FeatureEvent re-exports eventledger.FeatureEvent.
type FeatureEvent = eventledger.FeatureEvent

// EventLedger returns the served-mutation event-name ledger.
func EventLedger() []FeatureEvent { return eventledger.Ledger() }

// EventTypesForFeatureAction resolves a (feature_id, action) selector to the event
// types it emits; see eventledger.EventTypesForFeatureAction.
func EventTypesForFeatureAction(featureID, action string) ([]string, bool) {
	return eventledger.EventTypesForFeatureAction(featureID, action)
}

// LedgerHasEventType reports whether t is catalogued in the ledger.
func LedgerHasEventType(t string) bool { return eventledger.HasEventType(t) }
