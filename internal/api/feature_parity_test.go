// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/featureparity"
)

func TestFeatureParityMapsCatalogRowsToOpenAPIOperations(t *testing.T) {
	operations := openAPIOperationIDs(t, fetchSpec(t))

	for _, item := range loadFeatureParityCatalog(t).Items {
		if len(item.APISurface) == 0 && strings.TrimSpace(item.APINA) == "" {
			t.Errorf("%s (%s) has no api_surface operations and no api_na reason", item.FeatureID, item.Feature)
		}
		if len(item.APISurface) > 0 && strings.TrimSpace(item.APINA) != "" {
			t.Errorf("%s (%s) declares both api_surface and api_na", item.FeatureID, item.Feature)
		}
		for _, opID := range item.APISurface {
			if strings.TrimSpace(opID) == "" {
				t.Errorf("%s (%s) has a blank api_surface operation", item.FeatureID, item.Feature)
				continue
			}
			if !operations[opID] {
				t.Errorf("%s (%s) references missing OpenAPI operationId %q", item.FeatureID, item.Feature, opID)
			}
		}
	}
}

func TestEveryOpenAPIOperationMapsToFeature(t *testing.T) {
	operations := openAPIOperationIDs(t, fetchSpec(t))
	mapped := map[string][]string{}
	for _, item := range loadFeatureParityCatalog(t).Items {
		for _, opID := range item.APISurface {
			opID = strings.TrimSpace(opID)
			if opID == "" {
				continue
			}
			mapped[opID] = append(mapped[opID], item.FeatureID)
		}
	}
	for opID := range operations {
		if len(mapped[opID]) == 0 {
			t.Errorf("OpenAPI operationId %q is served but not mapped to a feature catalog row", opID)
		}
	}
}

func loadFeatureParityCatalog(t *testing.T) featureparity.Catalog {
	t.Helper()
	catalog, err := featureparity.Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}
	return catalog
}

func openAPIOperationIDs(t *testing.T, doc map[string]any) map[string]bool {
	t.Helper()
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI document has no paths object")
	}
	out := map[string]bool{}
	for path, rawPathItem := range paths {
		pathItem, ok := rawPathItem.(map[string]any)
		if !ok {
			t.Fatalf("OpenAPI path %s is not an object", path)
		}
		for method, rawOp := range pathItem {
			op, ok := rawOp.(map[string]any)
			if !ok {
				t.Fatalf("OpenAPI %s %s is not an operation object", strings.ToUpper(method), path)
			}
			opID, ok := op["operationId"].(string)
			if !ok || strings.TrimSpace(opID) == "" {
				t.Fatalf("OpenAPI %s %s has no operationId", strings.ToUpper(method), path)
			}
			if out[opID] {
				t.Fatalf("OpenAPI operationId %q is duplicated", opID)
			}
			out[opID] = true
		}
	}
	// The discovery coverage surface raised this to 298; the ACME external
	// account binding operator surface (B4: list, disable, enable) raised it to
	// 301 and is mapped onto F5 in the same change; the agent job ledger's
	// operations surface (A1) raised it to 302 and is mapped onto F3; the AD CS
	// certificate template posture read (F1) raised it to 303 and is mapped
	// onto the discovery/posture feature row in the same change; the per-issuer
	// capability matrix (R2) raised it to 304 and is mapped onto the issuer
	// feature rows in the same change; the upstream authorization staleness
	// read (B7) raised it to 305 and is mapped onto the DNS-01 feature row,
	// because it answers "can this deployment still validate" for the same
	// provider configs that row already covers; D2's observed endpoint identity
	// raised it to 306 and is mapped onto F7, the deployment-connector row
	// whose delivery receipts it is the missing half of.
	// M2's crypto readiness raised it to 315 and is mapped onto the same graph
	// row as blast radius and reachability: it is the trust graph answering a
	// different question over the same edges — not who is reachable from a
	// node, but who depends on the crypto a node exhibits.
	// The count is a deliberate ratchet: every new operation must be mapped to
	// a feature-catalog row in the same change.
	// I2's ownership import, its conflict queue, and the CMDB reconcile schedule
	// raised it to 319, all mapped onto the owners feature row: they are that
	// row's data-quality half — where an ownership claim came from, and where two
	// sources disagree. There is deliberately no CMDB *write* operation.
	// I3's five issuance-request lifecycle operations raised it to 324. They map
	// onto the certificates feature row: a request IS the front half of
	// issuance, and giving it its own row would let the request queue look
	// covered while issuance itself regressed.
	// I5's two read-only MDM correlation operations raised it to 326, mapped onto
	// the certificates row: a device's enrollment trace is that row's "did the
	// certificate actually reach the endpoint" half. There is deliberately no
	// MDM write operation.
	// A5's five staged-upgrade operations raised it to 331, mapped onto the
	// agents feature row: a rollout is fleet operation, not a separate product.
	// AUD-14's brand route raised it to 332, mapped onto the platform row: it is
	// how a provider's white-label reaches a customer's screen at all.
	// I2 conflict resolution raised it to 333: the queue was read-only until now.
	// I5's two poll-schedule operations raised it to 335: the correlation
	// surface gained its producer.
	// I3's two intake-schedule operations raised it to 337: tickets became a
	// first-class request origin.
	// B6's seven edge-delegation operations raised it to 344: the constrained
	// edge sub-CA became a served surface — opt-in, attested mint, revocation,
	// and reconciliation of what the no-path host issued.
	// F4's two AD CS certificate-database operations raised it to 346: ingesting
	// certutil rows a domain-joined relay collected, and serving the per-CA
	// lifecycle breakdown issuance alone cannot show.
	// AUD-97's outbox reconciliation recovery read raised it to 347: the
	// Incidents workspace now exposes the tenant-scoped, payload-free evidence
	// for a startup command collision without rebinding the historical key.
	// AUD-77's immutable approval-request list and exact approve/deny endpoints
	// raise it to 350: the approval inbox now reads requests instead of inventing
	// them from inventory state, and every decision binds request ID plus intent
	// digest. Denial closes only the request; it never mutates the target.
	// AUD-28's segment declaration raises it to 351: network and SSH sources now
	// bind a served, event-sourced denominator before a relay can execute them.
	// AUD-38's CRL/OCSP observation read raises it to 352 and maps it onto F47,
	// the revocation infrastructure whose real client-facing health it proves.
	// AUD-40's six durable CA-migration run operations raise it to 358 and map
	// onto F48: they execute the trust-distribute, exact-authority reissue,
	// live-verify, pause/resume, and newest-first rollback half of CA hierarchy
	// management rather than merely describing a rollout.
	// AUD-44's attestOwner plus ownership-exception list/grant/revoke operations
	// raise it to 362 and make the owner application model lifecycle authority.
	// AUD-36's semantic AD CS drift history read raises it to 363 and maps onto
	// discovery: it is the consecutive-sweep history behind F1 posture, not a
	// parallel inventory surface.
	// AUD-39's signed per-segment/per-issuer CRL/OCSP cache read raises it to 364
	// and maps onto F47 beside endpoint health: the former asks whether an
	// upstream is healthy; this one asks whether isolated clients have a fresh
	// validated local copy.
	// AUD-49 adds exact signed endpoint-result readback, an authorized redacted
	// support addendum, and the prove-fixed mutation. AUD-53 raises the ratchet to
	// 370 with the public-only audit verification-key bootstrap. AUD-65 adds the
	// graph-bound readiness action and signed multi-format export, raising it to
	// 372; both map beside graphCryptoReadiness because they complete that same
	// CBOM/graph workflow rather than creating a parallel product feature. The
	// request prepare and evidence-backed completion operations close I3's
	// approved-to-issued bridge, raising the ratchet to 374. Asset-specific,
	// attributed ownership assignment raises it to 375 and maps beside the
	// existing ownership-attribution and attestation governance surface. The
	// read-only effective notification-route preview raises it to 376. The
	// shared typed discovery capability catalog raises it to 377 and maps beside
	// F2 so a backend field cannot quietly outrun the console contract. The
	// state-free server plan preview raises it to 378 and prevents the browser
	// from inventing segment, exclusion, relay, or capacity decisions. The
	// saved-source preflight raises it to 379 and keeps manual and scheduled run
	// admission aligned with the same current relay-readiness answer. The safe,
	// tenant-scoped Transit key metadata list raises it to 380 so the console
	// never has to guess whether an operation-compatible key already exists. The
	// sanitized current-caller capability projection raises it to 381 and maps to
	// F8 because it turns the same route RBAC registry into honest UI action state.
	// The server-authoritative Discovery retry raises it to 382 and maps to F2.
	// The effect-free agent enrollment preview raises it to 383 and maps to F3;
	// unlike the mint route, it creates no token, event, job, or idempotency row.
	// The effect-free issuance-request preview raises it to 384 and maps to F4;
	// request admission calls the same tenant/profile/CSR rule, so review cannot
	// promise a request the mutation would reject or normalize differently.
	// F5's effect-free ACME operator plan raises it to 385 and joins the mounted
	// responder, tenant binding, issuing profile, EAB admission, activation gate,
	// and recovery guidance before the console offers an execution step.
	// F48's effect-free CA ceremony preview raises it to 386 and binds the
	// console's trust-change review to the same exact ceremony request the
	// signer-backed mutation later consumes.
	// F48's effect-free CA rotation preview raises it to 387 and proves both
	// authorities pass the mutation's eligibility rules before confirmation.
	// F53's effect-free profile recovery preview and append-only restore raise it
	// to 389 and expose the full recovery boundary to API clients.
	// F59's effect-free, version-bound identity lifecycle preview raises it to 390.
	// F9's effect-free audit collector-feed preview raises it to 391.
	// F26's secret-free custody plan and effect-free generation preview raise it
	// to 393 and map to the existing HSM integration row.
	if len(out) != 393 {
		t.Fatalf("OpenAPI operationIds = %d, want 393", len(out))
	}
	return out
}
