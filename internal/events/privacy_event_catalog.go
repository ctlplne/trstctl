// SPDX-License-Identifier: MPL-2.0

package events

import (
	"fmt"
	"sort"
)

// ProductionPrivacyEventSchema is one immutable payload vocabulary coordinate.
// Event type alone is not a schema: producers must bump SchemaVersion whenever
// they add, remove, or reshape a payload field.
type ProductionPrivacyEventSchema struct {
	EventType     string
	SchemaVersion int
}

type productionPrivacyEventPolicy struct {
	ProductionPrivacyEventSchema
	Policy PrivacyEventPolicy
}

func catalogPrivacyRule(path string, mode PrivacyFieldMode) PrivacyFieldRule {
	return PrivacyFieldRule{Path: path, Mode: mode}
}

func catalogPrivacyPolicy(shape PrivacyPayloadShape, rules ...PrivacyFieldRule) PrivacyEventPolicy {
	return PrivacyEventPolicy{Rules: rules, PayloadShape: shape}
}

// coreProductionPrivacyEventCatalog owns the non-projector core vocabulary.
// Projector payloads register beside their concrete decoder types; keeping this
// leaf catalog in events avoids an events -> projections import cycle. The EE
// vocabulary has a separate root-ee catalog, loaded only by the full binary.
var coreProductionPrivacyEventCatalog = func() []productionPrivacyEventPolicy {
	const (
		exact  = PrivacyFieldIdentityExact
		token  = PrivacyFieldSubjectToken
		clear  = PrivacyFieldFreeTextClear
		jsonID = PrivacyFieldJSONIdentityValues
		opaque = PrivacyFieldOpaqueExact
	)
	entry := func(eventType string, rules ...PrivacyFieldRule) productionPrivacyEventPolicy {
		shape, ok := coreProductionPrivacyPayloadShape(eventType)
		if !ok {
			panic(fmt.Sprintf("events: core privacy catalog entry %s has no independent payload shape", eventType))
		}
		return productionPrivacyEventPolicy{
			ProductionPrivacyEventSchema: ProductionPrivacyEventSchema{
				EventType: eventType, SchemaVersion: DefaultSchemaVersion,
			},
			Policy: catalogPrivacyPolicy(shape, rules...),
		}
	}
	rejectingEntry := func(eventType string) productionPrivacyEventPolicy {
		shape, ok := coreProductionPrivacyPayloadShape(eventType)
		if !ok {
			panic(fmt.Sprintf("events: rejecting core privacy catalog entry %s has no independent payload shape", eventType))
		}
		return productionPrivacyEventPolicy{
			ProductionPrivacyEventSchema: ProductionPrivacyEventSchema{
				EventType: eventType, SchemaVersion: DefaultSchemaVersion,
			},
			Policy: PrivacyEventPolicy{PayloadShape: shape, RejectSubjectData: true},
		}
	}
	catalog := []productionPrivacyEventPolicy{
		entry("acme.account.upserted",
			catalogPrivacyRule("/seq", opaque), catalogPrivacyRule("/id", opaque),
			catalogPrivacyRule("/url", opaque), catalogPrivacyRule("/jwk", opaque),
			catalogPrivacyRule("/contact/*", token), catalogPrivacyRule("/status", opaque),
			catalogPrivacyRule("/eab_key_id", opaque)),
		entry("acme.ari.early_renewal_marked", catalogPrivacyRule("/cert_id", opaque)),
		entry("acme.certificate.issued",
			catalogPrivacyRule("/seq", opaque), catalogPrivacyRule("/order_id", opaque),
			catalogPrivacyRule("/cert_id", opaque), catalogPrivacyRule("/certificate_pem", opaque),
			catalogPrivacyRule("/ari_cert_id", opaque), catalogPrivacyRule("/not_before", opaque),
			catalogPrivacyRule("/not_after", opaque), catalogPrivacyRule("/fingerprint", opaque),
			catalogPrivacyRule("/issued/account_url", opaque), catalogPrivacyRule("/issued/key_thumb", opaque),
			catalogPrivacyRule("/issued/serial", opaque), catalogPrivacyRule("/issued/cert_id", opaque)),
		entry("acme.certificate.revoked",
			catalogPrivacyRule("/fingerprint", opaque), catalogPrivacyRule("/serial", opaque),
			catalogPrivacyRule("/reason", opaque), catalogPrivacyRule("/at", opaque)),
		entry("acme.challenge.validated",
			catalogPrivacyRule("/challenge_id", opaque), catalogPrivacyRule("/authz_id", opaque),
			catalogPrivacyRule("/order_id", opaque), catalogPrivacyRule("/challenge_status", opaque),
			catalogPrivacyRule("/authz_status", opaque), catalogPrivacyRule("/order_status", opaque),
			catalogPrivacyRule("/attested_key_sha256", opaque)),
		entry("acme.eab.order_denied",
			catalogPrivacyRule("/account_url", opaque), catalogPrivacyRule("/eab_key_id", opaque),
			catalogPrivacyRule("/identifiers/*", token), catalogPrivacyRule("/reason", clear)),
		entry("acme.order.created",
			catalogPrivacyRule("/seq", opaque),
			catalogPrivacyRule("/order/id", opaque), catalogPrivacyRule("/order/account_url", opaque),
			catalogPrivacyRule("/order/domains/*", token), catalogPrivacyRule("/order/authz_ids/*", opaque),
			catalogPrivacyRule("/order/status", opaque), catalogPrivacyRule("/order/auth_mode", opaque),
			catalogPrivacyRule("/order/cert_id", opaque), catalogPrivacyRule("/order/replaces", opaque),
			catalogPrivacyRule("/order/attested_key_sha256", opaque), catalogPrivacyRule("/order/created_at", opaque),
			catalogPrivacyRule("/authorizations/*/id", opaque), catalogPrivacyRule("/authorizations/*/order_id", opaque),
			catalogPrivacyRule("/authorizations/*/domain", token), catalogPrivacyRule("/authorizations/*/status", opaque),
			catalogPrivacyRule("/authorizations/*/created_at", opaque),
			catalogPrivacyRule("/authorizations/*/challenges/*/id", opaque),
			catalogPrivacyRule("/authorizations/*/challenges/*/type", opaque),
			catalogPrivacyRule("/authorizations/*/challenges/*/token", opaque),
			catalogPrivacyRule("/authorizations/*/challenges/*/status", opaque),
			catalogPrivacyRule("/authorizations/*/challenges/*/authz_id", opaque)),
		entry("agent.identity.issued",
			catalogPrivacyRule("/agent_id", exact), catalogPrivacyRule("/credential_id", opaque),
			catalogPrivacyRule("/subject", token)),
		entry("agent.identity.refused",
			catalogPrivacyRule("/agent_id", exact), catalogPrivacyRule("/reason", clear)),
		entry("agent.identity.revoked",
			catalogPrivacyRule("/agent_id", exact), catalogPrivacyRule("/credentials", opaque)),
		entry("ai.query.answered",
			catalogPrivacyRule("/subject", token), catalogPrivacyRule("/rows", opaque),
			catalogPrivacyRule("/citations", opaque), catalogPrivacyRule("/grounded", opaque)),
		entry("attestation.bound",
			catalogPrivacyRule("/attestation_id", opaque), catalogPrivacyRule("/credential_id", opaque),
			catalogPrivacyRule("/method", opaque)),
		entry("attestation.rejected",
			catalogPrivacyRule("/method", opaque), catalogPrivacyRule("/error", clear)),
		entry("attestation.verified",
			catalogPrivacyRule("/id", opaque), catalogPrivacyRule("/method", opaque),
			catalogPrivacyRule("/subject", token), catalogPrivacyRule("/selectors/*", token),
			catalogPrivacyRule("/claims", jsonID), catalogPrivacyRule("/verified_at", opaque)),
		entry("auth.rejected", catalogPrivacyRule("/method", opaque)),
		entry("auth.session.issued",
			catalogPrivacyRule("/method", opaque), catalogPrivacyRule("/principal", exact),
			catalogPrivacyRule("/scopes", opaque)),
		entry("breakglass.admin_login",
			catalogPrivacyRule("/actor_id", exact), catalogPrivacyRule("/outcome", opaque)),
		entry("broker.agent_identity.task_bound",
			catalogPrivacyRule("/agent_id", exact), catalogPrivacyRule("/credential_id", opaque),
			catalogPrivacyRule("/task_envelope_digest", opaque)),
		entry("codesign.keyless.refused",
			catalogPrivacyRule("/principal", exact), catalogPrivacyRule("/reason", clear),
			catalogPrivacyRule("/claimed_san", token), catalogPrivacyRule("/verified_san", token)),
		entry("codesign.keyless.signed",
			catalogPrivacyRule("/principal", exact), catalogPrivacyRule("/fulcio_san", token),
			catalogPrivacyRule("/fulcio_issuer", opaque), catalogPrivacyRule("/artifact_type", opaque)),
		entry("codesign.refused",
			catalogPrivacyRule("/principal", exact), catalogPrivacyRule("/key", opaque),
			catalogPrivacyRule("/reason", clear)),
		entry("codesign.signed",
			catalogPrivacyRule("/principal", exact), catalogPrivacyRule("/key", opaque),
			catalogPrivacyRule("/artifact_type", opaque), catalogPrivacyRule("/digest", opaque)),
		entry("ct.submission.delivered",
			catalogPrivacyRule("/capability", opaque), catalogPrivacyRule("/submission_id", opaque),
			catalogPrivacyRule("/log_url", opaque), catalogPrivacyRule("/entry_type", opaque),
			catalogPrivacyRule("/leaf_sha256_fingerprint", opaque), catalogPrivacyRule("/subject", token),
			catalogPrivacyRule("/serial_number", opaque), catalogPrivacyRule("/delivered_at", opaque)),
		entry("ct.submission.queued",
			catalogPrivacyRule("/capability", opaque), catalogPrivacyRule("/requested_by", exact),
			catalogPrivacyRule("/queued_at", opaque), catalogPrivacyRule("/submission_ids", opaque),
			catalogPrivacyRule("/outbox_keys", opaque), catalogPrivacyRule("/logs", opaque),
			catalogPrivacyRule("/fingerprints", opaque),
			catalogPrivacyRule("/payloads/*/capability", opaque),
			catalogPrivacyRule("/payloads/*/submission_id", opaque),
			catalogPrivacyRule("/payloads/*/log_url", opaque),
			catalogPrivacyRule("/payloads/*/entry_type", opaque),
			// Certificate bytes are the only intentionally closed binary subtrees.
			// The containing payload stays open to the exact rules below so its
			// subject and requester cannot hide behind one opaque parent.
			catalogPrivacyRule("/payloads/*/leaf_der", opaque),
			catalogPrivacyRule("/payloads/*/chain_der", opaque),
			catalogPrivacyRule("/payloads/*/leaf_sha256_fingerprint", opaque),
			catalogPrivacyRule("/payloads/*/subject", token),
			catalogPrivacyRule("/payloads/*/serial_number", opaque),
			catalogPrivacyRule("/payloads/*/requested_by", exact),
			catalogPrivacyRule("/payloads/*/idempotency_key", opaque),
			catalogPrivacyRule("/payloads/*/allow_private_endpoint", opaque),
			catalogPrivacyRule("/payloads/*/private_egress_cidrs", opaque),
			catalogPrivacyRule("/payloads/*/submission_profile", opaque),
			catalogPrivacyRule("/payloads/*/operator_correlation_ref", token),
			catalogPrivacyRule("/payloads/*/queued_at", opaque)),
		entry("discovery.found",
			catalogPrivacyRule("/kind", opaque), catalogPrivacyRule("/ref", token),
			catalogPrivacyRule("/source", opaque), catalogPrivacyRule("/provenance", token)),
		entry("discovery.network_target_blocked",
			catalogPrivacyRule("/run_id", opaque), catalogPrivacyRule("/source_id", opaque),
			catalogPrivacyRule("/target", token), catalogPrivacyRule("/reason", clear)),
		entry("discovery.ssh_target_blocked",
			catalogPrivacyRule("/run_id", opaque), catalogPrivacyRule("/source_id", opaque),
			catalogPrivacyRule("/target", token), catalogPrivacyRule("/reason", clear)),
		rejectingEntry("dynsecret.lease.revoked"),
		entry("ephemeral.issued",
			catalogPrivacyRule("/subject", token), catalogPrivacyRule("/method", opaque),
			catalogPrivacyRule("/ttl_seconds", opaque), catalogPrivacyRule("/not_after", opaque)),
		entry("history.tenant_data_rewrite.continuity", catalogPrivacyRule("/jws", opaque)),
		entry("issuance.host_renewal_dispatched",
			catalogPrivacyRule("/identity_id", opaque), catalogPrivacyRule("/target_id", opaque),
			catalogPrivacyRule("/target_name", token), catalogPrivacyRule("/connector", opaque),
			catalogPrivacyRule("/dns_names", opaque), catalogPrivacyRule("/custody", opaque),
			catalogPrivacyRule("/detail", clear)),
		entry("issuance.profile_evaluated",
			catalogPrivacyRule("/profile", opaque), catalogPrivacyRule("/version", opaque),
			catalogPrivacyRule("/decision", opaque), catalogPrivacyRule("/reason", clear),
			catalogPrivacyRule("/protocol", opaque)),
		entry("issuance.server_side_keygen",
			catalogPrivacyRule("/identity_id", opaque), catalogPrivacyRule("/name", token),
			catalogPrivacyRule("/detail", clear), catalogPrivacyRule("/successor", clear)),
		entry("itsm.ticket.requested",
			catalogPrivacyRule("/id", opaque), catalogPrivacyRule("/instance_url", opaque),
			catalogPrivacyRule("/table", opaque), catalogPrivacyRule("/token_ref", opaque),
			catalogPrivacyRule("/short_description", clear), catalogPrivacyRule("/description", clear),
			catalogPrivacyRule("/category", clear), catalogPrivacyRule("/urgency", opaque),
			catalogPrivacyRule("/impact", opaque), catalogPrivacyRule("/correlation_id", opaque),
			catalogPrivacyRule("/allow_private_endpoint", opaque), catalogPrivacyRule("/private_egress_cidrs", opaque),
			catalogPrivacyRule("/requested_by", exact)),
		entry("lifecycle.renewal.deferred",
			catalogPrivacyRule("/reason", clear), catalogPrivacyRule("/deferred_at", opaque),
			catalogPrivacyRule("/window_open", opaque)),
		entry("mcp.tool.call",
			catalogPrivacyRule("/caller", exact), catalogPrivacyRule("/tool", opaque),
			catalogPrivacyRule("/scope", opaque), catalogPrivacyRule("/citations", opaque),
			catalogPrivacyRule("/outcome", opaque)),
		entry("mcp.tool.denied",
			catalogPrivacyRule("/caller", exact), catalogPrivacyRule("/tool", opaque),
			catalogPrivacyRule("/reason", clear)),
		entry("mcp.tool.ratelimited",
			catalogPrivacyRule("/caller", exact), catalogPrivacyRule("/tool", opaque)),
		entry("mcp.tool.rest",
			catalogPrivacyRule("/caller", exact), catalogPrivacyRule("/tool", opaque),
			catalogPrivacyRule("/method", opaque), catalogPrivacyRule("/path", token),
			catalogPrivacyRule("/status", opaque)),
		entry("mcp.tool.write",
			catalogPrivacyRule("/caller", exact), catalogPrivacyRule("/tool", opaque),
			catalogPrivacyRule("/authority_id", opaque), catalogPrivacyRule("/serial", opaque),
			catalogPrivacyRule("/reason", clear)),
		entry("mdm.intune_scep_challenge.replay_rejected",
			catalogPrivacyRule("/decision", opaque), catalogPrivacyRule("/reason", clear),
			catalogPrivacyRule("/transaction_id", opaque), catalogPrivacyRule("/nonce", opaque)),
		entry("policy.abac.decision",
			catalogPrivacyRule("/permission", opaque), catalogPrivacyRule("/action", opaque),
			catalogPrivacyRule("/actor", exact), catalogPrivacyRule("/subject", token),
			catalogPrivacyRule("/deny", opaque), catalogPrivacyRule("/reason", clear),
			catalogPrivacyRule("/error", clear)),
		entry("policy.decision",
			catalogPrivacyRule("/action", opaque), catalogPrivacyRule("/profile", opaque),
			catalogPrivacyRule("/actor", exact), catalogPrivacyRule("/allow", opaque),
			catalogPrivacyRule("/reason", clear), catalogPrivacyRule("/error", clear)),
		entry("policy.dry_run.evaluated",
			catalogPrivacyRule("/kind", opaque), catalogPrivacyRule("/valid", opaque),
			catalogPrivacyRule("/module_sha256", opaque), catalogPrivacyRule("/allow", opaque),
			catalogPrivacyRule("/deny", opaque), catalogPrivacyRule("/reason", clear),
			catalogPrivacyRule("/error", clear), catalogPrivacyRule("/input_summary/action", opaque),
			catalogPrivacyRule("/input_summary/permission", opaque), catalogPrivacyRule("/input_summary/profile", opaque),
			catalogPrivacyRule("/input_summary/subject", token), catalogPrivacyRule("/input_summary/actor", exact),
			catalogPrivacyRule("/input_summary/tenant_id", opaque), catalogPrivacyRule("/idempotency_key", opaque)),
		entry("pkisecret.issued",
			catalogPrivacyRule("/name", token), catalogPrivacyRule("/version", opaque)),
		entry("profile.edit_approval.approved",
			catalogPrivacyRule("/id", opaque), catalogPrivacyRule("/approver", exact),
			catalogPrivacyRule("/requester", exact), catalogPrivacyRule("/resource", token)),
		entry("profile.edit_approval.refused",
			catalogPrivacyRule("/id", opaque), catalogPrivacyRule("/approver", exact),
			catalogPrivacyRule("/reason", clear)),
		entry("profile.edit_approval.requested",
			catalogPrivacyRule("/request/id", opaque), catalogPrivacyRule("/request/tenant_id", opaque),
			catalogPrivacyRule("/request/kind", opaque), catalogPrivacyRule("/request/resource", token),
			catalogPrivacyRule("/request/requester", exact), catalogPrivacyRule("/request/required_approvals", opaque),
			catalogPrivacyRule("/request/approvals", opaque), catalogPrivacyRule("/request/state", opaque),
			catalogPrivacyRule("/request/credential_id", opaque), catalogPrivacyRule("/request/payload", opaque),
			catalogPrivacyRule("/request/created_at", opaque), catalogPrivacyRule("/request/expires_at", opaque),
			catalogPrivacyRule("/name", token), catalogPrivacyRule("/spec", opaque)),
		entry("protocol.cmp.enroll",
			catalogPrivacyRule("/op", opaque), catalogPrivacyRule("/decision", opaque),
			catalogPrivacyRule("/reason", clear), catalogPrivacyRule("/transaction_id", opaque),
			catalogPrivacyRule("/profile", opaque)),
		entry("protocol.est.cacerts",
			catalogPrivacyRule("/op", opaque), catalogPrivacyRule("/decision", opaque),
			catalogPrivacyRule("/reason", clear), catalogPrivacyRule("/profile", opaque)),
		entry("protocol.est.serverkeygen",
			catalogPrivacyRule("/op", opaque), catalogPrivacyRule("/decision", opaque),
			catalogPrivacyRule("/reason", clear), catalogPrivacyRule("/profile", opaque)),
		entry("protocol.est.simpleenroll",
			catalogPrivacyRule("/op", opaque), catalogPrivacyRule("/decision", opaque),
			catalogPrivacyRule("/reason", clear), catalogPrivacyRule("/profile", opaque)),
		entry("protocol.est.simplereenroll",
			catalogPrivacyRule("/op", opaque), catalogPrivacyRule("/decision", opaque),
			catalogPrivacyRule("/reason", clear), catalogPrivacyRule("/profile", opaque)),
		entry("protocol.issued",
			catalogPrivacyRule("/protocol", opaque), catalogPrivacyRule("/serial", opaque),
			catalogPrivacyRule("/decision", opaque)),
		entry("protocol.revoked",
			catalogPrivacyRule("/protocol", opaque), catalogPrivacyRule("/serial", opaque),
			catalogPrivacyRule("/reason_code", opaque), catalogPrivacyRule("/decision", opaque)),
		entry("protocol.scep.enroll",
			catalogPrivacyRule("/op", opaque), catalogPrivacyRule("/decision", opaque),
			catalogPrivacyRule("/reason", clear), catalogPrivacyRule("/transaction_id", opaque),
			catalogPrivacyRule("/profile", opaque)),
		entry("protocol.scep.issuance.observed",
			catalogPrivacyRule("/transaction_id", opaque), catalogPrivacyRule("/device_serial", token),
			catalogPrivacyRule("/profile", opaque), catalogPrivacyRule("/outcome", opaque),
			catalogPrivacyRule("/detail", clear), catalogPrivacyRule("/certificate_serial", opaque),
			catalogPrivacyRule("/certificate_fingerprint", opaque), catalogPrivacyRule("/certificate_not_after", opaque)),
		entry("protocol.scep.request.observed",
			catalogPrivacyRule("/transaction_id", opaque), catalogPrivacyRule("/device_serial", token),
			catalogPrivacyRule("/profile", opaque), catalogPrivacyRule("/outcome", opaque),
			catalogPrivacyRule("/detail", clear), catalogPrivacyRule("/certificate_serial", opaque),
			catalogPrivacyRule("/certificate_fingerprint", opaque), catalogPrivacyRule("/certificate_not_after", opaque)),
		entry("rca.evidence.gathered",
			catalogPrivacyRule("/subject", token), catalogPrivacyRule("/items", opaque)),
		entry("rotation.completed", catalogPrivacyRule("/key", token), catalogPrivacyRule("/phase", opaque)),
		entry("rotation.failed", catalogPrivacyRule("/key", token), catalogPrivacyRule("/phase", opaque)),
		entry("rotation.queued", catalogPrivacyRule("/key", token), catalogPrivacyRule("/phase", opaque)),
		entry("rotation.retire_pending", catalogPrivacyRule("/key", token), catalogPrivacyRule("/phase", opaque)),
		entry("rotation.rollback_failed", catalogPrivacyRule("/key", token), catalogPrivacyRule("/phase", opaque)),
		entry("rotation.rolled_back", catalogPrivacyRule("/key", token), catalogPrivacyRule("/phase", opaque)),
		entry("rotation.staged", catalogPrivacyRule("/key", token), catalogPrivacyRule("/phase", opaque)),
		entry("secret.access",
			catalogPrivacyRule("/principal", exact), catalogPrivacyRule("/path", token),
			catalogPrivacyRule("/action", opaque), catalogPrivacyRule("/decision", opaque)),
		entry("secret.access.denied",
			catalogPrivacyRule("/principal", exact), catalogPrivacyRule("/path", token),
			catalogPrivacyRule("/reason", clear)),
		entry("secret.imported",
			catalogPrivacyRule("/name", token), catalogPrivacyRule("/version", opaque)),
		entry("secret.purged", catalogPrivacyRule("/path", token)),
		entry("secret.rotation.completed",
			catalogPrivacyRule("/name", token), catalogPrivacyRule("/version", opaque)),
		entry("secret.rotation.queued",
			catalogPrivacyRule("/name", token), catalogPrivacyRule("/version", opaque)),
		entry("secret.rotation_schedule.completed",
			catalogPrivacyRule("/name", token), catalogPrivacyRule("/version", opaque)),
		entry("secret.rotation_schedule.queued",
			catalogPrivacyRule("/name", token), catalogPrivacyRule("/version", opaque)),
		entry("secret.share.viewed",
			catalogPrivacyRule("/share_id", opaque), catalogPrivacyRule("/token_sha256", opaque)),
		entry("secret.shared",
			catalogPrivacyRule("/share_id", opaque), catalogPrivacyRule("/token_sha256", opaque)),
		entry("secret.sync.delivered",
			catalogPrivacyRule("/key", token), catalogPrivacyRule("/target", token),
			catalogPrivacyRule("/id", opaque), catalogPrivacyRule("/attempts", opaque),
			catalogPrivacyRule("/remote_version", opaque)),
		entry("secret.sync.enqueued", catalogPrivacyRule("/key", token), catalogPrivacyRule("/target", token)),
		entry("secret.sync.requested",
			catalogPrivacyRule("/name", token), catalogPrivacyRule("/version", opaque)),
		entry("secret.version.written",
			catalogPrivacyRule("/path", token), catalogPrivacyRule("/version", opaque),
			catalogPrivacyRule("/sealed", opaque), catalogPrivacyRule("/envelope", opaque),
			catalogPrivacyRule("/name", token), catalogPrivacyRule("/written_at", opaque),
			catalogPrivacyRule("/recovered_from_version", opaque)),
		entry("secretscan.finding",
			catalogPrivacyRule("/scanner", opaque), catalogPrivacyRule("/rule", opaque),
			catalogPrivacyRule("/file", token), catalogPrivacyRule("/ref", token)),
		entry("secretscli.fetch", catalogPrivacyRule("/path", token)),
		entry("secretscli.inject", catalogPrivacyRule("/vars/*", token)),
		entry("secretscli.set", catalogPrivacyRule("/path", token)),
		entry("spiffe.svid.issued",
			catalogPrivacyRule("/type", opaque), catalogPrivacyRule("/spiffe_id", token)),
		entry("spiffe.workload_api.local_socket_used",
			catalogPrivacyRule("/type", opaque), catalogPrivacyRule("/detail", clear)),
		entry("ssh.attested_cert.issued",
			catalogPrivacyRule("/key_id", token), catalogPrivacyRule("/serial", opaque),
			catalogPrivacyRule("/method", opaque), catalogPrivacyRule("/subject", token),
			catalogPrivacyRule("/approver", exact), catalogPrivacyRule("/principals/*", token),
			catalogPrivacyRule("/critical_options", opaque)),
		entry("ssh.cert.issued",
			catalogPrivacyRule("/type", opaque), catalogPrivacyRule("/key_id", token),
			catalogPrivacyRule("/serial", opaque), catalogPrivacyRule("/principals", opaque),
			catalogPrivacyRule("/profile", opaque)),
		entry("ssh.trust.added", catalogPrivacyRule("/detail", clear)),
		entry("ssh.trust.removed", catalogPrivacyRule("/detail", clear)),
		entry("ssh.trust.rollback_failed", catalogPrivacyRule("/detail", clear)),
		entry("ssh.trust.rolled_back", catalogPrivacyRule("/detail", clear)),
		entry("transit.decrypt", catalogPrivacyRule("/key", token)),
		entry("transit.encrypt", catalogPrivacyRule("/key", token)),
		entry("transit.hmac", catalogPrivacyRule("/key", token)),
		entry("transit.key.created", catalogPrivacyRule("/key", token)),
		entry("transit.key.rotated", catalogPrivacyRule("/key", token)),
		entry("transit.rewrap", catalogPrivacyRule("/key", token)),
		entry("transit.sign", catalogPrivacyRule("/key", token)),
		entry("transit.verify", catalogPrivacyRule("/key", token)),
		entry("tsa.timestamp.issued",
			catalogPrivacyRule("/serial", opaque), catalogPrivacyRule("/gen_time", opaque)),
		entry("vault.compat.mount.disabled",
			catalogPrivacyRule("/path", token), catalogPrivacyRule("/type", opaque),
			catalogPrivacyRule("/description", clear), catalogPrivacyRule("/options", jsonID)),
		entry("vault.compat.mount.enabled",
			catalogPrivacyRule("/path", token), catalogPrivacyRule("/type", opaque),
			catalogPrivacyRule("/description", clear), catalogPrivacyRule("/options", jsonID)),
		entry("vault.compat.policy.deleted", catalogPrivacyRule("/name", token), catalogPrivacyRule("/policy", opaque)),
		entry("vault.compat.policy.put", catalogPrivacyRule("/name", token), catalogPrivacyRule("/policy", clear)),
	}
	sort.Slice(catalog, func(i, j int) bool {
		if catalog[i].EventType == catalog[j].EventType {
			return catalog[i].SchemaVersion < catalog[j].SchemaVersion
		}
		return catalog[i].EventType < catalog[j].EventType
	})
	return catalog
}()

// CoreProductionPrivacyEventSchemas returns a defensive copy of the exact core
// non-projector vocabulary. It is used by assembly tests and by static census
// guards; callers cannot mutate the registered catalog.
func CoreProductionPrivacyEventSchemas() []ProductionPrivacyEventSchema {
	out := make([]ProductionPrivacyEventSchema, len(coreProductionPrivacyEventCatalog))
	for i, entry := range coreProductionPrivacyEventCatalog {
		out[i] = entry.ProductionPrivacyEventSchema
	}
	return out
}

func init() {
	seen := make(map[ProductionPrivacyEventSchema]struct{}, len(coreProductionPrivacyEventCatalog))
	for _, entry := range coreProductionPrivacyEventCatalog {
		if _, duplicate := seen[entry.ProductionPrivacyEventSchema]; duplicate {
			panic(fmt.Sprintf("events: duplicate core privacy catalog entry for %s v%d", entry.EventType, entry.SchemaVersion))
		}
		seen[entry.ProductionPrivacyEventSchema] = struct{}{}
		if err := RegisterPrivacyEventPolicy(entry.EventType, entry.SchemaVersion, entry.Policy); err != nil {
			panic(fmt.Sprintf("events: register core privacy catalog entry %s v%d: %v", entry.EventType, entry.SchemaVersion, err))
		}
	}
}
