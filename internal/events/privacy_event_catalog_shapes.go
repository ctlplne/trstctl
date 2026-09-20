// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// catalogPrivacyShapeOptions makes the non-projector catalog state its JSON
// contract independently of its privacy modes. Example contains every known
// field with one representative array element. Optional removes the named
// field from its parent's required set; Nullable preserves a concrete kind but
// also permits JSON null; DynamicObject declares a string-keyed map; Open
// declares an intentionally schemaless json.RawMessage/interface subtree.
type catalogPrivacyShapeOptions struct {
	Optional      []string
	Nullable      []string
	DynamicObject []string
	Open          []string
}

func catalogPrivacyPayloadShape(example string, options catalogPrivacyShapeOptions) PrivacyPayloadShape {
	data := []byte(example)
	if !json.Valid(data) {
		panic(fmt.Sprintf("events: invalid privacy catalog shape example %q", example))
	}
	if err := validatePrivacyJSONUniqueKeys(data); err != nil {
		panic(fmt.Sprintf("events: invalid privacy catalog shape example: %v", err))
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		panic(fmt.Sprintf("events: decode privacy catalog shape example: %v", err))
	}
	root := catalogPrivacyShapeNode(value)
	if root.kind != privacyPayloadShapeObject {
		panic("events: privacy catalog payload shape root must be an object")
	}
	for _, path := range options.Optional {
		parent, field := catalogPrivacyShapeParent(root, path)
		if parent.kind != privacyPayloadShapeObject {
			panic(fmt.Sprintf("events: optional privacy catalog path %q has a non-object parent", path))
		}
		if _, exists := parent.fields[field]; !exists {
			panic(fmt.Sprintf("events: optional privacy catalog path %q is absent", path))
		}
		delete(parent.requiredFields, field)
	}
	for _, path := range options.Nullable {
		catalogPrivacyShapeAt(root, path).nullable = true
	}
	for _, path := range options.DynamicObject {
		node := catalogPrivacyShapeAt(root, path)
		if node.kind != privacyPayloadShapeObject {
			panic(fmt.Sprintf("events: dynamic privacy catalog path %q is not represented as an object", path))
		}
		node.kind = privacyPayloadShapeMap
		node.fields = nil
		node.requiredFields = nil
		node.element = &privacyPayloadShapeNode{kind: privacyPayloadShapeOpen, nullable: true}
	}
	for _, path := range options.Open {
		node := catalogPrivacyShapeAt(root, path)
		node.kind = privacyPayloadShapeOpen
		node.fields = nil
		node.requiredFields = nil
		node.element = nil
	}
	return PrivacyPayloadShape{root: root}
}

func catalogPrivacyShapeNode(value any) *privacyPayloadShapeNode {
	switch typed := value.(type) {
	case string:
		return &privacyPayloadShapeNode{kind: privacyPayloadShapeScalar, scalar: privacyPayloadScalarString}
	case json.Number:
		return &privacyPayloadShapeNode{kind: privacyPayloadShapeScalar, scalar: privacyPayloadScalarNumber}
	case bool:
		return &privacyPayloadShapeNode{kind: privacyPayloadShapeScalar, scalar: privacyPayloadScalarBoolean}
	case map[string]any:
		node := &privacyPayloadShapeNode{
			kind: privacyPayloadShapeObject, fields: make(map[string]*privacyPayloadShapeNode, len(typed)),
			requiredFields: make(map[string]struct{}, len(typed)),
		}
		for field, child := range typed {
			node.fields[field] = catalogPrivacyShapeNode(child)
			node.requiredFields[field] = struct{}{}
		}
		return node
	case []any:
		if len(typed) != 1 {
			panic("events: privacy catalog array example must contain exactly one element")
		}
		return &privacyPayloadShapeNode{
			kind: privacyPayloadShapeArray, nullable: true,
			element: catalogPrivacyShapeNode(typed[0]),
		}
	case nil:
		panic("events: privacy catalog examples use Nullable with a concrete non-null value")
	default:
		panic(fmt.Sprintf("events: unsupported privacy catalog shape example value %T", value))
	}
}

func catalogPrivacyShapeAt(root *privacyPayloadShapeNode, path string) *privacyPayloadShapeNode {
	segments := parsePrivacyPath(path)
	node := root
	for _, segment := range segments {
		switch {
		case segment == "*" && node.kind == privacyPayloadShapeArray:
			node = node.element
		case node.kind == privacyPayloadShapeObject:
			node = node.fields[segment]
		default:
			node = nil
		}
		if node == nil {
			panic(fmt.Sprintf("events: privacy catalog shape path %q is absent", path))
		}
	}
	return node
}

func catalogPrivacyShapeParent(root *privacyPayloadShapeNode, path string) (*privacyPayloadShapeNode, string) {
	segments := parsePrivacyPath(path)
	if len(segments) == 0 {
		panic("events: privacy catalog field path is empty")
	}
	if len(segments) == 1 {
		return root, segments[0]
	}
	parentPath := "/"
	for i, segment := range segments[:len(segments)-1] {
		if i > 0 {
			parentPath += "/"
		}
		parentPath += segment
	}
	return catalogPrivacyShapeAt(root, parentPath), segments[len(segments)-1]
}

// coreProductionPrivacyPayloadShape is deliberately a separate switch from the
// privacy-rule catalog. A mode such as opaque_exact says what erasure may do; it
// does not say whether the producer encoded a string, number, array, or object.
// Keeping the shape here prevents a mode edit from silently widening JSON.
func coreProductionPrivacyPayloadShape(eventType string) (PrivacyPayloadShape, bool) {
	shape := func(example string, options ...catalogPrivacyShapeOptions) PrivacyPayloadShape {
		if len(options) == 0 {
			return catalogPrivacyPayloadShape(example, catalogPrivacyShapeOptions{})
		}
		if len(options) != 1 {
			panic("events: core privacy shape accepts at most one option set")
		}
		return catalogPrivacyPayloadShape(example, options[0])
	}
	switch eventType {
	case "acme.account.upserted":
		return shape(`{"seq":1,"id":"","url":"","jwk":{},"contact":[""],"status":"","eab_key_id":""}`,
			catalogPrivacyShapeOptions{
				Optional: []string{"/seq", "/contact", "/eab_key_id"},
				Open:     []string{"/jwk"}, Nullable: []string{"/jwk"},
			}), true
	case "acme.ari.early_renewal_marked":
		return shape(`{"cert_id":""}`), true
	case "acme.certificate.issued":
		return shape(`{"seq":1,"order_id":"","cert_id":"","certificate_pem":"","ari_cert_id":"","not_before":"","not_after":"","fingerprint":"","issued":{"account_url":"","key_thumb":"","serial":"","cert_id":""}}`,
			catalogPrivacyShapeOptions{
				Optional: []string{"/seq", "/ari_cert_id", "/not_before", "/not_after", "/fingerprint", "/issued/key_thumb", "/issued/serial"},
				Nullable: []string{"/certificate_pem"},
			}), true
	case "acme.certificate.revoked":
		return shape(`{"fingerprint":"","serial":"","reason":1,"at":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/serial"}}), true
	case "acme.challenge.validated":
		return shape(`{"challenge_id":"","authz_id":"","order_id":"","challenge_status":"","authz_status":"","order_status":"","attested_key_sha256":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/order_status", "/attested_key_sha256"}}), true
	case "acme.dns01.plugin.presented", "acme.dns01.plugin.cleaned",
		"acme.dns01.plugin.denied", "acme.dns01.plugin.failed":
		return shape(`{"provider":"","record_name":"","detail":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/detail"}}), true
	case "acme.eab.order_denied":
		return shape(`{"account_url":"","eab_key_id":"","identifiers":[""],"reason":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/identifiers"}}), true
	case "acme.order.created":
		return shape(`{"seq":1,"order":{"id":"","account_url":"","issuance_key":"","domains":[""],"authz_ids":[""],"status":"","auth_mode":"","cert_id":"","replaces":"","attested_key_sha256":"","created_at":""},"authorizations":[{"id":"","order_id":"","domain":"","status":"","created_at":"","challenges":[{"id":"","type":"","token":"","status":"","authz_id":""}]}]}`,
			catalogPrivacyShapeOptions{Optional: []string{
				"/seq", "/order/issuance_key", "/order/auth_mode", "/order/cert_id", "/order/replaces", "/order/attested_key_sha256",
			}}), true
	case "agent.identity.issued":
		return shape(`{"agent_id":"","credential_id":"","subject":""}`), true
	case "agent.identity.refused":
		return shape(`{"agent_id":"","reason":""}`), true
	case "agent.identity.revoked":
		return shape(`{"agent_id":"","credentials":1}`), true
	case "ai.query.answered":
		return shape(`{"subject":"","rows":1,"citations":1,"grounded":true}`), true
	case "attestation.bound":
		return shape(`{"attestation_id":"","credential_id":"","method":""}`), true
	case "attestation.rejected":
		return shape(`{"method":"","error":""}`), true
	case "attestation.verified":
		return shape(`{"id":"","method":"","subject":"","selectors":[""],"claims":{"key":""},"verified_at":""}`,
			catalogPrivacyShapeOptions{DynamicObject: []string{"/claims"}, Nullable: []string{"/claims"}}), true
	case "auth.rejected":
		return shape(`{"method":""}`), true
	case "auth.session.issued":
		return shape(`{"method":"","principal":"","scopes":1}`), true
	case "breakglass.admin_login":
		return shape(`{"actor_id":"","outcome":""}`), true
	case "certificate.expiring":
		return shape(`{"certificate_id":"","serial":"","not_after":""}`), true
	case "broker.agent_identity.task_bound":
		return shape(`{"agent_id":"","credential_id":"","task_envelope_digest":""}`), true
	case "codesign.keyless.refused":
		return shape(`{"principal":"","reason":"","claimed_san":"","verified_san":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/claimed_san", "/verified_san"}}), true
	case "codesign.keyless.signed":
		return shape(`{"principal":"","fulcio_san":"","fulcio_issuer":"","artifact_type":""}`), true
	case "codesign.refused":
		return shape(`{"principal":"","key":"","reason":""}`), true
	case "codesign.signed":
		return shape(`{"principal":"","key":"","artifact_type":"","digest":""}`), true
	case "connector.rollback.requested":
		return shape(`{"connector":"","target":"","target_id":"","identity_id":"","target_config":{"key":""},"predecessor_fingerprint":"","predecessor_serial":"","successor_fingerprint":"","reason":"","requested_by":"","required_agent_id":"","required_agent_role":""}`,
			catalogPrivacyShapeOptions{
				Optional: []string{
					"/target_id", "/identity_id", "/target_config", "/predecessor_serial",
					"/successor_fingerprint", "/reason", "/requested_by", "/required_agent_id",
					"/required_agent_role",
				},
				DynamicObject: []string{"/target_config"},
			}), true
	case "ct.submission.delivered":
		return shape(`{"capability":"","submission_id":"","log_url":"","entry_type":"","leaf_sha256_fingerprint":"","subject":"","serial_number":"","delivered_at":""}`), true
	case "ct.submission.queued":
		return shape(`{"capability":"","requested_by":"","queued_at":"","submission_ids":[""],"outbox_keys":[""],"logs":[""],"fingerprints":[""],"payloads":[{"capability":"","submission_id":"","log_url":"","entry_type":"","leaf_der":"","chain_der":[""],"leaf_sha256_fingerprint":"","subject":"","serial_number":"","requested_by":"","idempotency_key":"","allow_private_endpoint":true,"private_egress_cidrs":[""],"submission_profile":"","operator_correlation_ref":"","queued_at":""}]}`,
			catalogPrivacyShapeOptions{
				Optional: []string{
					"/requested_by", "/payloads", "/payloads/*/chain_der", "/payloads/*/requested_by",
					"/payloads/*/allow_private_endpoint", "/payloads/*/private_egress_cidrs",
					"/payloads/*/submission_profile", "/payloads/*/operator_correlation_ref",
				},
				Nullable: []string{"/payloads/*/leaf_der"},
			}), true
	case "discovery.found":
		return shape(`{"source":"","ref":"","kind":"","provenance":""}`), true
	case "discovery.network_target_blocked", "discovery.ssh_target_blocked":
		return shape(`{"run_id":"","source_id":"","target":"","reason":""}`), true
	case "dynsecret.lease.revoked":
		return shape(`{"lease":"","provider":"","role":"","backend_ref":"","state":""}`), true
	case "ephemeral.issued":
		return shape(`{"subject":"","method":"","ttl_seconds":1,"not_after":"","recovered":true}`), true
	case "history.tenant_data_rewrite.continuity":
		return shape(`{"jws":""}`), true
	case "issuance.host_renewal_dispatched":
		return shape(`{"identity_id":"","target_id":"","target_name":"","connector":"","dns_names":[""],"custody":"","detail":""}`), true
	case "issuance.profile_evaluated":
		return shape(`{"profile":"","version":1,"decision":"","reason":"","protocol":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/reason", "/protocol"}}), true
	case "issuance.server_side_keygen":
		return shape(`{"identity_id":"","name":"","detail":"","successor":""}`), true
	case "itsm.ticket.requested":
		return shape(`{"id":"","instance_url":"","table":"","token_ref":"","short_description":"","description":"","category":"","urgency":"","impact":"","correlation_id":"","allow_private_endpoint":true,"private_egress_cidrs":[""],"requested_by":""}`,
			catalogPrivacyShapeOptions{Optional: []string{
				"/description", "/category", "/urgency", "/impact", "/correlation_id",
				"/allow_private_endpoint", "/private_egress_cidrs", "/requested_by",
			}}), true
	case "lifecycle.renewal.deferred":
		return shape(`{"reason":"","deferred_at":"","window_open":""}`), true
	case "mcp.tool.call":
		return shape(`{"caller":"","tool":"","scope":"","citations":1,"outcome":""}`), true
	case "mcp.tool.denied":
		return shape(`{"caller":"","tool":"","reason":""}`), true
	case "mcp.tool.ratelimited":
		return shape(`{"caller":"","tool":""}`), true
	case "mcp.tool.rest":
		return shape(`{"caller":"","tool":"","method":"","path":"","status":1}`), true
	case "mcp.tool.write":
		return shape(`{"caller":"","tool":"","authority_id":"","serial":"","reason":""}`), true
	case "mdm.intune_scep_challenge.replay_rejected":
		return shape(`{"decision":"","reason":"","transaction_id":"","nonce":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/reason", "/transaction_id", "/nonce"}}), true
	case "policy.abac.decision":
		return shape(`{"permission":"","action":"","actor":"","subject":"","deny":true,"reason":"","error":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/action", "/actor", "/subject", "/reason", "/error"}}), true
	case "policy.decision":
		return shape(`{"action":"","profile":"","actor":"","allow":true,"reason":"","error":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/profile", "/actor", "/reason", "/error"}}), true
	case "policy.version.authored":
		return shape(`{"id":"","kind":"","module":"","module_sha256":"","package":"","query":"","description":"","change_ref":"","evidence_refs":[""],"author":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/description", "/change_ref", "/evidence_refs", "/author"}}), true
	case "policy.version.activated":
		return shape(`{"id":"","kind":"","reason":"","evidence_refs":[""],"activated_by":"","previous_id":"","previous_module":"","previous_module_sha256":"","previous_package":"","previous_query":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/evidence_refs", "/activated_by", "/previous_id", "/previous_module", "/previous_module_sha256", "/previous_package", "/previous_query"}}), true
	case "policy.version.rolled_back":
		return shape(`{"id":"","kind":"","reason":"","evidence_refs":[""],"rolled_back_by":"","rollback_to_id":"","rollback_to_module":"","rollback_to_module_sha256":"","rollback_to_package":"","rollback_to_query":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/evidence_refs", "/rolled_back_by"}}), true
	case "policy.dry_run.evaluated":
		return shape(`{"kind":"","valid":true,"module_sha256":"","allow":true,"deny":true,"reason":"","error":"","input_summary":{"action":"","permission":"","profile":"","subject":"","actor":"","tenant_id":""},"idempotency_key":""}`,
			catalogPrivacyShapeOptions{Optional: []string{
				"/reason", "/error", "/input_summary/action", "/input_summary/permission",
				"/input_summary/profile", "/input_summary/subject", "/input_summary/actor",
			}}), true
	case "pkisecret.issued", "secret.imported", "secret.rotation.completed", "secret.rotation.queued",
		"secret.rotation_schedule.completed", "secret.rotation_schedule.queued", "secret.sync.requested":
		return shape(`{"name":"","version":1}`), true
	case "profile.edit_approval.approved":
		return shape(`{"id":"","approver":"","requester":"","resource":""}`), true
	case "profile.edit_approval.refused":
		return shape(`{"id":"","approver":"","reason":""}`), true
	case "profile.edit_approval.requested":
		return shape(`{"request":{"id":"","tenant_id":"","kind":"","resource":"","requester":"","required_approvals":1,"approvals":[{"approver":"","decision":"","at":""}],"state":"","credential_id":"","payload":{},"created_at":"","expires_at":""},"name":"","spec":{}}`,
			catalogPrivacyShapeOptions{
				Optional: []string{"/request/credential_id", "/request/payload"},
				Open:     []string{"/request/payload", "/spec"}, Nullable: []string{"/request/payload", "/spec"},
			}), true
	case "protocol.cmp.enroll", "protocol.scep.enroll":
		return shape(`{"op":"","decision":"","reason":"","transaction_id":"","profile":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/reason", "/transaction_id", "/profile"}}), true
	case "protocol.est.cacerts", "protocol.est.serverkeygen", "protocol.est.simpleenroll", "protocol.est.simplereenroll":
		return shape(`{"op":"","decision":"","reason":"","profile":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/reason", "/profile"}}), true
	case "protocol.eval_profile.activated":
		return shape(`{"profile":"","protocols":[""]}`), true
	case "protocol.issued":
		return shape(`{"protocol":"","serial":"","decision":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/serial"}}), true
	case "protocol.revoked":
		return shape(`{"protocol":"","serial":"","reason_code":1,"decision":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/serial"}}), true
	case "protocol.scep.issuance.observed", "protocol.scep.request.observed":
		return shape(`{"transaction_id":"","device_serial":"","profile":"","outcome":"","detail":"","certificate_serial":"","certificate_fingerprint":"","certificate_not_after":""}`,
			catalogPrivacyShapeOptions{Optional: []string{
				"/profile", "/detail", "/certificate_serial", "/certificate_fingerprint", "/certificate_not_after",
			}}), true
	case "rca.evidence.gathered":
		return shape(`{"subject":"","items":1}`), true
	case "rotation.completed", "rotation.failed", "rotation.queued", "rotation.retire_pending",
		"rotation.rollback_failed", "rotation.rolled_back", "rotation.staged":
		return shape(`{"key":"","phase":""}`), true
	case "secret.access":
		return shape(`{"principal":"","path":"","action":"","decision":""}`), true
	case "secret.access.denied":
		return shape(`{"principal":"","path":"","reason":""}`), true
	case "secret.purged", "secretscli.fetch", "secretscli.set":
		return shape(`{"path":""}`), true
	case "secret.share.viewed", "secret.shared":
		return shape(`{"share_id":"","token_sha256":""}`), true
	case "secret.sync.delivered":
		return PrivacyPayloadShapeOneOf(
			shape(`{"key":"","target":""}`),
			shape(`{"id":"","attempts":1,"remote_version":""}`,
				catalogPrivacyShapeOptions{Optional: []string{"/remote_version"}}),
		), true
	case "secret.sync.enqueued":
		return shape(`{"key":"","target":""}`), true
	case "secret.version.written":
		return PrivacyPayloadShapeOneOf(
			shape(`{"path":"","version":1,"sealed":"","envelope":{"format":"","version":1,"wrapped_dek":"","dek_nonce":"","nonce":"","ciphertext":""}}`,
				catalogPrivacyShapeOptions{
					Optional: []string{"/envelope/format", "/envelope/version"},
					Nullable: []string{
						"/sealed", "/envelope/wrapped_dek", "/envelope/dek_nonce",
						"/envelope/nonce", "/envelope/ciphertext",
					},
				}),
			shape(`{"path":"","version":1,"envelope":{"format":"","version":1,"wrapped_dek":"","dek_nonce":"","nonce":"","ciphertext":""}}`,
				catalogPrivacyShapeOptions{
					Optional: []string{"/envelope/format", "/envelope/version"},
				}),
			shape(`{"name":"","version":1,"sealed":"","written_at":"","recovered_from_version":1}`,
				catalogPrivacyShapeOptions{
					Optional: []string{"/recovered_from_version"}, Nullable: []string{"/sealed"},
				}),
		), true
	case "secretscan.finding":
		return shape(`{"scanner":"","rule":"","file":"","ref":""}`), true
	case "secretscli.inject":
		return shape(`{"vars":[""]}`), true
	case "spiffe.svid.issued":
		return shape(`{"type":"","spiffe_id":""}`), true
	case "spiffe.workload_api.local_socket_used":
		return shape(`{"type":"","detail":""}`), true
	case "ssh.attested_cert.issued":
		return shape(`{"key_id":"","serial":1,"method":"","subject":"","approver":"","principals":[""],"critical_options":{"key":""}}`,
			catalogPrivacyShapeOptions{DynamicObject: []string{"/critical_options"}, Nullable: []string{"/critical_options"}}), true
	case "ssh.cert.issued":
		return shape(`{"type":"","key_id":"","serial":1,"principals":1,"profile":""}`), true
	case "ssh.cert.revoked":
		return shape(`{"serial":1,"key_id":"","reason":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/serial", "/key_id", "/reason"}}), true
	case "ssh.host.retired":
		return shape(`{"id":"","tenant_id":"","host":"","source_id":"","run_id":"","identity_id":"","reason":"","status":"","recorded_at":""}`,
			catalogPrivacyShapeOptions{Optional: []string{"/source_id", "/run_id", "/identity_id", "/reason"}}), true
	case "ssh.trust_rollout.recorded":
		return shape(`{"id":"","tenant_id":"","source_id":"","target_hosts":[""],"candidate_ca_fingerprint":"","reload_command":"","health_command":"","rollback_plan":"","status":"","confirmed":true,"recorded_at":""}`), true
	case "ssh.trust.added", "ssh.trust.removed", "ssh.trust.rollback_failed", "ssh.trust.rolled_back":
		return shape(`{"detail":""}`), true
	case "transit.decrypt", "transit.encrypt", "transit.hmac", "transit.key.created",
		"transit.key.rotated", "transit.rewrap", "transit.sign", "transit.verify":
		return shape(`{"key":""}`), true
	case "tsa.timestamp.issued":
		return shape(`{"serial":1,"gen_time":""}`), true
	case "vault.compat.mount.disabled", "vault.compat.mount.enabled":
		return shape(`{"path":"","type":"","description":"","options":{"key":""}}`,
			catalogPrivacyShapeOptions{
				Optional: []string{"/description", "/options"}, DynamicObject: []string{"/options"},
				Nullable: []string{"/options"},
			}), true
	case "vault.compat.policy.deleted", "vault.compat.policy.put":
		return shape(`{"name":"","policy":""}`), true
	default:
		return PrivacyPayloadShape{}, false
	}
}
