// SPDX-License-Identifier: MPL-2.0

package events

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/codesigningref"
	"trstctl.com/trstctl/internal/privacyref"
)

const privacyCodeSigningCommandedEvent = "codesign.commanded"

const (
	// ApplicationSecretPrivacyDispositionSchemaVersion is a privacy-only event
	// wire. It never renames application-secret coordinates: those coordinates
	// authenticate ciphertext as AAD, so changing their spelling while retaining
	// sealed bytes would manufacture an undecryptable or misdirected command.
	ApplicationSecretPrivacyDispositionSchemaVersion = 3

	ApplicationSecretPrivacyDispositionNameTombstoned = "name_tombstoned"
	ApplicationSecretPrivacyDispositionSyncErased     = "sync_erased"
)

var privacyApplicationSecretMutationActions = map[string]string{
	"secret.created":   "create",
	"secret.rotated":   "rotate",
	"secret.recovered": "recover",
	"secret.deleted":   "delete",
}

type privacyApplicationSecretMutationCoordinates struct {
	Action string `json:"action"`
	Name   string `json:"name"`
	Sync   *struct {
		SecretName string `json:"secret_name"`
		Target     string `json:"target"`
		RemoteKey  string `json:"remote_key"`
	} `json:"sync,omitempty"`
}

type privacyApplicationSecretDispositionHeader struct {
	Action                     string `json:"action"`
	PrivacyDisposition         string `json:"privacy_disposition"`
	PrivacySubjectRef          string `json:"privacy_subject_ref"`
	PrivacySourceSchemaVersion int    `json:"privacy_source_schema_version"`
	PrivacyAuthorityTombstone  bool   `json:"privacy_authority_tombstone,omitempty"`
	PrivacySyncAuthorityErased bool   `json:"privacy_sync_authority_erased,omitempty"`
}

type privacyCodeSigningIssuanceBinding struct {
	ProfileName         string `json:"profile_name,omitempty"`
	ProfileID           string `json:"profile_id,omitempty"`
	ProfileVersion      int    `json:"profile_version,omitempty"`
	ProfileSpecDigest   string `json:"profile_spec_digest,omitempty"`
	RequestedTTLSeconds int64  `json:"requested_ttl_seconds"`
	EffectiveTTLSeconds int64  `json:"effective_ttl_seconds"`
}

type privacyCodeSigningApprovalUse struct {
	RequestID         string                             `json:"request_id"`
	IntentDigest      string                             `json:"intent_digest"`
	Requester         string                             `json:"requester"`
	ResourceKind      string                             `json:"resource_kind"`
	ResourceID        string                             `json:"resource_id"`
	Action            string                             `json:"action"`
	FromState         string                             `json:"from_state,omitempty"`
	ToState           string                             `json:"to_state,omitempty"`
	TargetVersion     uint64                             `json:"target_version"`
	RequiredApprovals int                                `json:"required_approvals"`
	Reason            string                             `json:"reason,omitempty"`
	EvidenceRefs      []string                           `json:"evidence_refs,omitempty"`
	Issuance          *privacyCodeSigningIssuanceBinding `json:"issuance,omitempty"`
}

type privacyCodeSigningCommandV1 struct {
	OperationID    string `json:"operation_id"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	Mode           string `json:"mode"`
	RequestHash    string `json:"request_hash"`
	SealedCommand  []byte `json:"sealed_command"`
}

type privacyCodeSigningCommandV2 struct {
	privacyCodeSigningCommandV1
	Approval *privacyCodeSigningApprovalUse `json:"approval,omitempty"`
}

type privacyCodeSigningCommandV3 struct {
	OperationID       string                         `json:"operation_id"`
	IdempotencyKeyRef string                         `json:"idempotency_key_ref,omitempty"`
	RequestBinding    string                         `json:"request_binding,omitempty"`
	Mode              string                         `json:"mode"`
	RequestHash       string                         `json:"request_hash"`
	SealedCommand     []byte                         `json:"sealed_command"`
	Approval          *privacyCodeSigningApprovalUse `json:"approval,omitempty"`
}

func init() {
	command := []PrivacyFieldRule{
		{Path: "/operation_id", Mode: PrivacyFieldOpaqueExact},
		{Path: "/idempotency_key", Mode: PrivacyFieldOpaqueExact},
		{Path: "/mode", Mode: PrivacyFieldOpaqueExact},
		{Path: "/request_hash", Mode: PrivacyFieldOpaqueExact},
		{Path: "/sealed_command", Mode: PrivacyFieldOpaqueExact},
	}
	approval := []PrivacyFieldRule{
		{Path: "/approval/request_id", Mode: PrivacyFieldOpaqueExact},
		{Path: "/approval/intent_digest", Mode: PrivacyFieldOpaqueExact},
		{Path: "/approval/requester", Mode: PrivacyFieldIdentityExact},
		{Path: "/approval/resource_kind", Mode: PrivacyFieldOpaqueExact},
		{Path: "/approval/resource_id", Mode: PrivacyFieldOpaqueExact},
		{Path: "/approval/action", Mode: PrivacyFieldOpaqueExact},
		{Path: "/approval/from_state", Mode: PrivacyFieldOpaqueExact},
		{Path: "/approval/to_state", Mode: PrivacyFieldOpaqueExact},
		{Path: "/approval/target_version", Mode: PrivacyFieldOpaqueExact},
		{Path: "/approval/required_approvals", Mode: PrivacyFieldOpaqueExact},
		{Path: "/approval/reason", Mode: PrivacyFieldFreeTextClear},
		{Path: "/approval/evidence_refs", Mode: PrivacyFieldFreeTextClear},
		{Path: "/approval/issuance", Mode: PrivacyFieldOpaqueExact},
	}
	policies := map[int]PrivacyEventPolicy{
		1: {
			Rules:        append([]PrivacyFieldRule(nil), command...),
			PayloadShape: PrivacyPayloadShapeOf[privacyCodeSigningCommandV1](),
		},
		2: {
			Rules:        append(append([]PrivacyFieldRule(nil), command...), approval...),
			PayloadShape: PrivacyPayloadShapeOf[privacyCodeSigningCommandV2](),
		},
		3: {Rules: append([]PrivacyFieldRule{
			{Path: "/operation_id", Mode: PrivacyFieldOpaqueExact},
			{Path: "/idempotency_key_ref", Mode: PrivacyFieldOpaqueExact},
			{Path: "/request_binding", Mode: PrivacyFieldOpaqueExact},
			{Path: "/mode", Mode: PrivacyFieldOpaqueExact},
			{Path: "/request_hash", Mode: PrivacyFieldOpaqueExact},
			{Path: "/sealed_command", Mode: PrivacyFieldOpaqueExact},
		}, approval...), PayloadShape: PrivacyPayloadShapeOf[privacyCodeSigningCommandV3]()},
	}
	for _, version := range []int{1, 2, 3} {
		policy := policies[version]
		if err := RegisterPrivacyEventPolicy(privacyCodeSigningCommandedEvent, version, policy); err != nil {
			panic(err)
		}
	}
}

// PseudonymizeSubject replaces exact occurrences of an erased subject in stored
// event payloads and actor subjects with the tenant-bound erasure placeholder. It
// uses the same generation switch, frozen cutover, continuity receipt, and secure
// source scrub as RewriteTenantData; it never deletes and republishes the active
// stream in place.
//
// This is intentionally narrow: it is the storage-level companion to the
// privacy.subject.erased event. Cold archives and backups created before this
// rewrite need their own operator retention/deletion process, documented under
// privacy retention. The proof options are mandatory. The variadic form keeps
// existing callers source-compatible while making unwired callers fail closed
// before any history mutation.
func (l *Log) PseudonymizeSubject(
	ctx context.Context,
	tenantID, subject string,
	options ...TenantDataRewriteOption,
) error {
	return l.PseudonymizeSubjectWithCompletion(ctx, tenantID, subject, nil, options...)
}

// PseudonymizeSubjectWithCompletion performs the generation rewrite and then
// invokes completion before releasing the same deployment-wide rewrite-operation
// lock. The completion callback runs after the cutover lock has been released, so
// it may use normal history reads/append/projection paths without inverting the
// operation -> cutover -> backup lock order. This narrow seam lets the served
// erasure command re-check durable state and append its deterministic completion
// event without another replica starting the same long-window rewrite in between.
func (l *Log) PseudonymizeSubjectWithCompletion(
	ctx context.Context,
	tenantID, subject string,
	completion func(context.Context) error,
	options ...TenantDataRewriteOption,
) error {
	return l.PseudonymizeSubjectWithPreparationAndCompletion(
		ctx, tenantID, subject, nil, completion, options...)
}

// PseudonymizeSubjectWithPreparationAndCompletion owns one exclusive history
// operation across three ordered phases: signed replacement staging, durable SQL
// preparation, and deterministic event completion. Preparation receives the
// exact signed generation report and runs only after the target can be recovered
// without the erased plaintext. The target remains non-authoritative until the
// callback commits; any later error leaves both generations for autonomous
// recovery instead of deleting the target named by the PostgreSQL marker.
func (l *Log) PseudonymizeSubjectWithPreparationAndCompletion(
	ctx context.Context,
	tenantID, subject string,
	preparation func(context.Context, TenantDataRewriteReport) error,
	completion func(context.Context) error,
	options ...TenantDataRewriteOption,
) error {
	if tenantID == "" {
		return errors.New("events: subject pseudonymization requires tenant_id (AN-1)")
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return errors.New("events: subject pseudonymization requires subject")
	}

	if err := ValidateTenantDataRewriteOptions(options...); err != nil {
		return fmt.Errorf("events: subject pseudonymization proof wall: %w", err)
	}
	if err := l.HistoryRewriteReady(); err != nil {
		return fmt.Errorf("events: subject pseudonymization readiness: %w", err)
	}
	if preparation != nil {
		if _, ok := l.history.(HistoryRewritePreparationResolver); !ok {
			return errors.New("events: subject pseudonymization preparation requires a durable history rewrite preparation resolver")
		}
	}
	opts := parseTenantDataRewriteOptions(options)
	opts.externalPreparation = preparation
	opts.externalKind = rewriteExternalPreparationPrivacySubjectErasure

	transform := func(before storedEvent) (storedEvent, bool, error) {
		if before.TenantID != tenantID {
			return before, false, nil
		}
		after := cloneStoredEvent(before)
		changed, err := pseudonymizeStoredSubject(&after, subject)
		if err != nil {
			return before, false, err
		}
		if !changed {
			return before, false, nil
		}
		return after, true, nil
	}
	validate := func(before, after storedEvent) error {
		if before.TenantID != tenantID {
			return errors.New("subject pseudonymization changed a non-target tenant")
		}
		expected := cloneStoredEvent(before)
		changed, err := pseudonymizeStoredSubject(&expected, subject)
		if err != nil {
			return err
		}
		if !changed {
			return errors.New("subject pseudonymization changed an event without the erased subject")
		}
		expectedCanonical, err := json.Marshal(expected)
		if err != nil {
			return fmt.Errorf("encode expected pseudonymized event: %w", err)
		}
		afterCanonical, err := json.Marshal(after)
		if err != nil {
			return fmt.Errorf("encode actual pseudonymized event: %w", err)
		}
		if !bytes.Equal(expectedCanonical, afterCanonical) {
			return errors.New("subject pseudonymization changed fields outside the exact actor/data replacement")
		}
		return nil
	}

	return l.withRewriteOperation(ctx, func(ctx context.Context) error {
		// A closed-policy refusal happens before rewrite metadata or a target stream
		// exists. This prevents an unsupported schema from leaving even a
		// non-authoritative generation that recovery might later misclassify.
		if err := l.preflightStoredSubjectRewrite(ctx, tenantID, transform); err != nil {
			return err
		}
		_, err := l.rewriteStoredGeneration(ctx, tenantID, transform, validate, opts)
		if err != nil {
			return err
		}
		if completion != nil {
			if err := completion(ctx); err != nil {
				return fmt.Errorf("events: subject pseudonymization completion: %w", err)
			}
		}
		return nil
	})
}

func (l *Log) preflightStoredSubjectRewrite(
	ctx context.Context,
	tenantID string,
	transform storedEventTransform,
) error {
	_, source, err := l.resolveActiveStream(ctx)
	if err != nil {
		return fmt.Errorf("events: resolve subject rewrite preflight source: %w", err)
	}
	info, err := l.infoForStream(ctx, source)
	if err != nil {
		return fmt.Errorf("events: subject rewrite preflight source info: %w", err)
	}
	first := info.State.FirstSeq
	if first == 0 {
		first = 1
	}
	for seq := first; seq <= info.State.LastSeq; seq++ {
		raw, err := source.GetMsg(ctx, seq)
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("events: read subject rewrite preflight seq %d: %w", seq, err)
		}
		var event storedEvent
		if err := json.Unmarshal(raw.Data, &event); err != nil {
			return fmt.Errorf("events: decode subject rewrite preflight seq %d: %w", seq, err)
		}
		if event.TenantID != tenantID {
			continue
		}
		if _, _, err := transform(event); err != nil {
			return fmt.Errorf("events: subject rewrite preflight event %q: %w", event.ID, err)
		}
	}
	return nil
}

func cloneStoredEvent(event storedEvent) storedEvent {
	clone := event
	clone.Data = append([]byte(nil), event.Data...)
	if event.Actor != nil {
		actor := *event.Actor
		if event.Actor.Roles != nil {
			actor.Roles = make([]string, len(event.Actor.Roles))
			copy(actor.Roles, event.Actor.Roles)
		}
		clone.Actor = &actor
	}
	return clone
}

func pseudonymizeStoredSubject(s *storedEvent, subject string) (bool, error) {
	var changed bool
	if s.Actor != nil {
		s.Actor, changed = PseudonymizeActorForSubject(s.Actor, s.TenantID, subject)
	}
	if len(s.Data) > 0 {
		next, nextSchemaVersion, dataChanged, err := PseudonymizeEventDataForSubjectVersioned(
			s.Data, s.TenantID, subject, s.Type, s.SchemaVersion,
		)
		if err != nil {
			return false, err
		}
		if dataChanged {
			s.Data = next
			s.SchemaVersion = nextSchemaVersion
			changed = true
		}
	}
	return changed, nil
}

// PseudonymizeActorForSubject returns an actor with every exact occurrence of
// subject replaced by the tenant-bound privacy placeholder. Custom role names
// are caller-controlled strings too, so they receive the same narrow transform
// as Actor.Subject. The role slice keeps its exact length and order: privacy
// erasure changes spelling, never the authorization shape recorded by history.
func PseudonymizeActorForSubject(actor *Actor, tenantID, subject string) (*Actor, bool) {
	if actor == nil || subject == "" {
		return actor, false
	}
	placeholder := privacyref.Placeholder(privacyref.SubjectRef(tenantID, subject))
	rewritten := *actor
	if actor.Roles != nil {
		rewritten.Roles = make([]string, len(actor.Roles))
		copy(rewritten.Roles, actor.Roles)
	}
	changed := false
	if actor.Subject == subject && !isExactExistingPrivacyPlaceholder(actor.Subject) {
		rewritten.Subject = placeholder
		changed = true
	}
	for i, role := range actor.Roles {
		if next, roleChanged := replaceSubjectTokens(role, subject, placeholder); roleChanged {
			rewritten.Roles[i] = next
			changed = true
		}
	}
	if !changed {
		return actor, false
	}
	return &rewritten, true
}

func pseudonymizeDataBytes(data []byte, subject, placeholder string) ([]byte, bool) {
	if json.Valid(data) {
		next, changed, err := pseudonymizeJSONStringValues(data, subject, placeholder)
		if err == nil {
			return next, changed
		}
	}
	next := bytes.ReplaceAll(data, []byte(subject), []byte(placeholder))
	return next, !bytes.Equal(next, data)
}

// PseudonymizeDataForSubject rewrites non-event durable JSON copies that do not
// have a registered event/schema policy. Canonical event payloads must use
// PseudonymizeEventDataForSubject so closed-shape and command-identity rules are
// applied before any rewritten bytes are accepted during recovery.
func PseudonymizeDataForSubject(data []byte, tenantID, subject string) ([]byte, bool) {
	ref := privacyref.SubjectRef(tenantID, subject)
	return pseudonymizeDataBytes(data, subject, privacyref.Placeholder(ref))
}

// PseudonymizeEventDataForSubject applies the history transform with the event
// type and schema needed by fields whose representation is itself an immutable
// command identity. Legacy code-signing Idempotency-Key values are the important
// case: replacing only the subject substring would leave the old operation ID
// pointing at a different key. V1/v2 therefore store the explicit one-way
// operation mapping while v3 keeps its already-one-way reference byte-exact.
func PseudonymizeEventDataForSubject(
	data []byte,
	tenantID, subject, eventType string,
	schemaVersion int,
) ([]byte, bool, error) {
	next, nextSchemaVersion, changed, err := PseudonymizeEventDataForSubjectVersioned(
		data, tenantID, subject, eventType, schemaVersion,
	)
	if err != nil {
		return nil, false, err
	}
	if nextSchemaVersion != schemaVersion {
		return nil, false, fmt.Errorf(
			"events: %s v%d privacy rewrite requires envelope schema v%d",
			eventType, schemaVersion, nextSchemaVersion,
		)
	}
	return next, changed, nil
}

// PseudonymizeEventDataForSubjectVersioned is the envelope-aware typed history
// transform. Most schemas keep their version. Application-secret commands are
// the narrow exception: a subject in the secret name or connector coordinates
// cannot be renamed because those exact bytes are authenticated as ciphertext
// AAD. The transform returns a closed v3 authority disposition instead, and the
// caller MUST store nextSchemaVersion beside next.
func PseudonymizeEventDataForSubjectVersioned(
	data []byte,
	tenantID, subject, eventType string,
	schemaVersion int,
) (next []byte, nextSchemaVersion int, changed bool, err error) {
	if _, ok := privacyApplicationSecretMutationActions[eventType]; ok {
		return pseudonymizeApplicationSecretMutationData(
			data, tenantID, subject, eventType, schemaVersion,
		)
	}
	if eventType == privacyCodeSigningCommandedEvent {
		next, changed, err = pseudonymizeCodeSigningCommandData(
			data, tenantID, subject, schemaVersion,
		)
		return next, schemaVersion, changed, err
	}
	next, changed, err = applyRegisteredPrivacyEventPolicy(
		data, tenantID, subject, eventType, schemaVersion,
	)
	return next, schemaVersion, changed, err
}

func pseudonymizeApplicationSecretMutationData(
	data []byte,
	tenantID, subject, eventType string,
	schemaVersion int,
) ([]byte, int, bool, error) {
	version := schemaVersion
	if version == 0 {
		version = DefaultSchemaVersion
	}
	if version != 2 && version != ApplicationSecretPrivacyDispositionSchemaVersion {
		next, changed, err := applyRegisteredPrivacyEventPolicy(
			data, tenantID, subject, eventType, schemaVersion,
		)
		return next, schemaVersion, changed, err
	}
	if !json.Valid(data) {
		return nil, schemaVersion, false,
			errors.New("events: application-secret command payload is not JSON during privacy rewrite")
	}
	if err := validatePrivacyJSONUniqueKeys(data); err != nil {
		return nil, schemaVersion, false, err
	}
	if err := validateRegisteredPrivacyEventPayload(data, eventType, version); err != nil {
		return nil, schemaVersion, false, fmt.Errorf(
			"events: application-secret %s v%d privacy pre-rewrite payload: %w",
			eventType, version, err,
		)
	}

	expectedAction := privacyApplicationSecretMutationActions[eventType]
	var coordinates privacyApplicationSecretMutationCoordinates
	if err := json.Unmarshal(data, &coordinates); err != nil {
		return nil, schemaVersion, false,
			fmt.Errorf("events: decode application-secret privacy coordinates: %w", err)
	}
	if coordinates.Action != expectedAction {
		return nil, schemaVersion, false,
			fmt.Errorf("events: application-secret %s action differs during privacy rewrite", eventType)
	}

	if version == ApplicationSecretPrivacyDispositionSchemaVersion {
		var header privacyApplicationSecretDispositionHeader
		if err := json.Unmarshal(data, &header); err != nil {
			return nil, schemaVersion, false, err
		}
		switch header.PrivacyDisposition {
		case ApplicationSecretPrivacyDispositionNameTombstoned:
			next, changed, err := applyRegisteredPrivacyEventPolicy(
				data, tenantID, subject, eventType, version,
			)
			return next, schemaVersion, changed, err
		case ApplicationSecretPrivacyDispositionSyncErased:
			if !header.PrivacySyncAuthorityErased || coordinates.Name == "" {
				return nil, schemaVersion, false,
					errors.New("events: application-secret sync privacy disposition is incomplete")
			}
		default:
			return nil, schemaVersion, false,
				fmt.Errorf("events: application-secret privacy disposition %q is unsupported", header.PrivacyDisposition)
		}
	}

	if coordinates.Name == "" {
		return nil, schemaVersion, false,
			errors.New("events: application-secret privacy coordinate name is empty")
	}
	_, nameChanged := replaceSubjectTokens(coordinates.Name, subject, "")
	if nameChanged {
		return applicationSecretPrivacyNameTombstone(
			data, tenantID, subject, eventType, version, coordinates.Action,
		)
	}

	syncChanged := false
	if coordinates.Sync != nil {
		if coordinates.Action != "rotate" || coordinates.Sync.SecretName != coordinates.Name ||
			coordinates.Sync.Target == "" || coordinates.Sync.RemoteKey == "" {
			return nil, schemaVersion, false,
				errors.New("events: application-secret sync privacy coordinates are inconsistent")
		}
		_, targetChanged := replaceSubjectTokens(coordinates.Sync.Target, subject, "")
		_, remoteKeyChanged := replaceSubjectTokens(coordinates.Sync.RemoteKey, subject, "")
		syncChanged = targetChanged || remoteKeyChanged
	}
	if !syncChanged {
		next, changed, err := applyRegisteredPrivacyEventPolicy(
			data, tenantID, subject, eventType, version,
		)
		return next, schemaVersion, changed, err
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, schemaVersion, false, err
	}
	delete(document, "sync")
	disposition, err := json.Marshal(ApplicationSecretPrivacyDispositionSyncErased)
	if err != nil {
		return nil, schemaVersion, false, err
	}
	subjectRef, err := json.Marshal(privacyref.SubjectRef(tenantID, subject))
	if err != nil {
		return nil, schemaVersion, false, err
	}
	sourceVersion, err := json.Marshal(version)
	if err != nil {
		return nil, schemaVersion, false, err
	}
	document["privacy_disposition"] = disposition
	document["privacy_subject_ref"] = subjectRef
	document["privacy_source_schema_version"] = sourceVersion
	document["privacy_sync_authority_erased"] = json.RawMessage("true")
	rewritten, err := json.Marshal(document)
	if err != nil {
		return nil, schemaVersion, false, err
	}
	return finalizeApplicationSecretPrivacyDisposition(
		rewritten, tenantID, subject, eventType,
	)
}

func applicationSecretPrivacyNameTombstone(
	_ []byte,
	tenantID, subject, eventType string,
	sourceSchemaVersion int,
	action string,
) ([]byte, int, bool, error) {
	rewritten, err := json.Marshal(privacyApplicationSecretDispositionHeader{
		Action:                     action,
		PrivacyDisposition:         ApplicationSecretPrivacyDispositionNameTombstoned,
		PrivacySubjectRef:          privacyref.SubjectRef(tenantID, subject),
		PrivacySourceSchemaVersion: sourceSchemaVersion,
		PrivacyAuthorityTombstone:  true,
	})
	if err != nil {
		return nil, sourceSchemaVersion, false, err
	}
	return finalizeApplicationSecretPrivacyDisposition(
		rewritten, tenantID, subject, eventType,
	)
}

func finalizeApplicationSecretPrivacyDisposition(
	rewritten []byte,
	tenantID, subject, eventType string,
) ([]byte, int, bool, error) {
	const targetVersion = ApplicationSecretPrivacyDispositionSchemaVersion
	if err := validateRegisteredPrivacyEventPayload(rewritten, eventType, targetVersion); err != nil {
		return nil, targetVersion, false, fmt.Errorf(
			"events: application-secret %s v%d privacy disposition payload: %w",
			eventType, targetVersion, err,
		)
	}
	next, _, err := applyRegisteredPrivacyEventPolicy(
		rewritten, tenantID, subject, eventType, targetVersion,
	)
	if err != nil {
		return nil, targetVersion, false, err
	}
	if bytes.Contains(next, []byte(subject)) {
		return nil, targetVersion, false,
			errors.New("events: application-secret privacy disposition retained the raw subject")
	}
	return next, targetVersion, true, nil
}

func pseudonymizeCodeSigningCommandData(
	data []byte,
	tenantID, subject string,
	schemaVersion int,
) ([]byte, bool, error) {
	version := schemaVersion
	if version == 0 {
		version = DefaultSchemaVersion
	}
	if !json.Valid(data) {
		return nil, false, errors.New("events: code-signing command payload is not JSON during privacy rewrite")
	}
	if err := validatePrivacyJSONUniqueKeys(data); err != nil {
		return nil, false, err
	}
	// The legacy operation-bound key rewrite runs before the generic field
	// walker. Close the original payload here so a key-only subject occurrence
	// cannot bypass applyRegisteredPrivacyEventPolicy's subject-bearing shape
	// preflight after the key has been replaced by its one-way reference.
	if err := validateRegisteredPrivacyEventPayload(
		data, privacyCodeSigningCommandedEvent, version,
	); err != nil {
		return nil, false, fmt.Errorf("events: code-signing privacy pre-rewrite payload: %w", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, false, fmt.Errorf("events: decode code-signing command during privacy rewrite: %w", err)
	}
	var operationID string
	if err := json.Unmarshal(document["operation_id"], &operationID); err != nil || operationID == "" {
		return nil, false, errors.New("events: code-signing command operation identity is invalid during privacy rewrite")
	}
	changed := false
	if version <= 2 {
		var key string
		if err := json.Unmarshal(document["idempotency_key"], &key); err != nil || key == "" {
			return nil, false, errors.New("events: legacy code-signing key is invalid during privacy rewrite")
		}
		switch {
		case codesigningref.IsLegacyStorageKeyForOperation(key, operationID):
			// A later subject erasure may touch another field in an already-scrubbed
			// command. Keep the operation-bound mapping byte-exact.
		case codesigningref.IsLegacyStorageKey(key):
			return nil, false, errors.New("events: legacy code-signing privacy mapping belongs to another operation")
		case func() bool {
			_, containsIdentity := replaceSubjectTokens(key, subject, "")
			return containsIdentity
		}():
			replacement, err := json.Marshal(codesigningref.LegacyStorageKeyForRaw(operationID, key))
			if err != nil {
				return nil, false, err
			}
			document["idempotency_key"] = replacement
			changed = true
		}
	} else {
		var rawKey string
		if raw, ok := document["idempotency_key"]; ok {
			if err := json.Unmarshal(raw, &rawKey); err != nil {
				return nil, false, errors.New("events: privacy-safe code-signing raw key field is invalid")
			}
		}
		if rawKey != "" {
			return nil, false, errors.New("events: privacy-safe code-signing command contains a raw idempotency key")
		}
	}

	policyInput := data
	if changed {
		var err error
		policyInput, err = json.Marshal(document)
		if err != nil {
			return nil, false, err
		}
	}
	rewritten, policyChanged, err := applyRegisteredPrivacyEventPolicy(
		policyInput, tenantID, subject, privacyCodeSigningCommandedEvent, version,
	)
	if err != nil {
		return nil, false, err
	}
	return rewritten, changed || policyChanged, nil
}

// pseudonymizeJSONStringValues rewrites semantic JSON strings, including object
// keys because dynamic keys can carry subject PII. It copies every byte outside
// the matched subject spans verbatim, so object ordering, whitespace, and even
// unrelated escapes in a changed token do not move. json.Valid is checked by the
// caller before this scanner runs.
func pseudonymizeJSONStringValues(data []byte, subject, placeholder string) ([]byte, bool, error) {
	var (
		out     []byte
		last    int
		changed bool
	)
	for cursor := 0; cursor < len(data); {
		if data[cursor] != '"' {
			cursor++
			continue
		}

		start := cursor
		cursor++
		for cursor < len(data) {
			switch data[cursor] {
			case '\\':
				cursor += 2
			case '"':
				cursor++
				goto stringComplete
			default:
				cursor++
			}
		}
		return nil, false, errors.New("unterminated JSON string")

	stringComplete:
		end := cursor
		rewritten, tokenChanged, err := pseudonymizeJSONStringToken(data[start:end], subject, placeholder)
		if err != nil {
			return nil, false, err
		}
		if !tokenChanged {
			continue
		}
		out = append(out, data[last:start]...)
		out = append(out, rewritten...)
		last = end
		changed = true
	}
	if !changed {
		return data, false, nil
	}
	out = append(out, data[last:]...)
	return out, true, nil
}

func pseudonymizeJSONStringToken(token []byte, subject, placeholder string) ([]byte, bool, error) {
	if subject == "" {
		return token, false, nil
	}
	decoded, rawBoundary, err := decodeJSONStringTokenSpans(token)
	if err != nil {
		return nil, false, err
	}

	type rawMatch struct {
		start int
		end   int
	}
	var matches []rawMatch
	for search := 0; search < len(decoded); {
		relative := strings.Index(decoded[search:], subject)
		if relative < 0 {
			break
		}
		semanticStart := search + relative
		semanticEnd := semanticStart + len(subject)
		rawStart, startOK := rawBoundary[semanticStart]
		rawEnd, endOK := rawBoundary[semanticEnd]
		if !startOK || !endOK {
			return nil, false, errors.New("subject match splits a JSON Unicode character")
		}
		matches = append(matches, rawMatch{start: rawStart, end: rawEnd})
		search = semanticEnd
	}
	if len(matches) == 0 {
		// encoding/json represents []byte fields as base64 JSON strings. Lifecycle
		// v3 used that shape for a nested replayable outbox command, so treating the
		// token as opaque would leave erased subjects in hot history and let boot
		// reconciliation restore them. Recursively rewrite only a canonical base64
		// value that decodes to valid JSON; unrelated opaque strings remain byte-for-
		// byte unchanged.
		if nested, decodeErr := base64.StdEncoding.DecodeString(decoded); decodeErr == nil &&
			base64.StdEncoding.EncodeToString(nested) == decoded && json.Valid(nested) {
			if rewritten, changed := pseudonymizeDataBytes(nested, subject, placeholder); changed {
				encoded, marshalErr := json.Marshal(base64.StdEncoding.EncodeToString(rewritten))
				if marshalErr != nil {
					return nil, false, fmt.Errorf("encode pseudonymized nested JSON payload: %w", marshalErr)
				}
				return encoded, true, nil
			}
		}
		return token, false, nil
	}

	encodedPlaceholder, err := json.Marshal(placeholder)
	if err != nil {
		return nil, false, fmt.Errorf("encode subject placeholder: %w", err)
	}
	encodedPlaceholder = encodedPlaceholder[1 : len(encodedPlaceholder)-1]

	out := make([]byte, 0, len(token))
	rawCursor := 0
	for _, match := range matches {
		out = append(out, token[rawCursor:match.start]...)
		out = append(out, encodedPlaceholder...)
		rawCursor = match.end
	}
	out = append(out, token[rawCursor:]...)
	return out, true, nil
}

// decodeJSONStringTokenSpans decodes a valid quoted JSON string and records
// which raw offsets surround each complete decoded Unicode character. The map
// lets the caller replace a semantic substring without normalizing unrelated
// escapes elsewhere in the same token.
func decodeJSONStringTokenSpans(token []byte) (string, map[int]int, error) {
	if len(token) < 2 || token[0] != '"' || token[len(token)-1] != '"' {
		return "", nil, errors.New("JSON string token is not quoted")
	}

	decoded := make([]byte, 0, len(token)-2)
	rawBoundary := map[int]int{0: 1}
	for rawCursor := 1; rawCursor < len(token)-1; {
		rawStart := rawCursor
		var semantic rune
		if token[rawCursor] != '\\' {
			var rawSize int
			semantic, rawSize = utf8.DecodeRune(token[rawCursor : len(token)-1])
			rawCursor += rawSize
		} else {
			if rawCursor+1 >= len(token)-1 {
				return "", nil, errors.New("truncated JSON escape")
			}
			switch token[rawCursor+1] {
			case '"', '\\', '/':
				semantic = rune(token[rawCursor+1])
				rawCursor += 2
			case 'b':
				semantic = '\b'
				rawCursor += 2
			case 'f':
				semantic = '\f'
				rawCursor += 2
			case 'n':
				semantic = '\n'
				rawCursor += 2
			case 'r':
				semantic = '\r'
				rawCursor += 2
			case 't':
				semantic = '\t'
				rawCursor += 2
			case 'u':
				first, ok := decodeJSONHexQuad(token[rawCursor+2:])
				if !ok {
					return "", nil, errors.New("invalid JSON Unicode escape")
				}
				semantic = rune(first)
				rawCursor += 6
				if 0xD800 <= first && first <= 0xDBFF &&
					rawCursor+6 <= len(token)-1 &&
					token[rawCursor] == '\\' && token[rawCursor+1] == 'u' {
					second, secondOK := decodeJSONHexQuad(token[rawCursor+2:])
					if secondOK && 0xDC00 <= second && second <= 0xDFFF {
						semantic = utf16.DecodeRune(rune(first), rune(second))
						rawCursor += 6
					}
				}
				if utf16.IsSurrogate(semantic) {
					semantic = utf8.RuneError
				}
			default:
				return "", nil, errors.New("invalid JSON escape")
			}
		}

		semanticStart := len(decoded)
		decoded = utf8.AppendRune(decoded, semantic)
		rawBoundary[semanticStart] = rawStart
		rawBoundary[len(decoded)] = rawCursor
	}
	return string(decoded), rawBoundary, nil
}

func decodeJSONHexQuad(encoded []byte) (uint16, bool) {
	if len(encoded) < 4 {
		return 0, false
	}
	var value uint16
	for _, digit := range encoded[:4] {
		value <<= 4
		switch {
		case '0' <= digit && digit <= '9':
			value |= uint16(digit - '0')
		case 'a' <= digit && digit <= 'f':
			value |= uint16(digit-'a') + 10
		case 'A' <= digit && digit <= 'F':
			value |= uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}
