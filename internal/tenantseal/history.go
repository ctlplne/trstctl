// SPDX-License-Identifier: MPL-2.0

// Package tenantseal coordinates tenant-scoped cryptographic protection domains
// without moving cryptographic primitives outside internal/crypto.
package tenantseal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

const maxNestedHistoryDepth = 12

var (
	// ErrUnexpectedDomain prevents migration from guessing which non-legacy
	// wrapper owns a container.
	ErrUnexpectedDomain = errors.New("tenantseal: ciphertext belongs to an unexpected protection domain")
	// ErrCorruptContainer marks bytes that claim the CSL container family but do
	// not parse or authenticate.
	ErrCorruptContainer = errors.New("tenantseal: corrupt sealed container")
	// ErrLegacyEnvelope keeps pre-CSL JSON envelope history visible as partial;
	// it cannot be silently treated as a current binary container.
	ErrLegacyEnvelope = errors.New("tenantseal: legacy JSON envelope requires explicit migration")
	// ErrCertificateMetadataReceiptBridge preserves the original generation
	// until randomized payload changes can rebind existing completion receipts
	// through an actual-pair, crash-safe transaction bridge.
	ErrCertificateMetadataReceiptBridge = errors.New("tenantseal: changed certificate metadata receipt requires a history-rewrite bridge")
)

// HistoryRewrapper transforms sealed containers embedded anywhere in event JSON,
// including base64-encoded nested outbox payloads. It never opens payload
// ciphertext and never needs row-specific AAD.
type HistoryRewrapper struct {
	deployment seal.KeyWrapper
	tenant     seal.KeyWrapper
	domain     []byte
}

// NewHistoryRewrapper binds a migration pass to exactly one destination domain.
func NewHistoryRewrapper(deployment, tenant seal.KeyWrapper, domain []byte) (*HistoryRewrapper, error) {
	if deployment == nil || tenant == nil {
		return nil, errors.New("tenantseal: deployment and tenant wrappers are required")
	}
	if len(domain) == 0 {
		return nil, errors.New("tenantseal: destination domain is required")
	}
	return &HistoryRewrapper{
		deployment: deployment,
		tenant:     tenant,
		domain:     append([]byte(nil), domain...),
	}, nil
}

// Transform implements events.TenantDataTransform. eventType and schemaVersion
// remain in the signature so callers can record precise failure evidence; the
// rewrite itself recognizes authenticated container formats rather than a
// brittle allowlist of event names.
func (r *HistoryRewrapper) Transform(_ string, _ int, data []byte) ([]byte, bool, error) {
	if bytes.HasPrefix(data, []byte("CSL1")) {
		next, changed, err := r.rewriteContainer(data)
		if err != nil {
			return nil, false, err
		}
		return next, changed, nil
	}
	if !json.Valid(data) {
		return data, false, nil
	}
	value, err := decodeHistoryJSON(data)
	if err != nil {
		return nil, false, err
	}
	changed, err := r.rewriteValue(&value, 0)
	if err != nil {
		return nil, false, err
	}
	if !changed {
		return data, false, nil
	}
	next, err := json.Marshal(value)
	if err != nil {
		return nil, false, fmt.Errorf("tenantseal: encode rewritten event data: %w", err)
	}
	return next, true, nil
}

// ValidatePair proves that one staged event rewrite changed only CSL wrapper
// metadata. The payload nonce+ciphertext must remain byte-identical, every new
// container must authenticate under the exact destination domain, and all JSON
// keys, array positions, scalar values, and non-container base64 bytes must be
// unchanged. No record plaintext or row-specific AAD is opened.
func (r *HistoryRewrapper) ValidatePair(
	eventType string,
	schemaVersion int,
	before, after []byte,
) error {
	if err := r.validateRewrappedPair(before, after); err != nil {
		return err
	}
	dependent, err := projections.CertificateMetadataEvent(events.Event{Type: eventType, SchemaVersion: schemaVersion, Data: before})
	if err != nil {
		return err
	}
	if dependent {
		return ErrCertificateMetadataReceiptBridge
	}
	return nil
}

func (r *HistoryRewrapper) validateRewrappedPair(before, after []byte) error {
	if bytes.Equal(before, after) {
		return errors.New("tenantseal: rewritten history pair is byte-identical")
	}
	if bytes.HasPrefix(before, []byte("CSL1")) {
		return r.validateContainerPair(before, after)
	}
	if !json.Valid(before) || !json.Valid(after) {
		return errors.New("tenantseal: rewritten non-JSON history changed")
	}
	beforeValue, err := decodeHistoryJSON(before)
	if err != nil {
		return err
	}
	afterValue, err := decodeHistoryJSON(after)
	if err != nil {
		return err
	}
	changed, err := r.validateValuePair(beforeValue, afterValue, 0)
	if err != nil {
		return err
	}
	if !changed {
		return errors.New("tenantseal: rewritten history pair contains no tenant-domain rewrap")
	}
	return nil
}

func (r *HistoryRewrapper) validateValuePair(before, after any, depth int) (bool, error) {
	if depth > maxNestedHistoryDepth {
		return false, errors.New("tenantseal: nested event payload exceeds rewrite depth")
	}
	switch beforeTyped := before.(type) {
	case map[string]any:
		afterTyped, ok := after.(map[string]any)
		if !ok || len(beforeTyped) != len(afterTyped) {
			return false, errors.New("tenantseal: history rewrite changed JSON object shape")
		}
		changed := false
		for key, beforeChild := range beforeTyped {
			afterChild, exists := afterTyped[key]
			if !exists {
				return false, errors.New("tenantseal: history rewrite changed JSON object keys")
			}
			childChanged, err := r.validateValuePair(beforeChild, afterChild, depth+1)
			if err != nil {
				return false, err
			}
			changed = changed || childChanged
		}
		return changed, nil
	case []any:
		afterTyped, ok := after.([]any)
		if !ok || len(beforeTyped) != len(afterTyped) {
			return false, errors.New("tenantseal: history rewrite changed JSON array shape")
		}
		changed := false
		for index := range beforeTyped {
			childChanged, err := r.validateValuePair(beforeTyped[index], afterTyped[index], depth+1)
			if err != nil {
				return false, err
			}
			changed = changed || childChanged
		}
		return changed, nil
	case string:
		afterTyped, ok := after.(string)
		if !ok {
			return false, errors.New("tenantseal: history rewrite changed JSON scalar type")
		}
		beforeDecoded, beforeErr := base64.StdEncoding.DecodeString(beforeTyped)
		afterDecoded, afterErr := base64.StdEncoding.DecodeString(afterTyped)
		if beforeErr == nil && bytes.HasPrefix(beforeDecoded, []byte("CSL1")) {
			if afterErr != nil {
				return false, errors.New("tenantseal: history rewrite corrupted base64 container")
			}
			return true, r.validateContainerPair(beforeDecoded, afterDecoded)
		}
		if beforeErr == nil && afterErr == nil && json.Valid(beforeDecoded) && json.Valid(afterDecoded) {
			beforeNested, err := decodeHistoryJSON(beforeDecoded)
			if err != nil {
				return false, err
			}
			afterNested, err := decodeHistoryJSON(afterDecoded)
			if err != nil {
				return false, err
			}
			return r.validateValuePair(beforeNested, afterNested, depth+1)
		}
		if beforeTyped != afterTyped {
			return false, errors.New("tenantseal: history rewrite changed a non-container string")
		}
		return false, nil
	default:
		if !scalarValuesEqual(before, after) {
			return false, errors.New("tenantseal: history rewrite changed a non-container scalar")
		}
		return false, nil
	}
}

func (r *HistoryRewrapper) validateContainerPair(before, after []byte) error {
	beforeDomain, err := seal.Domain(before)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCorruptContainer, err)
	}
	if beforeDomain != nil {
		return errors.New("tenantseal: rewrite pair source is not a legacy deployment container")
	}
	afterDomain, err := seal.Domain(after)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCorruptContainer, err)
	}
	if !bytes.Equal(afterDomain, r.domain) {
		return ErrUnexpectedDomain
	}
	if err := seal.ValidateDomain(r.tenant, after, r.domain); err != nil {
		return err
	}
	beforePayload, err := seal.PayloadCiphertext(before)
	if err != nil {
		return err
	}
	afterPayload, err := seal.PayloadCiphertext(after)
	if err != nil {
		return err
	}
	if !bytes.Equal(beforePayload, afterPayload) {
		return errors.New("tenantseal: history rewrap changed payload ciphertext")
	}
	return nil
}

func scalarValuesEqual(before, after any) bool {
	switch beforeTyped := before.(type) {
	case nil:
		return after == nil
	case bool:
		afterTyped, ok := after.(bool)
		return ok && beforeTyped == afterTyped
	case json.Number:
		afterTyped, ok := after.(json.Number)
		return ok && beforeTyped.String() == afterTyped.String()
	default:
		return false
	}
}

func (r *HistoryRewrapper) rewriteValue(value *any, depth int) (bool, error) {
	if depth > maxNestedHistoryDepth {
		return false, errors.New("tenantseal: nested event payload exceeds rewrite depth")
	}
	switch typed := (*value).(type) {
	case map[string]any:
		if isPopulatedLegacyEnvelope(typed) {
			return false, ErrLegacyEnvelope
		}
		changed := false
		for key, child := range typed {
			childChanged, err := r.rewriteValue(&child, depth+1)
			if err != nil {
				return false, err
			}
			if childChanged {
				typed[key] = child
				changed = true
			}
		}
		return changed, nil
	case []any:
		changed := false
		for index, child := range typed {
			childChanged, err := r.rewriteValue(&child, depth+1)
			if err != nil {
				return false, err
			}
			if childChanged {
				typed[index] = child
				changed = true
			}
		}
		return changed, nil
	case string:
		decoded, err := base64.StdEncoding.DecodeString(typed)
		if err != nil {
			return false, nil
		}
		if bytes.HasPrefix(decoded, []byte("CSL1")) {
			next, changed, err := r.rewriteContainer(decoded)
			if err != nil {
				return false, err
			}
			if changed {
				*value = base64.StdEncoding.EncodeToString(next)
			}
			return changed, nil
		}
		if !json.Valid(decoded) {
			return false, nil
		}
		nested, err := decodeHistoryJSON(decoded)
		if err != nil {
			return false, err
		}
		changed, err := r.rewriteValue(&nested, depth+1)
		if err != nil || !changed {
			return changed, err
		}
		next, err := json.Marshal(nested)
		if err != nil {
			return false, fmt.Errorf("tenantseal: encode nested event payload: %w", err)
		}
		*value = base64.StdEncoding.EncodeToString(next)
		return true, nil
	default:
		return false, nil
	}
}

func (r *HistoryRewrapper) rewriteContainer(container []byte) ([]byte, bool, error) {
	domain, err := seal.Domain(container)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrCorruptContainer, err)
	}
	if domain == nil {
		next, err := seal.RewrapDomain(r.deployment, r.tenant, container, r.domain)
		if err != nil {
			return nil, false, err
		}
		return next, true, nil
	}
	if !bytes.Equal(domain, r.domain) {
		return nil, false, ErrUnexpectedDomain
	}
	if err := seal.ValidateDomain(r.tenant, container, r.domain); err != nil {
		return nil, false, err
	}
	return container, false, nil
}

func decodeHistoryJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("tenantseal: decode event data: %w", err)
	}
	return value, nil
}

func isPopulatedLegacyEnvelope(value map[string]any) bool {
	format, _ := value["format"].(string)
	if format == "trstctl.crypto.envelope" {
		return true
	}
	_, hasWrapped := value["wrapped_dek"]
	_, hasDEKNonce := value["dek_nonce"]
	_, hasNonce := value["nonce"]
	_, hasCiphertext := value["ciphertext"]
	if !hasWrapped || !hasDEKNonce || !hasNonce || !hasCiphertext {
		return false
	}
	return nonEmptyEncodedBytes(value["wrapped_dek"]) || nonEmptyEncodedBytes(value["ciphertext"])
}

func nonEmptyEncodedBytes(value any) bool {
	encoded, ok := value.(string)
	return ok && encoded != ""
}
