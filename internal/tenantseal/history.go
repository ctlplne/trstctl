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
